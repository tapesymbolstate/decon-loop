#!/bin/bash
# Decon Agent — Binary Decompilation via Ralph Loop
#
# Usage: ./loop_decon.sh <binary_path> [codex|claude] [max_iterations]
#
# Examples:
#   ./loop_decon.sh target-binaries/sample-binary              # Claude, unlimited
#   ./loop_decon.sh target-binaries/sample-binary codex 50     # Codex, max 50
#
# Multi-cycle workflow:
#   1. Plan   → auto-generate PRD from binary recon (or existing findings)
#   2. Build  → iterate through PRD tasks
#   3. Verify → attempt to compile output/src/
#   4. If compilation fails → archive PRD, re-plan with deeper tasks, goto 2
#   5. Repeat until source compiles or max_iterations reached
#
# Completion = source in output/src/ compiles successfully

set -euo pipefail
cd "$(dirname "$0")"

# ─── Argument parsing ────────────────────────────────────────────────────────

if [ -z "${1:-}" ]; then
    echo "Usage: ./loop_decon.sh <binary_path> [codex|claude] [max_iterations]"
    exit 1
fi

BINARY_PATH="$1"
shift

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: binary not found at $BINARY_PATH"
    exit 1
fi

TOOL="claude"
if [ "${1:-}" = "codex" ] || [ "${1:-}" = "claude" ]; then
    TOOL="$1"
    shift
fi

MAX_ITERATIONS=${1:-0}
ITERATION=0
CYCLE=0

PRD="output/prd.json"
PROGRESS="output/progress.txt"

# ─── Records setup ───────────────────────────────────────────────────────────

mkdir -p output/records
RECORD_FILE="output/records/$(date '+%Y-%m-%d-%H%M%S')-decon-$TOOL.log"

# ─── Prompt: initial plan (cycle 1) ─────────────────────────────────────────

gen_plan_prompt() {
    cat <<PLAN_EOF
You are an autonomous binary decompilation planner. Your ONLY goal is to plan how to LIFT Ghidra-decompiled functions into clean, compilable C/C++ source files.

## Target
Binary file: \`$BINARY_PATH\`

## Available Ghidra data (already generated)
- \`output/ghidra/function_boundaries.tsv\` — TSV with columns: name, entry_address, end_address, size, param_count, return_type, calling_convention, is_thunk, is_external
- \`output/ghidra/call_graph.tsv\` — TSV with columns: caller_name, caller_address, callee_name, callee_address, ref_type
- \`output/ghidra/all_decompiled.c\` — Full Ghidra C pseudocode for all functions
- \`output/ghidra/functions/<prefix>/<funcname>_<addr>.c\` — Individual function decompilations

## Steps

1. Quick recon (brief — spend most effort on Ghidra data):
   - \`file $BINARY_PATH\` / \`otool -h $BINARY_PATH\` / \`otool -L $BINARY_PATH\`
   - \`wc -l output/ghidra/function_boundaries.tsv\` (total function count)

2. Analyze Ghidra function data to plan module chunking:
   - Read \`output/ghidra/function_boundaries.tsv\` — count functions, identify named vs unnamed (FUN_*)
   - Sample 10-20 decompiled functions from \`output/ghidra/functions/\` to assess pseudocode quality
   - Read first 500 lines of \`output/ghidra/call_graph.tsv\` to understand connectivity
   - Group functions into logical modules by:
     (a) Address proximity (functions at adjacent addresses often belong to the same compilation unit)
     (b) Call graph clusters (functions that call each other heavily)
     (c) String references and import patterns

3. Create directories: \`mkdir -p output/{headers,symbols,strings,reports,src,records}\`

4. Generate \`output/prd.json\` with schema:
   \`\`\`json
   { "binaryTarget": "$BINARY_PATH", "binaryType": "DESC", "cycle": 1,
     "userStories": [{ "id": "US-001", "title": "...", "description": "...",
       "ghidraFunctions": ["FUN_XXXXX", "FUN_YYYYY"],
       "addressRange": "0x100XXXX-0x100YYYY",
       "targetSourceFile": "output/src/module_name.cpp",
       "acceptanceCriteria": ["..."], "priority": 1, "passes": false, "notes": "" }] }
   \`\`\`

   CRITICAL task planning rules:
   - Task 1 MUST be "Create shared type definitions header" — scan Ghidra pseudocode for common types (undefined8→uint64_t, undefined4→uint32_t, etc.) and struct patterns, produce \`output/src/types.h\`
   - Tasks 2+ are "Lift module X functions" — each task covers 20-200 related functions
   - Each task MUST specify:
     \`ghidraFunctions\`: list of Ghidra function names to lift
     \`addressRange\`: address range covered
     \`targetSourceFile\`: output .cpp/.h file path
   - Accept criteria MUST include: "output/src/<file>.cpp contains lifted function implementations" and "compiles with clang++ -c"
   - 10-25 tasks total, ordered by dependency (types first, then utilities, then subsystems)

   DO NOT create analysis tasks like "extract symbols", "triage strings", "map dependencies".
   Every task must produce actual C/C++ function implementations in output/src/.

5. Generate \`output/progress.txt\` with recon summary and empty \`## Iteration Log\`.

## Rules
- NEVER modify the target binary. All output inside \`output/\`.
- Every PRD task must produce or improve .cpp/.h files in \`output/src/\`
- The output source must contain REAL function bodies lifted from Ghidra pseudocode, not metadata structs

## Completion
When output/prd.json and output/progress.txt are created, output: <promise>PLAN_COMPLETE</promise>
PLAN_EOF
}

# ─── Prompt: re-plan (cycle 2+, after compilation failure) ───────────────────

gen_replan_prompt() {
    local cycle_num="$1"
    local build_errors="$2"
    cat <<REPLAN_EOF
You are an autonomous function-lifting planner running cycle $cycle_num. The previous cycle's tasks are done but verification FAILED.

## Target
Binary file: \`$BINARY_PATH\`

## Failure from last verification
\`\`\`
$build_errors
\`\`\`

## Diagnosing the failure

If the error starts with "QUALITY:":
→ The source files do NOT contain real lifted function implementations. They contain metadata/struct literals.
→ You MUST: run \`rm -f output/src/*.cpp output/src/*.hpp output/src/*.h\` to delete all metadata files
→ Then plan fresh function-lifting tasks that read Ghidra pseudocode and produce real code

If the error starts with "COMPILATION:":
→ The source has real function implementations but doesn't compile
→ Analyze the specific compiler errors to plan targeted fixes

## Current state
- \`output/progress.txt\` — all prior findings
- \`output/prd.json\` — previous PRD (all passes: true)
- \`output/src/\` — current source files (may need deletion if quality failure)
- \`output/ghidra/function_boundaries.tsv\` — all functions
- \`output/ghidra/call_graph.tsv\` — call graph
- \`output/ghidra/all_decompiled.c\` — full Ghidra C pseudocode
- \`output/ghidra/functions/\` — individual function decompilations

## Your job
1. Archive: \`cp output/prd.json output/records/prd_cycle_$((cycle_num - 1)).json\`
2. If QUALITY failure: delete metadata source files, start fresh with function lifting
3. If COMPILATION failure: analyze errors, plan fixes for missing types/headers/implementations
4. Generate NEW \`output/prd.json\` with \`"cycle": $cycle_num\`:
   - Every task MUST have \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`
   - Every task MUST produce real C/C++ function implementations from Ghidra pseudocode
   - Accept criteria MUST include "compiles with clang++ -c" and "contains N function implementations"
   - Order: shared types.h first → utility functions → subsystem modules
5. Append cycle transition note to \`output/progress.txt\`

## Rules
- NEVER modify the target binary. All output inside \`output/\`.
- Every task must produce LIFTED function implementations, not analysis artifacts.
- Tasks must reference specific Ghidra function names to lift.

## Completion
When new output/prd.json is ready, output: <promise>PLAN_COMPLETE</promise>
REPLAN_EOF
}

# ─── Prompt: build (same for all cycles) ────────────────────────────────────

gen_build_prompt() {
    cat <<BUILD_EOF
You are an autonomous function-lifting agent. Your job: read Ghidra decompiled C pseudocode and transform it into clean, compilable C/C++ source.

## Target
Binary file: \`$BINARY_PATH\`

## Context — read FIRST
1. \`output/prd.json\` — task list with \`ghidraFunctions\` and \`targetSourceFile\` per task
2. \`output/progress.txt\` — cumulative findings

## Workflow for each task

### Step 1: Identify your task
Read \`output/prd.json\`, find the highest-priority task where \`passes\` is \`false\`.
Note the \`ghidraFunctions\` list, \`addressRange\`, and \`targetSourceFile\`.

### Step 2: Read Ghidra pseudocode
For each function in \`ghidraFunctions\`:
- Find it in \`output/ghidra/functions/\` (organized by address prefix subdirectories)
- Or grep for it in \`output/ghidra/all_decompiled.c\`: \`grep -A 100 "=== FUNCNAME @" output/ghidra/all_decompiled.c\`
- Read the raw Ghidra C pseudocode

### Step 3: Clean up and lift each function
Transform the Ghidra pseudocode into proper C/C++:
- \`undefined8\` → \`uint64_t\`, \`undefined4\` → \`uint32_t\`, \`undefined2\` → \`uint16_t\`, \`undefined1\` → \`uint8_t\`
- \`undefined\` → \`uint8_t\` (or appropriate type from context)
- \`FUN_XXXXXXXXX\` → meaningful name based on what the function does (analyze string refs, call patterns, operations)
- \`param_1\`, \`param_2\` → meaningful parameter names based on usage
- \`uVar1\`, \`lVar2\` → meaningful local variable names
- \`*(long *)(param_1 + 0x38)\` → keep as pointer arithmetic (or use struct if layout is known)
- Preserve ALL control flow exactly: every if/while/for/switch/goto must match the original
- Do NOT invent functionality — only clean up what Ghidra produced
- Add \`#include <cstdint>\`, \`<cstring>\`, \`<cstdlib>\` as needed

### Step 4: Write source files
- Write the header: \`output/src/<module>.h\` with function declarations and type definitions
- Write the implementation: \`output/src/<module>.cpp\` with cleaned function bodies
- For functions that call not-yet-lifted functions, declare them as \`extern\` in the header
- \`#include "types.h"\` if it exists (shared type definitions from task 1)

### Step 5: Compile and verify
Run: \`clang++ -std=c++17 -target arm64-apple-macos -c output/src/<module>.cpp -o /dev/null 2>&1\`
- Do NOT use \`-fsyntax-only\` — use \`-c\` for real compilation
- Do NOT append \`|| true\` — you need to see errors
- If compilation fails, fix the errors before marking the task as done
- Only set \`passes: true\` if compilation succeeds

### Step 6: Update state
- Update \`output/prd.json\`: set \`passes: true\`, record function count and notes
- Append to \`output/progress.txt\`: what functions you lifted, key findings

## CRITICAL RULES
- You MUST read Ghidra decompiled functions as your PRIMARY input
- Every function you write MUST correspond to a real Ghidra-decompiled function
- Output MUST contain actual function implementations with real logic (if/while/for/switch)
- Struct literals containing strings that describe the binary are NOT acceptable
- Do NOT produce "analysis artifacts" or "metadata models" — produce LIFTED CODE
- ONE task per iteration
- NEVER modify the target binary

## Completion
If ALL tasks have \`passes: true\`, output exactly:
<promise>CYCLE_DONE</promise>

Otherwise, complete your one task and exit.
BUILD_EOF
}

# ─── Agent spawner ───────────────────────────────────────────────────────────

spawn_agent() {
    local prompt="$1"
    if [ "$TOOL" = "codex" ]; then
        echo "$prompt" | codex exec \
            --full-auto \
            -c 'model_reasoning_effort="high"' \
            2>&1 || true
    else
        claude -p \
            --model sonnet \
            --permission-mode bypassPermissions \
            --dangerously-skip-permissions \
            "$prompt" \
            2>&1 || true
    fi
}

# ─── Verify: try to compile output/src/ ──────────────────────────────────────

verify_build() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase:  VERIFY (compilation + quality)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # ── Gate A: source files exist ──
    local src_files
    src_files=$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.m' -o -name '*.swift' 2>/dev/null)
    if [ -z "$src_files" ]; then
        echo "FAIL: No source files in output/src/"
        BUILD_ERRORS="No source files found in output/src/. Must lift Ghidra functions into compilable source."
        return 1
    fi

    # ── Gate B: source quantity thresholds ──
    local file_count loc
    file_count=$(echo "$src_files" | wc -l | tr -d ' ')
    loc=$(echo "$src_files" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "Source: $file_count files, $loc LOC"

    if [ "$loc" -lt 500 ]; then
        echo "FAIL: Only $loc LOC (need ≥500). Source is too small for a real reconstruction."
        BUILD_ERRORS="QUALITY: Only $loc lines of code across $file_count files. Minimum 500 LOC required. Lift more Ghidra functions into output/src/."
        return 1
    fi

    # ── Gate C: source quality — must contain real function logic, not just data structs ──
    local logic_lines data_lines
    logic_lines=$(grep -cE '(if\s*\(|while\s*\(|for\s*\(|switch\s*\(|->|<<|>>|\+\+|--|&&|\|\|)' output/src/*.cpp output/src/*.c 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
    data_lines=$(grep -cE '^\s*"[^"]*"|\{\s*"|\{\s*[0-9]' output/src/*.cpp output/src/*.c 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')

    local total_content=$((logic_lines + data_lines))
    if [ "$total_content" -gt 0 ]; then
        local logic_ratio=$((logic_lines * 100 / total_content))
        echo "Logic density: ${logic_ratio}% ($logic_lines logic lines / $total_content content lines)"
        if [ "$logic_ratio" -lt 25 ]; then
            echo "FAIL: Source is ${logic_ratio}% logic (need ≥25%). Files contain mostly data literals, not lifted function implementations."
            BUILD_ERRORS="QUALITY: Source is only ${logic_ratio}% logic (${logic_lines} logic lines vs ${data_lines} data lines). Files appear to be metadata/struct literals, not real function implementations lifted from Ghidra decompilation. Delete metadata-only files and produce actual C/C++ function implementations from output/ghidra/functions/."
            return 1
        fi
    fi

    local func_defs
    func_defs=$(grep -cE '^[a-zA-Z_].*\(.*\)\s*\{' output/src/*.cpp output/src/*.c 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
    echo "Function definitions: $func_defs"
    if [ "$func_defs" -lt 10 ]; then
        echo "FAIL: Only $func_defs function definitions (need ≥10)."
        BUILD_ERRORS="QUALITY: Only $func_defs function definitions found. Need at least 10 real function implementations lifted from the binary."
        return 1
    fi

    # ── Gate D: actual compilation (not just syntax check) ──
    local errors="" compile_rc=0
    if find output/src -name 'CMakeLists.txt' | grep -q .; then
        errors=$(cd output/src && cmake -B /tmp/decon-build -DCMAKE_OSX_ARCHITECTURES=arm64 . 2>&1 && cmake --build /tmp/decon-build 2>&1)
        compile_rc=$?
    elif find output/src -name '*.cpp' -o -name '*.c' | grep -q .; then
        errors=""
        while IFS= read -r srcfile; do
            file_errors=$(clang++ -std=c++17 -target arm64-apple-macos -c "$srcfile" -o /dev/null 2>&1)
            file_rc=$?
            if [ "$file_rc" -ne 0 ]; then
                compile_rc=$file_rc
                errors="${errors}${file_errors}\n"
            fi
        done < <(find output/src -name '*.cpp' -o -name '*.c')
    elif find output/src -name '*.swift' | grep -q .; then
        errors=$(find output/src -name '*.swift' | xargs swiftc -typecheck -target arm64-apple-macos 2>&1)
        compile_rc=$?
    fi

    if [ "$compile_rc" -ne 0 ] || [ -n "$errors" ]; then
        echo "FAIL: Compilation errors."
        echo "$errors" | head -50
        BUILD_ERRORS="COMPILATION:\n$errors"
        return 1
    fi

    echo "ALL GATES PASSED: $file_count files, $loc LOC, ${logic_ratio:-0}% logic, $func_defs functions, compiles clean."
    BUILD_ERRORS=""
    return 0
}

# ─── Phase 0: Ghidra pre-analysis (run once) ────────────────────────────────

mkdir -p /tmp/ghidra-projects output/ghidra

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GHIDRA PRE-ANALYSIS                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Quick analysis (function boundaries + call graph)
if [ ! -f "output/ghidra/function_boundaries.tsv" ]; then
    echo "[1/2] Running quick analysis (function boundaries + call graph)..."
    ./ghidra_analyze.sh "$BINARY_PATH" quick 2>&1 | tee -a "$RECORD_FILE"

    if [ -f "output/ghidra/function_boundaries.tsv" ]; then
        FUNC_COUNT=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
        echo "Quick done: $FUNC_COUNT functions found."
    else
        echo "Warning: Quick analysis failed. Continuing without Ghidra data."
    fi
else
    FUNC_COUNT=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
    echo "[1/2] Quick analysis cached ($FUNC_COUNT functions). Skipping."
fi

# Step 2: Full decompilation (all functions → C pseudocode)
if [ ! -f "output/ghidra/all_decompiled.c" ]; then
    echo ""
    echo "[2/2] Running full decompilation (this takes 30-60 min for large binaries)..."
    ./ghidra_analyze.sh "$BINARY_PATH" full 2>&1 | tee -a "$RECORD_FILE"

    if [ -f "output/ghidra/all_decompiled.c" ]; then
        DECOMP_SIZE=$(du -sh output/ghidra/all_decompiled.c | cut -f1)
        DECOMP_FUNCS=$(grep -c '^// ===' output/ghidra/all_decompiled.c 2>/dev/null || echo "?")
        echo "Full decompilation done: $DECOMP_FUNCS functions, $DECOMP_SIZE."
    else
        echo "Warning: Full decompilation failed. Continuing with quick data only."
    fi
else
    DECOMP_SIZE=$(du -sh output/ghidra/all_decompiled.c | cut -f1)
    echo "[2/2] Full decompilation cached ($DECOMP_SIZE). Skipping."
fi

# ─── Pre-compute module chunks for planning ─────────────────────────────────

if [ -f "output/ghidra/function_boundaries.tsv" ] && [ ! -f "output/ghidra/module_chunks.tsv" ]; then
    echo "Pre-computing module chunks from function boundaries..."
    python3 -c "
import csv, sys
from collections import defaultdict

chunks = defaultdict(lambda: {'count': 0, 'min_addr': '', 'max_addr': '', 'named': 0, 'total_size': 0})
with open('output/ghidra/function_boundaries.tsv') as f:
    reader = csv.DictReader(f, delimiter='\t')
    for row in reader:
        addr = row['entry_address']
        prefix = addr[:6] if len(addr) > 6 else addr
        c = chunks[prefix]
        c['count'] += 1
        c['total_size'] += int(row['size'])
        if not row['name'].startswith('FUN_') and not row['name'].startswith('thunk_'):
            c['named'] += 1
        if not c['min_addr'] or addr < c['min_addr']:
            c['min_addr'] = addr
        if not c['max_addr'] or addr > c['max_addr']:
            c['max_addr'] = addr

with open('output/ghidra/module_chunks.tsv', 'w') as out:
    out.write('prefix\tfunction_count\tnamed_count\ttotal_bytes\tmin_address\tmax_address\n')
    for prefix in sorted(chunks.keys()):
        c = chunks[prefix]
        out.write(f\"{prefix}\t{c['count']}\t{c['named']}\t{c['total_size']}\t{c['min_addr']}\t{c['max_addr']}\n\")
" 2>/dev/null
    if [ -f "output/ghidra/module_chunks.tsv" ]; then
        CHUNK_COUNT=$(tail -n +2 output/ghidra/module_chunks.tsv | wc -l | tr -d ' ')
        echo "Module chunks: $CHUNK_COUNT address-prefix groups."
    fi
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP: Plan → Build → Verify → Re-plan if needed
# ═══════════════════════════════════════════════════════════════════════════════

while true; do
    CYCLE=$((CYCLE + 1))

    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  CYCLE $CYCLE                                                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    # ─── Plan phase ───────────────────────────────────────────────────────

    if [ ! -f "$PRD" ] || ! python3 -c "import json,sys; d=json.load(open('$PRD')); sys.exit(0 if any(not s['passes'] for s in d['userStories']) else 1)" 2>/dev/null; then

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Phase:  PLAN (cycle $CYCLE)"
        echo "Target: $BINARY_PATH"
        echo "Tool:   $TOOL"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        if [ "$CYCLE" -eq 1 ]; then
            PLAN_PROMPT=$(gen_plan_prompt)
        else
            PLAN_PROMPT=$(gen_replan_prompt "$CYCLE" "$BUILD_ERRORS")
        fi

        echo "======================== PLAN CYCLE $CYCLE ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"

        OUTPUT=$(spawn_agent "$PLAN_PROMPT")
        echo "$OUTPUT" | tee -a "$RECORD_FILE"

        # Recover misplaced files
        [ ! -f "$PRD" ] && [ -f "prd.json" ] && mv prd.json "$PRD"
        [ ! -f "$PROGRESS" ] && [ -f "progress.txt" ] && mv progress.txt "$PROGRESS"

        if [ ! -f "$PRD" ]; then
            echo "Error: Plan phase did not generate output/prd.json"
            exit 1
        fi

        echo "Plan phase complete (cycle $CYCLE)."
    fi

    # ─── Build phase ──────────────────────────────────────────────────────

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase:  BUILD (cycle $CYCLE)"
    echo "Target: $BINARY_PATH"
    echo "Tool:   $TOOL"
    [ "$MAX_ITERATIONS" -gt 0 ] && echo "Max:    $MAX_ITERATIONS total iterations"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    BUILD_PROMPT=$(gen_build_prompt)

    while true; do
        if [ "$MAX_ITERATIONS" -gt 0 ] && [ "$ITERATION" -ge "$MAX_ITERATIONS" ]; then
            echo "Reached max iterations: $MAX_ITERATIONS"
            echo ""
            echo "Record saved: $RECORD_FILE"
            exit 0
        fi

        ITERATION=$((ITERATION + 1))
        echo -e "\n======================== BUILD C${CYCLE}.${ITERATION} ($(date '+%Y-%m-%d %H:%M:%S')) ========================\n" | tee -a "$RECORD_FILE"

        OUTPUT=$(spawn_agent "$BUILD_PROMPT")
        echo "$OUTPUT" | tee -a "$RECORD_FILE"

        # Rate limit
        if echo "$OUTPUT" | grep -qi 'rate.limit\|429\|too many requests\|overloaded'; then
            echo "Rate limit. Waiting 60s..."
            sleep 60
            ITERATION=$((ITERATION - 1))
            continue
        fi

        # Check if all current PRD tasks are done
        if echo "$OUTPUT" | tail -30 | grep -q '<promise>CYCLE_DONE</promise>'; then
            echo "All PRD tasks complete for cycle $CYCLE."
            break
        fi

        echo "Iteration $ITERATION done."
    done

    # ─── Verify phase ────────────────────────────────────────────────────

    echo ""
    BUILD_ERRORS=""
    if verify_build; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  SUCCESS — Source compiles! Mission complete.               ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Record saved: $RECORD_FILE"
        exit 0
    fi

    echo ""
    echo "Source does not compile yet. Starting cycle $((CYCLE + 1))..."
    echo ""
done
