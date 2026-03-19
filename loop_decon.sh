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
    local mapping_section=""
    if [ "$HAS_FUNCTION_MAP" = true ]; then
        mapping_section="
## Reference source mapping (AVAILABLE — use hybrid strategy)
- \`output/mapping/function_map.tsv\` — maps Ghidra functions to original source files with columns:
  ghidra_function_name, ghidra_address, source_file, source_line, confidence, match_method, original_name, source_language
- \`output/mapping/helper_aliases.tsv\` — maps FUN_* names to meaningful original names
- \`output/mapping/stats.json\` — mapping coverage summary
- \`reference-src/\` — cloned original source code

HYBRID STRATEGY: For functions that have mappings (check function_map.tsv), the agent will
read BOTH the Ghidra pseudocode AND the original source, then produce output that matches
the original code quality. Prioritize mapped functions — they produce the best results.

When planning tasks:
- Read output/mapping/stats.json to understand coverage
- Group tasks by SOURCE FILE (not just address), using the source_file column from function_map.tsv
- For tasks with mapped functions: set \`sourceFiles\` field listing the original source files
- Order: high-confidence mapped functions first, then medium, then unmapped
- Output language should match the original: .zig for Zig source, .cpp for C++ source
"
    else
        mapping_section="
## No reference source mapping available — use pure reversing strategy
The binary's original source was not identified or is not open source.
All lifting must be done from Ghidra pseudocode alone.
"
    fi

    cat <<PLAN_EOF
You are an autonomous source reconstruction planner. Your goal is to plan how to reconstruct real, readable source code from a decompiled binary.

## Target
Binary file: \`$BINARY_PATH\`

## Available Ghidra data
- \`output/ghidra/function_boundaries.tsv\` — all detected functions (name, address, size, params, return_type)
- \`output/ghidra/call_graph.tsv\` — caller→callee relationships
- \`output/ghidra/all_decompiled.c\` — Full Ghidra C pseudocode
- \`output/ghidra/functions/<prefix>/<funcname>_<addr>.c\` — Individual function decompilations
- \`output/ghidra/module_chunks.tsv\` — address-prefix groupings with function counts
$mapping_section
## Steps

1. Quick recon:
   - \`file $BINARY_PATH\` / \`otool -h $BINARY_PATH\` / \`otool -L $BINARY_PATH\`
   - \`wc -l output/ghidra/function_boundaries.tsv\` (function count)
   - If mapping exists: \`cat output/mapping/stats.json\` (coverage)
   - If mapping exists: \`head -30 output/mapping/function_map.tsv\` (sample mappings)

2. Plan module grouping:
   - If mapping exists: group by source_file from function_map.tsv
   - If no mapping: group by address proximity + call graph clusters
   - Sample decompiled functions to assess pseudocode quality

3. Create: \`mkdir -p output/{headers,symbols,strings,reports,src,records}\`

4. Generate \`output/prd.json\` with schema:
   \`\`\`json
   { "binaryTarget": "$BINARY_PATH", "binaryType": "DESC", "cycle": 1,
     "userStories": [{ "id": "US-001", "title": "...", "description": "...",
       "ghidraFunctions": ["FUN_XXXXX", "FUN_YYYYY"],
       "addressRange": "0x100XXXX-0x100YYYY",
       "sourceFiles": ["src/path/to/original.zig"],
       "targetSourceFile": "output/src/module_name.zig",
       "acceptanceCriteria": ["..."], "priority": 1, "passes": false, "notes": "" }] }
   \`\`\`

   Task planning rules:
   - Task 1: "Create shared type definitions" from Ghidra type patterns
   - Tasks 2+: "Reconstruct <module>" — each covers 20-200 related functions
   - Each task MUST specify \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`
   - If mapping exists: include \`sourceFiles\` listing the original source paths
   - Output file extension MUST match source language (.zig, .cpp, .c, .rs etc.)
   - 10-25 tasks, ordered by dependency
   - DO NOT create analysis-only tasks

5. Generate \`output/progress.txt\` with recon summary.

## Rules
- NEVER modify the target binary. All output inside \`output/\`.
- Every task must produce real source code in \`output/src/\`

## Completion
When done, output: <promise>PLAN_COMPLETE</promise>
PLAN_EOF
}

# ─── Prompt: re-plan (cycle 2+, after compilation failure) ───────────────────

gen_replan_prompt() {
    local cycle_num="$1"
    local build_errors="$2"

    local mapping_note=""
    if [ "$HAS_FUNCTION_MAP" = true ]; then
        mapping_note="
- \`output/mapping/function_map.tsv\` — function→source mappings
- \`output/mapping/helper_aliases.tsv\` — FUN_*→original name aliases
- \`reference-src/\` — original source (use for hybrid lifting)
"
    fi

    cat <<REPLAN_EOF
You are a source reconstruction planner running cycle $cycle_num. Verification FAILED.

## Target
Binary file: \`$BINARY_PATH\`

## Failure
\`\`\`
$build_errors
\`\`\`

## Diagnosis
- "QUALITY:" → source is metadata/stubs, not real code. Delete and re-lift from Ghidra.
- "COMPILATION:" → real code but compile errors. Fix specific issues.

## Available data
- \`output/progress.txt\`, \`output/prd.json\`, \`output/src/\`
- \`output/ghidra/function_boundaries.tsv\`, \`call_graph.tsv\`, \`functions/\`
$mapping_note
## Job
1. Archive: \`cp output/prd.json output/records/prd_cycle_$((cycle_num - 1)).json\`
2. If QUALITY failure: \`rm -f output/src/*\`, start fresh
3. Generate NEW \`output/prd.json\` (\`"cycle": $cycle_num\`):
   - Every task: \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`
   - If mapping available: include \`sourceFiles\`, match output language to original
   - Output must be real source code, not analysis artifacts
4. Append cycle note to \`output/progress.txt\`

## Completion
When ready, output: <promise>PLAN_COMPLETE</promise>
REPLAN_EOF
}

# ─── Prompt: build (same for all cycles) ────────────────────────────────────

gen_build_prompt() {
    local mapping_section=""
    if [ "$HAS_FUNCTION_MAP" = true ]; then
        mapping_section="
## Reference source mapping (AVAILABLE)
- \`output/mapping/function_map.tsv\` — maps Ghidra function → original source file:line
- \`output/mapping/helper_aliases.tsv\` — maps FUN_* → meaningful names
- \`reference-src/\` — original source code

### HYBRID WORKFLOW (for functions with mappings):
1. Look up the function in \`output/mapping/function_map.tsv\`
2. Read the ORIGINAL source at the mapped file:line in \`reference-src/\`
3. Read the Ghidra pseudocode to verify correspondence (check control flow matches)
4. Write output that matches the ORIGINAL source — same language, names, types, idioms
5. Add a comment with the Ghidra address for traceability: \`// @ghidra: 0x100XXXXXX\`

### LANGUAGE RULES:
- If original is .zig → write .zig output (use Zig syntax, types, error handling)
- If original is .cpp/.c → write .cpp/.c output
- If original is .rs → write .rs output
- Unmapped functions → write .c output (cleaned Ghidra pseudocode)

### NAME RESTORATION:
- Use \`helper_aliases.tsv\` to rename FUN_* calls to their original names
- Use the mapping to restore parameter names, types, and variable names from the original
"
    else
        mapping_section="
## No reference source — pure reversing mode
All lifting must be from Ghidra pseudocode alone.
Clean up types (undefined8→uint64_t), infer meaningful names from context.
"
    fi

    cat <<BUILD_EOF
You are an autonomous source reconstruction agent. Your job: produce clean, readable source code that faithfully represents the binary's logic.

## Target
Binary file: \`$BINARY_PATH\`

## Context — read FIRST
1. \`output/prd.json\` — task list with \`ghidraFunctions\`, \`targetSourceFile\`, and optionally \`sourceFiles\`
2. \`output/progress.txt\` — cumulative findings
$mapping_section
## Workflow

### Step 1: Identify your task
Read \`output/prd.json\`, find the highest-priority task where \`passes\` is \`false\`.

### Step 2: For each function in the task

**If mapping exists for this function** (check function_map.tsv):
a) Read the original source from \`reference-src/<source_file>\` at the mapped line
b) Read the Ghidra pseudocode from \`output/ghidra/functions/\`
c) Verify they correspond (similar control flow, string references)
d) Write the ORIGINAL source code, adapting minimally:
   - Keep original function name, parameter names, types
   - Keep original language (Zig/C++/Rust/etc.)
   - Add \`// @ghidra: <address>\` comment for traceability
   - Replace any remaining FUN_* calls with mapped names from helper_aliases.tsv

**If NO mapping exists** (pure Ghidra lifting):
a) Read the Ghidra pseudocode
b) Clean up: \`undefined8\`→\`uint64_t\`, \`FUN_*\`→meaningful name, \`param_N\`→descriptive name
c) Infer function purpose from string refs, call patterns, operations
d) Preserve ALL control flow exactly
e) Write as clean C

### Step 3: Write source files
- Use the language matching the original source (or .c for unmapped)
- For functions calling not-yet-lifted functions, declare them as \`extern\`
- Include \`types.h\` if needed for Ghidra type aliases

### Step 4: Compile and verify
- C/C++: \`clang++ -std=c++17 -target arm64-apple-macos -c <file> -o /dev/null 2>&1\`
- Zig: \`zig ast-check <file> 2>&1\` (syntax check only if full build not possible)
- Do NOT use \`|| true\` — you need to detect failures
- Only set \`passes: true\` if verification succeeds

### Step 5: Update state
- Update \`output/prd.json\`: set \`passes: true\`, note function count and accuracy
- Append to \`output/progress.txt\`

## CRITICAL RULES
- Output must be REAL SOURCE CODE — readable, with meaningful names and proper types
- If reference source exists, your output should MATCH it as closely as possible
- Struct literals / metadata describing the binary are NOT acceptable
- ONE task per iteration
- NEVER modify the target binary

## Completion
If ALL tasks have \`passes: true\`, output: <promise>CYCLE_DONE</promise>
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

# ─── Phase 0.5: Source discovery + mapping ───────────────────────────────────

HAS_REFERENCE_SOURCE=false
HAS_FUNCTION_MAP=false

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SOURCE DISCOVERY & MAPPING                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Discover what the binary is
if [ ! -f "output/discovery/identity.json" ]; then
    echo "[1/3] Identifying binary..."
    python3 discover_source.py "$BINARY_PATH" --clone 2>&1 | tee -a "$RECORD_FILE"
else
    echo "[1/3] Identity cached."
    cat output/discovery/identity.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  {d.get(\"name\",\"?\")}{\" \"+d[\"version\"] if d.get(\"version\") else \"\"} (confidence: {d.get(\"confidence\",\"?\")})')" 2>/dev/null
fi

# Step 2: Check if reference source exists
if [ -f "output/discovery/identity.json" ]; then
    SOURCE_NAME=$(python3 -c "import json; d=json.load(open('output/discovery/identity.json')); print(d.get('name',''))" 2>/dev/null)
    SOURCE_DIR="reference-src/${SOURCE_NAME}"

    if [ -n "$SOURCE_NAME" ] && [ -d "$SOURCE_DIR" ]; then
        HAS_REFERENCE_SOURCE=true
        echo "[2/3] Reference source: $SOURCE_DIR"
    elif [ -n "$SOURCE_NAME" ]; then
        echo "[2/3] Cloning reference source..."
        python3 discover_source.py "$BINARY_PATH" --clone 2>&1 | tee -a "$RECORD_FILE"
        [ -d "$SOURCE_DIR" ] && HAS_REFERENCE_SOURCE=true
    else
        echo "[2/3] No source identified. Using pure reversing (Approach A only)."
    fi
else
    echo "[2/3] No identity. Using pure reversing (Approach A only)."
fi

# Step 3: Build function-to-source mapping
if [ "$HAS_REFERENCE_SOURCE" = true ] && [ ! -f "output/mapping/function_map.tsv" ]; then
    echo "[3/3] Building function→source mapping..."
    python3 map_to_source.py "$BINARY_PATH" 2>&1 | tee -a "$RECORD_FILE"
    [ -f "output/mapping/function_map.tsv" ] && HAS_FUNCTION_MAP=true
elif [ -f "output/mapping/function_map.tsv" ]; then
    HAS_FUNCTION_MAP=true
    MAP_COUNT=$(tail -n +2 output/mapping/function_map.tsv | wc -l | tr -d ' ')
    echo "[3/3] Function mapping cached ($MAP_COUNT entries)."
else
    echo "[3/3] No mapping available. Proceeding with Ghidra data only."
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
