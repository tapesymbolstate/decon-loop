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
You are an autonomous binary analysis planner. Inspect the target binary and generate a structured task plan (PRD) for full decompilation and source reconstruction.

## Target
Binary file: \`$BINARY_PATH\`

## Steps

1. Run quick reconnaissance:
   - \`file $BINARY_PATH\`
   - \`otool -h $BINARY_PATH\` / \`otool -l $BINARY_PATH | head -200\` / \`otool -L $BINARY_PATH\`
   - \`nm $BINARY_PATH 2>&1 | head -50\` / \`nm $BINARY_PATH 2>&1 | wc -l\`
   - \`strings $BINARY_PATH | wc -l\` / \`strings $BINARY_PATH | head -200\`

2. Check if Ghidra pre-analysis exists:
   - \`output/ghidra/function_boundaries.tsv\` — all detected functions with addresses and sizes
   - \`output/ghidra/call_graph.tsv\` — caller→callee relationships
   If these exist, use them to inform task planning (you have real function boundaries, not just guesses).

3. Determine: binary type, architecture, languages, embedded frameworks, stripping level, complexity, function count from Ghidra.

4. Create: \`mkdir -p output/{headers,symbols,strings,classes,protocols,functions,diff,reports,obfuscation,src,records}\`

5. Generate \`output/prd.json\` with schema:
   \`\`\`json
   { "binaryTarget": "$BINARY_PATH", "binaryType": "DESC", "cycle": 1,
     "userStories": [{ "id": "US-001", "title": "...", "description": "...",
       "acceptanceCriteria": ["..."], "priority": 1, "passes": false, "notes": "" }] }
   \`\`\`
   Rules: start structural → symbols → deps → strings → components → disassembly → source reconstruction. 5-15 tasks. Each completable in one iteration.

6. Generate \`output/progress.txt\` with recon under \`## Codebase Patterns\` and empty \`## Iteration Log\`.

7. Save recon to \`output/reports/recon_summary.md\`.

## Rules
- NEVER modify the target binary. All output goes inside \`output/\`.

## Completion
When done, output: <promise>PLAN_COMPLETE</promise>
PLAN_EOF
}

# ─── Prompt: re-plan (cycle 2+, after compilation failure) ───────────────────

gen_replan_prompt() {
    local cycle_num="$1"
    local build_errors="$2"
    cat <<REPLAN_EOF
You are an autonomous binary decompilation planner running cycle $cycle_num. The previous cycle's PRD tasks are ALL complete, but the reconstructed source does NOT compile yet.

## Target
Binary file: \`$BINARY_PATH\`

## Current state
- Read \`output/progress.txt\` for all findings so far
- Read \`output/prd.json\` to see what was already done (all passes: true)
- Existing source skeletons are in \`output/src/\`
- Previous reports are in \`output/reports/\`
- Ghidra data (if available): \`output/ghidra/function_boundaries.tsv\`, \`output/ghidra/call_graph.tsv\`, \`output/ghidra/all_decompiled.c\`
- To get individual function decompilation, check \`output/ghidra/functions/\` or run \`./ghidra_analyze.sh $BINARY_PATH full\`

## Build errors from last verification
\`\`\`
$build_errors
\`\`\`

## Your job
1. Archive the current PRD: \`cp output/prd.json output/records/prd_cycle_$((cycle_num - 1)).json\`
2. Analyze the build errors and existing source to determine what's missing
3. Generate a NEW \`output/prd.json\` with:
   - \`"cycle": $cycle_num\`
   - Fresh tasks targeting: missing function implementations, unresolved symbols, incomplete type definitions, missing headers, incorrect control flow, etc.
   - Each task should produce or fix actual compilable source files in \`output/src/\`
   - Acceptance criteria MUST include "modified source compiles without the specific error this task addresses"
   - Priority order: fix foundational types/headers first, then implementations, then linking
4. Append cycle transition note to \`output/progress.txt\`

## Rules
- NEVER modify the target binary. All output inside \`output/\`.
- Focus tasks on producing COMPILABLE source, not just analysis artifacts.
- Every task must result in source file changes under \`output/src/\`.

## Completion
When new output/prd.json is ready, output: <promise>PLAN_COMPLETE</promise>
REPLAN_EOF
}

# ─── Prompt: build (same for all cycles) ────────────────────────────────────

gen_build_prompt() {
    cat <<BUILD_EOF
You are an autonomous binary decompilation agent in a Ralph Loop. Your goal: produce compilable source code from the target binary.

## Target
Binary file: \`$BINARY_PATH\`

## Context — read FIRST
1. \`output/prd.json\` — task list with completion status
2. \`output/progress.txt\` — cumulative findings from all cycles

## Your task
1. Read \`output/prd.json\`, find highest-priority task where \`passes\` is \`false\`
2. Read \`output/progress.txt\` for prior findings
3. Execute ONLY that one task. Tools available:
   - \`otool\`, \`nm\`, \`strings\`, \`xxd\`, \`hexdump\`, \`objdump\`, \`c++filt\`, \`swift demangle\`
   - \`clang\`, \`clang++\`, \`swiftc\` (for compilation verification)
   - Ghidra pre-analysis data (if available):
     - \`output/ghidra/function_boundaries.tsv\` — all functions with name, address, size, params, return type
     - \`output/ghidra/call_graph.tsv\` — caller→callee call graph
     - \`output/ghidra/all_decompiled.c\` — full decompiled C pseudocode (if full mode was run)
     - \`output/ghidra/functions/\` — individual function decompilations
   - To run full Ghidra decompilation: \`./ghidra_analyze.sh $BINARY_PATH full\`
4. Save analysis to \`output/{headers,symbols,strings,reports,functions}/\`
5. Save/update reconstructed source in \`output/src/\`
6. After writing source, attempt compilation:
   \`\`\`
   cd output/src && clang++ -std=c++17 -target arm64-apple-macos -fsyntax-only *.cpp *.hpp 2>&1 || true
   \`\`\`
   Record result in progress.txt.
7. Update \`output/prd.json\`: set \`passes: true\` and write notes
8. Append iteration summary to \`output/progress.txt\`

## Rules
- Binary at \`$BINARY_PATH\` — NEVER modify it
- All output inside \`output/\`
- ONE task per iteration
- Large outputs (>1000 lines) go to files
- Source files MUST be written to \`output/src/\` and MUST attempt compilation

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
    echo "Phase:  VERIFY (attempting compilation)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ ! -d "output/src" ] || [ -z "$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.m' -o -name '*.swift' -o -name '*.zig' 2>/dev/null)" ]; then
        echo "No source files found in output/src/"
        BUILD_ERRORS="No source files found in output/src/. Need to generate actual compilable source."
        return 1
    fi

    # Try compilation based on what's there
    local errors=""
    if find output/src -name 'CMakeLists.txt' | grep -q .; then
        errors=$(cd output/src && cmake -B /tmp/decon-build -DCMAKE_OSX_ARCHITECTURES=arm64 . 2>&1 && cmake --build /tmp/decon-build 2>&1) || true
    elif find output/src -name '*.cpp' -o -name '*.c' | grep -q .; then
        errors=$(find output/src -name '*.cpp' -o -name '*.c' | head -20 | xargs clang++ -std=c++17 -target arm64-apple-macos -fsyntax-only 2>&1) || true
    elif find output/src -name '*.swift' | grep -q .; then
        errors=$(find output/src -name '*.swift' | head -20 | xargs swiftc -typecheck -target arm64-apple-macos 2>&1) || true
    fi

    if [ $? -eq 0 ] && [ -z "$errors" ]; then
        echo "Compilation succeeded!"
        BUILD_ERRORS=""
        return 0
    else
        echo "Compilation failed."
        echo "$errors" | head -50
        BUILD_ERRORS="$errors"
        return 1
    fi
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
