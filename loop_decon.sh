#!/bin/bash
# Decon Agent — Binary Decompilation via Ralph Loop
#
# Usage: ./loop_decon.sh <binary_path> [codex|claude] [max_iterations]
#
# Examples:
#   ./loop_decon.sh target-binaries/sample-binary              # Claude, unlimited
#   ./loop_decon.sh target-binaries/sample-binary 5            # Claude, max 5
#   ./loop_decon.sh target-binaries/sample-binary codex        # Codex, unlimited
#   ./loop_decon.sh target-binaries/sample-binary codex 10     # Codex, max 10
#
# Two-phase workflow:
#   Phase 1 (Plan):  If output/prd.json doesn't exist, auto-generates it
#   Phase 2 (Build): Iterates through prd.json tasks until all pass
#
# All artifacts go into output/ (gitignored)

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

PRD="output/prd.json"
PROGRESS="output/progress.txt"

# ─── Records setup ───────────────────────────────────────────────────────────

RECORDS_DIR="output/records"
mkdir -p "$RECORDS_DIR"
RECORD_FILE="$RECORDS_DIR/$(date '+%Y-%m-%d-%H%M%S')-decon-$TOOL.log"

# ─── Embedded prompt templates ───────────────────────────────────────────────

gen_plan_prompt() {
    cat <<PLAN_EOF
You are an autonomous binary analysis planner. Your job is to inspect a target binary and generate a structured task plan (PRD) for full decompilation.

## Target
Binary file: \`$BINARY_PATH\`

## Steps

1. Run quick reconnaissance on the binary:
   - \`file $BINARY_PATH\`
   - \`otool -h $BINARY_PATH\` (Mach-O header)
   - \`otool -l $BINARY_PATH | head -200\` (load commands sample)
   - \`otool -L $BINARY_PATH\` (linked libraries)
   - \`nm $BINARY_PATH 2>&1 | head -50\` (symbol sample)
   - \`nm $BINARY_PATH 2>&1 | wc -l\` (symbol count)
   - \`strings $BINARY_PATH | wc -l\` (string count)
   - \`strings $BINARY_PATH | head -200\` (string sample)

2. From the recon, determine:
   - Binary type (executable, dylib, framework, etc.)
   - Architecture (arm64, x86_64, universal)
   - Language(s) used (C, C++, Objective-C, Swift, Rust, Zig, etc.)
   - Major frameworks/libraries embedded
   - Whether symbols are stripped
   - Estimated complexity

3. Create output directory structure:
   \`\`\`
   mkdir -p output/{headers,symbols,strings,classes,protocols,functions,diff,reports,obfuscation,src,records}
   \`\`\`

4. Generate \`output/prd.json\` (inside output/ directory) with this exact schema:
   \`\`\`json
   {
     "binaryTarget": "$BINARY_PATH",
     "binaryType": "DESCRIPTION",
     "userStories": [
       {
         "id": "US-001",
         "title": "Task title",
         "description": "What to do",
         "acceptanceCriteria": ["criterion1", "criterion2"],
         "priority": 1,
         "passes": false,
         "notes": ""
       }
     ]
   }
   \`\`\`

   Task planning rules:
   - Start with structural analysis (headers, segments, sections)
   - Then symbol extraction and categorization
   - Then dependency/library mapping
   - Then string extraction and classification
   - Then component/subsystem identification
   - Then targeted disassembly of key functions
   - Then source reconstruction per component
   - Each task must be completable in one agent iteration
   - Priority 1 = do first, higher numbers = later
   - Typically 5-15 tasks for the initial plan

5. Generate \`output/progress.txt\` (inside output/ directory) with initial recon findings under \`## Codebase Patterns\` and an empty \`## Iteration Log\`.

6. Save recon summary to \`output/reports/recon_summary.md\`.

## Rules
- NEVER modify the target binary
- All generated files go inside \`output/\` directory
- The prd.json must be valid JSON
- Tasks should progress from broad analysis -> targeted extraction -> source reconstruction

## Completion
When output/prd.json and output/progress.txt are created, output exactly:
<promise>PLAN_COMPLETE</promise>
PLAN_EOF
}

gen_build_prompt() {
    cat <<BUILD_EOF
You are an autonomous binary decompilation agent operating in a Ralph Loop. Your goal is to fully deconstruct the target binary into readable, buildable source.

## Target
Binary file: \`$BINARY_PATH\`

## Context files — read these FIRST
1. \`output/prd.json\` — task list with completion status
2. \`output/progress.txt\` — cumulative findings from previous iterations

## Your task
1. Read \`output/prd.json\` and find the highest-priority task where \`passes\` is \`false\`
2. Read \`output/progress.txt\` to understand what has already been discovered
3. Execute ONLY that one task using CLI tools available on macOS:
   - \`otool -h\`, \`otool -l\`, \`otool -L\` (Mach-O inspection)
   - \`nm\` (symbol listing)
   - \`strings\` (string extraction)
   - \`xxd\`, \`hexdump\` (hex dumps)
   - \`objdump --disassemble-symbols=\` (targeted disassembly)
   - \`c++filt\` (C++ demangling)
   - \`swift demangle\` (Swift demangling)
4. Save analysis output to the appropriate directory under \`output/\`:
   - \`output/headers/\` — Mach-O headers, load commands
   - \`output/symbols/\` — symbol tables, exports/imports
   - \`output/strings/\` — extracted strings (categorized)
   - \`output/reports/\` — summary reports and component maps
   - \`output/functions/\` — disassembled functions
   - \`output/src/\` — reconstructed source code
5. Update \`output/prd.json\`: set \`passes: true\` and write relevant notes for the completed task
6. Append a concise iteration summary to \`output/progress.txt\` with:
   - What you did
   - Key findings
   - Patterns discovered
   - Caveats or issues encountered

## Rules
- The binary is at \`$BINARY_PATH\` — NEVER modify it
- All output goes inside \`output/\` directory
- Work on exactly ONE task per iteration
- Large outputs (>1000 lines) must go to files, not stdout
- Keep progress.txt concise — summaries only, full data goes to other output/ subdirs
- If a command produces too much output, pipe to a file first then analyze

## Completion
If ALL tasks in output/prd.json have \`passes: true\`, output exactly:
<promise>COMPLETE</promise>

Otherwise, just complete your one task and exit.
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

# ─── Phase 1: Plan ───────────────────────────────────────────────────────────

if [ ! -f "$PRD" ]; then
    mkdir -p output

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase:  PLAN (generating prd.json)"
    echo "Target: $BINARY_PATH"
    echo "Tool:   $TOOL"
    echo "Record: $RECORD_FILE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    PLAN_PROMPT=$(gen_plan_prompt)

    echo "======================== PLAN PHASE ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"

    OUTPUT=$(spawn_agent "$PLAN_PROMPT")
    echo "$OUTPUT" | tee -a "$RECORD_FILE"

    # Recover if agent placed files in project root instead of output/
    if [ ! -f "$PRD" ] && [ -f "prd.json" ]; then
        mv prd.json "$PRD"
    fi
    if [ ! -f "$PROGRESS" ] && [ -f "progress.txt" ]; then
        mv progress.txt "$PROGRESS"
    fi

    if [ ! -f "$PRD" ]; then
        echo ""
        echo "Error: Plan phase did not generate output/prd.json. Check output above."
        exit 1
    fi

    echo ""
    echo "Plan phase complete. output/prd.json generated."
    echo ""
fi

# ─── Phase 2: Build ──────────────────────────────────────────────────────────

CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "detached")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase:  BUILD"
echo "Target: $BINARY_PATH"
echo "Tool:   $TOOL"
echo "Branch: $CURRENT_BRANCH"
[ "$MAX_ITERATIONS" -gt 0 ] && echo "Max:    $MAX_ITERATIONS iterations"
echo "Record: $RECORD_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

BUILD_PROMPT=$(gen_build_prompt)

while true; do
    if [ "$MAX_ITERATIONS" -gt 0 ] && [ "$ITERATION" -ge "$MAX_ITERATIONS" ]; then
        echo "Reached max iterations: $MAX_ITERATIONS"
        break
    fi

    ITERATION=$((ITERATION + 1))
    LOOP_HEADER="======================== BUILD $ITERATION ($(date '+%Y-%m-%d %H:%M:%S')) ========================"
    echo -e "\n$LOOP_HEADER\n" | tee -a "$RECORD_FILE"

    OUTPUT=$(spawn_agent "$BUILD_PROMPT")
    echo "$OUTPUT" | tee -a "$RECORD_FILE"

    # Rate limit handling
    if echo "$OUTPUT" | grep -qi 'rate.limit\|429\|too many requests\|overloaded'; then
        echo ""
        echo "Rate limit detected. Waiting 60 seconds..."
        sleep 60
        echo "Resuming..."
        ITERATION=$((ITERATION - 1))
        continue
    fi

    # Completion check (tail only — prompt echo at top also contains the marker text)
    if echo "$OUTPUT" | tail -30 | grep -q '<promise>COMPLETE</promise>'; then
        echo ""
        echo "All tasks complete after $ITERATION iterations."
        break
    fi

    echo ""
    echo "Iteration $ITERATION done. Continuing..."
done

echo ""
echo "Record saved: $RECORD_FILE"
