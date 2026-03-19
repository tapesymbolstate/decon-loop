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
TARGET_COVERAGE=${TARGET_COVERAGE:-100}
ITERATION=0
CYCLE=0
BUILD_ERRORS=""

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
   - Tasks 2+: "Reconstruct <module>" — each covers 50-500 related functions
   - Each task MUST specify \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`
   - If mapping exists: include \`sourceFiles\` listing the original source paths
   - Output file extension MUST match source language (.zig, .cpp, .c, .rs etc.)
   - 20-40 tasks, ordered by dependency. Maximize function coverage per task.
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

    # List already-completed source files so planner avoids duplicating work
    local existing_files=""
    if [ -d "output/src" ]; then
        existing_files=$(ls output/src/ 2>/dev/null | tr '\n' ', ')
    fi

    # List archived PRD files for context
    local archived_prds=""
    if [ -d "output/records" ]; then
        archived_prds=$(ls output/records/prd_cycle_*.json 2>/dev/null | tr '\n' ', ')
    fi

    cat <<REPLAN_EOF
You are a source reconstruction planner running cycle $cycle_num.

## Target
Binary file: \`$BINARY_PATH\`

## Previous cycle result
\`\`\`
$build_errors
\`\`\`

## Diagnosis
- "COVERAGE:" → previous cycle succeeded but more functions need lifting. Plan the NEXT batch of modules.
- "QUALITY:" → source is metadata/stubs, not real code. Delete and re-lift from Ghidra.
- "COMPILATION:" → real code but compile errors. Fix specific issues.

## Already completed source files (DO NOT recreate these)
\`\`\`
$existing_files
\`\`\`
${archived_prds:+Previous PRDs: $archived_prds}

## Available data
- \`output/progress.txt\`, \`output/src/\` (already lifted code — keep these!)
- \`output/ghidra/function_boundaries.tsv\`, \`call_graph.tsv\`, \`functions/\`, \`module_chunks.tsv\`
$mapping_note
## Job
1. Read \`output/mapping/function_map.tsv\` (or \`function_boundaries.tsv\`) to find functions NOT yet covered by existing source files
2. Read \`output/ghidra/module_chunks.tsv\` to identify the next batch of address-prefix groups to lift
3. Generate NEW \`output/prd.json\` (\`"cycle": $cycle_num\`):
   - Plan 15-25 NEW tasks covering functions not in existing source files
   - Every task: \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`
   - If mapping available: include \`sourceFiles\`, match output language to original
   - Target different source files than already completed ones
   - Output must be real source code, not analysis artifacts
4. Append cycle note to \`output/progress.txt\`

## CRITICAL: Do NOT duplicate work. The goal is to EXPAND coverage, not redo what's done.

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
            --model "${CODEX_MODEL:-gpt-5.4}" \
            2>&1 || true
    else
        claude -p \
            --model opus \
            --effort "${CLAUDE_EFFORT:-max}" \
            --permission-mode bypassPermissions \
            --dangerously-skip-permissions \
            "$prompt" \
            2>&1 || true
    fi
}

# ─── Coverage: measure how many mapped functions have been lifted ─────────────

measure_coverage() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase:  COVERAGE CHECK"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local total_mapped lifted_funcs coverage_pct

    if [ "$HAS_FUNCTION_MAP" = true ] && [ -f "output/mapping/function_map.tsv" ]; then
        total_mapped=$(tail -n +2 output/mapping/function_map.tsv | wc -l | tr -d ' ')
    else
        total_mapped=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
    fi

    # Count function definitions across all source languages
    lifted_funcs=0
    if find output/src -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
        local c_funcs
        c_funcs=$(find output/src \( -name '*.cpp' -o -name '*.c' \) -exec grep -cE '^[a-zA-Z_].*\(.*\)\s*\{' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        lifted_funcs=$((lifted_funcs + c_funcs))
    fi
    if find output/src -name '*.zig' 2>/dev/null | grep -q .; then
        local zig_funcs
        zig_funcs=$(find output/src -name '*.zig' -exec grep -cE '^\s*(pub\s+)?(export\s+)?fn\s+' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        lifted_funcs=$((lifted_funcs + zig_funcs))
    fi

    if [ "$total_mapped" -gt 0 ]; then
        coverage_pct=$((lifted_funcs * 100 / total_mapped))
    else
        coverage_pct=0
    fi

    # Count total LOC across all languages
    local all_src_files total_loc total_files
    all_src_files=$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.zig' -o -name '*.rs' -o -name '*.h' 2>/dev/null)
    if [ -n "$all_src_files" ]; then
        total_files=$(echo "$all_src_files" | wc -l | tr -d ' ')
        total_loc=$(echo "$all_src_files" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    else
        total_files=0
        total_loc=0
    fi

    echo "Coverage: $lifted_funcs/$total_mapped functions lifted ($coverage_pct%)"
    echo "Source:   $total_files files, $total_loc LOC"

    COVERAGE_PCT=$coverage_pct
    COVERAGE_FUNCS=$lifted_funcs
    COVERAGE_TOTAL=$total_mapped
    COVERAGE_LOC=$total_loc
    COVERAGE_FILES=$total_files
}

# ─── Verify: try to compile output/src/ ──────────────────────────────────────

verify_build() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Phase:  VERIFY (compilation + quality)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # ── Gate A: source files exist (any language) ──
    local all_src
    all_src=$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.zig' -o -name '*.rs' -o -name '*.h' 2>/dev/null)
    if [ -z "$all_src" ]; then
        echo "FAIL: No source files in output/src/"
        BUILD_ERRORS="No source files found in output/src/. Must lift Ghidra functions into compilable source."
        return 1
    fi

    # ── Gate B: source quantity thresholds ──
    local file_count loc
    file_count=$(echo "$all_src" | wc -l | tr -d ' ')
    loc=$(echo "$all_src" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "Source: $file_count files, $loc LOC"

    if [ "$loc" -lt 500 ]; then
        echo "FAIL: Only $loc LOC (need ≥500)."
        BUILD_ERRORS="QUALITY: Only $loc lines of code across $file_count files. Minimum 500 LOC required."
        return 1
    fi

    # ── Gate C: source quality — real function logic ──
    local func_defs=0
    # C/C++ functions
    if find output/src -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
        local c_funcs
        c_funcs=$(find output/src \( -name '*.cpp' -o -name '*.c' \) -exec grep -cE '^[a-zA-Z_].*\(.*\)\s*\{' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        func_defs=$((func_defs + c_funcs))
    fi
    # Zig functions
    if find output/src -name '*.zig' 2>/dev/null | grep -q .; then
        local zig_funcs
        zig_funcs=$(find output/src -name '*.zig' -exec grep -cE '^\s*(pub\s+)?(export\s+)?fn\s+' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        func_defs=$((func_defs + zig_funcs))
    fi
    echo "Function definitions: $func_defs"
    if [ "$func_defs" -lt 10 ]; then
        echo "FAIL: Only $func_defs function definitions (need ≥10)."
        BUILD_ERRORS="QUALITY: Only $func_defs function definitions found."
        return 1
    fi

    # ── Gate D: compilation per language ──
    local errors="" compile_rc=0

    # C/C++ compilation
    if find output/src -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
        while IFS= read -r srcfile; do
            file_errors=$(clang++ -std=c++17 -target arm64-apple-macos -c "$srcfile" -o /dev/null 2>&1)
            file_rc=$?
            if [ "$file_rc" -ne 0 ]; then
                compile_rc=$file_rc
                errors="${errors}${file_errors}\n"
            fi
        done < <(find output/src -name '*.cpp' -o -name '*.c')
    fi

    # Zig syntax check
    if find output/src -name '*.zig' 2>/dev/null | grep -q .; then
        while IFS= read -r srcfile; do
            file_errors=$(zig ast-check "$srcfile" 2>&1)
            file_rc=$?
            if [ "$file_rc" -ne 0 ]; then
                compile_rc=$file_rc
                errors="${errors}${srcfile}: ${file_errors}\n"
            fi
        done < <(find output/src -name '*.zig')
    fi

    if [ "$compile_rc" -ne 0 ] || [ -n "$errors" ]; then
        echo "FAIL: Compilation errors."
        echo -e "$errors" | head -50
        BUILD_ERRORS="COMPILATION:\n$errors"
        return 1
    fi

    echo "ALL GATES PASSED: $file_count files, $loc LOC, $func_defs functions, compiles clean."
    BUILD_ERRORS=""
    return 0
}

# ─── Phase 0: Ghidra pre-analysis (run once) ────────────────────────────────

mkdir -p /tmp/ghidra-projects output/ghidra

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  GHIDRA PRE-ANALYSIS                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Combined mode: single import + analysis pass for both quick and full
if [ ! -f "output/ghidra/function_boundaries.tsv" ] && [ ! -f "output/ghidra/all_decompiled.c" ]; then
    echo "Running combined analysis (quick + parallel decompilation in one pass)..."
    ./ghidra_analyze.sh "$BINARY_PATH" combined 2>&1 | tee -a "$RECORD_FILE"
elif [ ! -f "output/ghidra/function_boundaries.tsv" ]; then
    echo "Running quick analysis..."
    ./ghidra_analyze.sh "$BINARY_PATH" quick 2>&1 | tee -a "$RECORD_FILE"
elif [ ! -f "output/ghidra/all_decompiled.c" ]; then
    echo "Running parallel decompilation (reusing existing project)..."
    ./ghidra_analyze.sh "$BINARY_PATH" full 2>&1 | tee -a "$RECORD_FILE"
else
    FUNC_COUNT=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
    DECOMP_SIZE=$(du -sh output/ghidra/all_decompiled.c | cut -f1)
    echo "Ghidra data cached: $FUNC_COUNT functions, $DECOMP_SIZE decompiled. Skipping."
fi

# Verify outputs
if [ -f "output/ghidra/function_boundaries.tsv" ]; then
    FUNC_COUNT=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
    echo "Functions: $FUNC_COUNT"
fi
if [ -f "output/ghidra/all_decompiled.c" ]; then
    DECOMP_SIZE=$(du -sh output/ghidra/all_decompiled.c | cut -f1)
    echo "Decompiled: $DECOMP_SIZE"
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

# Handle resume: if PRD exists with all tasks done, skip straight to verify+coverage
if [ -f "$PRD" ] && ! python3 -c "import json,sys; d=json.load(open('$PRD')); sys.exit(0 if any(not s['passes'] for s in d['userStories']) else 1)" 2>/dev/null; then
    echo "Existing PRD found with all tasks complete. Checking coverage..."
    CYCLE=$((CYCLE + 1))
    BUILD_ERRORS=""
    if verify_build; then
        measure_coverage
        if [ "$COVERAGE_PCT" -ge "$TARGET_COVERAGE" ]; then
            echo "Coverage target already met ($COVERAGE_PCT%). Nothing to do."
            exit 0
        fi
        echo "Coverage: $COVERAGE_PCT% (target: $TARGET_COVERAGE%). Expanding..."
        BUILD_ERRORS="COVERAGE: Only $COVERAGE_PCT% of functions lifted ($COVERAGE_FUNCS/$COVERAGE_TOTAL). Need $TARGET_COVERAGE%. Already completed files: $(ls output/src/ 2>/dev/null | tr '\n' ', ')"
        cp "$PRD" "output/records/prd_cycle_${CYCLE}.json" 2>/dev/null
        rm -f "$PRD"
    fi
fi

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

        # Use replan prompt if we have existing source (expanding coverage)
        if [ ! -f "$PRD" ] && [ -d "output/src" ] && find output/src -name '*.zig' -o -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
            echo "(Expanding coverage — planning next batch)"
            PLAN_PROMPT=$(gen_replan_prompt "$CYCLE" "$BUILD_ERRORS")
        else
            PLAN_PROMPT=$(gen_plan_prompt)
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
        # Verification passed — now check coverage
        measure_coverage

        if [ "$COVERAGE_PCT" -ge "$TARGET_COVERAGE" ]; then
            echo ""
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║  SUCCESS — Coverage target reached! Mission complete.       ║"
            echo "╠══════════════════════════════════════════════════════════════╣"
            echo "║  Functions: $COVERAGE_FUNCS/$COVERAGE_TOTAL ($COVERAGE_PCT%)"
            echo "║  Source:    $COVERAGE_FILES files, $COVERAGE_LOC LOC"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Record saved: $RECORD_FILE"
            exit 0
        fi

        echo ""
        echo "Verification passed but coverage is $COVERAGE_PCT% (target: $TARGET_COVERAGE%)."
        echo "Archiving PRD and planning next batch..."
        BUILD_ERRORS="COVERAGE: Only $COVERAGE_PCT% of functions lifted ($COVERAGE_FUNCS/$COVERAGE_TOTAL). Need $TARGET_COVERAGE%. Already completed files: $(ls output/src/ 2>/dev/null | tr '\n' ', ')"

        # Archive current PRD and force re-plan for next batch
        cp "$PRD" "output/records/prd_cycle_${CYCLE}.json" 2>/dev/null
        rm -f "$PRD"
    fi

    echo ""
    echo "Starting cycle $((CYCLE + 1))..."
    echo ""
done
