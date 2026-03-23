#!/bin/bash
# Decon Agent — Binary Decompilation via Ralph Loop
#
# Usage: ./loop_decon.sh <binary_path> [codex|codex-spark|claude] [max_iterations]
#
# Examples:
#   ./loop_decon.sh target-binaries/sample-binary                    # Claude, unlimited
#   ./loop_decon.sh target-binaries/sample-binary codex 50           # Codex gpt-5.4, max 50
#   ./loop_decon.sh target-binaries/sample-binary codex-spark        # Codex Spark (fast), unlimited
#
# Multi-cycle workflow:
#   1. Plan   → auto-generate analysis plan from binary recon (or existing findings)
#   2. Build  → iterate through plan tasks
#   3. Verify → attempt to compile output/src/
#   4. If compilation fails → archive plan, re-plan with deeper tasks, goto 2
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
if [ "${1:-}" = "codex" ] || [ "${1:-}" = "codex-spark" ] || [ "${1:-}" = "claude" ]; then
    TOOL="$1"
    shift
fi

MAX_ITERATIONS=${1:-0}
TARGET_COVERAGE=${TARGET_COVERAGE:-100}
ITERATION=0
CYCLE=0
BUILD_ERRORS=""
ANALYSIS_MODE="full_reconstruction"
BUNDLED_FORMAT=""        # detected bundled format: bun, node_sea, electron, pyinstaller, ...
BUNDLED_LANGUAGE=""      # language of the embedded code: javascript, python, etc.

PLAN="output/analysis_plan.json"
PROGRESS="output/progress.txt"

# ─── Records setup ───────────────────────────────────────────────────────────

RECORDS_DIR="output/records"
mkdir -p "$RECORDS_DIR"
if [ ! -f "$RECORDS_DIR/.gitignore" ]; then
    printf '*\n!.gitignore\n' > "$RECORDS_DIR/.gitignore"
fi
RECORD_FILE="$RECORDS_DIR/$(date '+%Y-%m-%d-%H%M%S')-decon-$TOOL.jsonl"
echo "Record: $RECORD_FILE"

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

4. Generate \`output/analysis_plan.json\` with schema:
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

    # List archived plan files for context
    local archived_plans=""
    if [ -d "output/records" ]; then
        archived_plans=$(ls output/records/plan_cycle_*.json 2>/dev/null | tr '\n' ', ')
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
${archived_plans:+Previous plans: $archived_plans}

## Available data
- \`output/progress.txt\`, \`output/src/\` (already lifted code — keep these!)
- \`output/ghidra/function_boundaries.tsv\`, \`call_graph.tsv\`, \`functions/\`, \`module_chunks.tsv\`
$mapping_note
## Job
1. Read \`output/mapping/function_map.tsv\` (or \`function_boundaries.tsv\`) to find functions NOT yet covered by existing source files
2. Read \`output/ghidra/module_chunks.tsv\` to identify the next batch of address-prefix groups to lift
3. Generate NEW \`output/analysis_plan.json\` (\`"cycle": $cycle_num\`):
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
1. \`output/analysis_plan.json\` — task list with \`ghidraFunctions\`, \`targetSourceFile\`, and optionally \`sourceFiles\`
2. \`output/progress.txt\` — cumulative findings
$mapping_section
## Workflow

### Step 1: Identify your task
Read \`output/analysis_plan.json\`, find the highest-priority task where \`passes\` is \`false\`.

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
- Update \`output/analysis_plan.json\`: set \`passes: true\`, note function count and accuracy
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

# ─── Prompt: custom extraction plan (when framework source is known) ─────────

gen_custom_plan_prompt() {
    local cycle_num="${1:-1}"
    local build_errors="${2:-}"
    local composition
    composition=$(cat output/composition/analysis.json 2>/dev/null || echo '{}')

    local existing_files=""
    if [ -d "output/src" ]; then
        existing_files=$(ls output/src/ 2>/dev/null | tr '\n' ', ')
    fi

    local archived_plans=""
    if [ -d "output/records" ]; then
        archived_plans=$(ls output/records/plan_cycle_*.json 2>/dev/null | tr '\n' ', ')
    fi

    cat <<CUSTOM_PLAN_EOF
You are an autonomous binary analysis planner. Your goal is to extract and understand the CUSTOM application logic inside a binary that was built on top of a known open-source framework.

## Target
Binary file: \`$BINARY_PATH\`

## Key Insight
This binary was built using an open-source framework. The framework source is already available — DO NOT reconstruct it. Instead, focus on what is UNIQUE to this binary.

## Composition Analysis
\`\`\`json
$composition
\`\`\`

## Available data
- \`output/ghidra/function_boundaries.tsv\` — all detected functions
- \`output/ghidra/call_graph.tsv\` — caller→callee relationships
- \`output/ghidra/functions/<prefix>/<funcname>_<addr>.c\` — individual Ghidra decompilations
- \`output/ghidra/module_chunks.tsv\` — address-prefix groupings
- \`output/mapping/function_map.tsv\` — framework function→source mappings (ALREADY KNOWN — skip these)
- \`output/mapping/helper_aliases.tsv\` — FUN_*→original name aliases
- \`output/composition/analysis.json\` — function categorization breakdown
- \`reference-src/\` — framework source (for understanding API calls only)
${build_errors:+
## Previous cycle result
\`\`\`
$build_errors
\`\`\`}
${existing_files:+
## Already analyzed files (DO NOT recreate)
\`\`\`
$existing_files
\`\`\`}
${archived_plans:+Previous plans: $archived_plans}

## Strategy: Triage → Classify → Extract

The composition analysis has grouped unknown functions into address-proximity clusters.
Your job has TWO phases:

### Phase A: TRIAGE (classify each cluster)
For the top clusters listed in \`analysis.json\`:
1. Sample 2-3 functions from each cluster — read their Ghidra pseudocode
2. Look at string literals, API call patterns, code structure
3. Classify each cluster as one of:
   - **"third_party"**: Recognizable open-source library (crypto, compression, parser, VM engine, etc.)
     Include a \`libraryGuess\` field with your best guess of what it is
   - **"custom"**: Application-specific logic unique to this binary
   - **"runtime_generated"**: Compiler/VM-generated dispatch tables, trampolines, stubs

### Phase B: PLAN (create tasks for custom + unknown clusters only)
- Skip clusters classified as "third_party" or "runtime_generated"
- Create reconstruction tasks ONLY for "custom" clusters

### What to SKIP (already excluded by harness):
- Functions in \`function_map.tsv\` (framework code)
- Functions named \`thunk_*\`, \`__*\`, \`caseD_*\` (compiler artifacts)
- Functions only called by framework code (propagated)

### What to FOCUS ON:
- Unclassified \`FUN_*\` function clusters from \`analysis.json\`
- Use \`call_graph.tsv\` to understand inter-cluster relationships
- Look for string references that reveal application-specific behavior
- Check what framework APIs these functions call (translate via helper_aliases.tsv)

### Steps
1. Read \`output/composition/analysis.json\` — see \`top_clusters\` for prioritized cluster list
2. For each top cluster: read 2-3 sample functions from \`output/ghidra/functions/<prefix>/\`
3. Classify each cluster (third_party / custom / runtime_generated)
4. For "custom" clusters: plan reconstruction tasks

5. Generate \`output/analysis_plan.json\` with schema:
   \`\`\`json
   { "binaryTarget": "$BINARY_PATH", "binaryType": "DESC", "cycle": $cycle_num,
     "analysisMode": "custom_extraction",
     "triageResults": [
       {"prefix": "1032be", "classification": "runtime_generated", "reason": "VM dispatch table"},
       {"prefix": "102a80", "classification": "third_party", "libraryGuess": "JavaScriptCore DollarVM", "reason": "debug intrinsics"},
       {"prefix": "102758", "classification": "custom", "reason": "app-specific Intl adapter"}
     ],
     "userStories": [{
       "id": "US-001", "title": "...", "description": "...",
       "ghidraFunctions": ["FUN_XXXXX"],
       "addressRange": "0x100XXXX-0x100YYYY",
       "targetSourceFile": "output/src/custom_module.c",
       "clusterType": "custom",
       "calledFrameworkAPIs": ["api_name1", "api_name2"],
       "acceptanceCriteria": ["..."], "priority": 1, "passes": false, "notes": "" }]
   }
   \`\`\`

   Task rules:
   - 15-30 tasks, but ONLY for clusters classified as "custom"
   - Include \`triageResults\` array so future cycles know what was already classified
   - Order by: largest custom clusters first
   - Each task: \`ghidraFunctions\`, \`addressRange\`, \`targetSourceFile\`, \`calledFrameworkAPIs\`
   - DO NOT create tasks for third_party or runtime_generated clusters

6. Generate \`output/progress.txt\` with analysis summary.

## Rules
- NEVER modify the target binary. All output inside \`output/\`
- Every task must produce real source code in \`output/src/\`
- Use framework API names (not FUN_*) when the custom code calls known functions

## Completion
When done, output: <promise>PLAN_COMPLETE</promise>
CUSTOM_PLAN_EOF
}

# ─── Prompt: custom extraction build ─────────────────────────────────────────

gen_custom_build_prompt() {
    cat <<CUSTOM_BUILD_EOF
You are an autonomous binary analysis agent. Your job: extract and reconstruct CUSTOM application logic from a binary built on a known framework.

## Target
Binary file: \`$BINARY_PATH\`

## Context — read FIRST
1. \`output/analysis_plan.json\` — task list with custom function clusters
2. \`output/progress.txt\` — cumulative findings
3. \`output/composition/analysis.json\` — function categorization

## Available data
- \`output/ghidra/functions/<prefix>/<funcname>_<addr>.c\` — Ghidra decompilations
- \`output/ghidra/call_graph.tsv\` — caller→callee relationships
- \`output/mapping/function_map.tsv\` — framework function mappings (for resolving API names)
- \`output/mapping/helper_aliases.tsv\` — FUN_*→meaningful name aliases
- \`reference-src/\` — framework source (read-only reference for understanding API contracts)

## Workflow

### Step 1: Identify your task
Read \`output/analysis_plan.json\`, find the highest-priority task where \`passes\` is \`false\`.

### Step 2: Analyze the custom function cluster

For each function in the task's \`ghidraFunctions\`:

a) Read the Ghidra pseudocode from \`output/ghidra/functions/\`
b) Identify what framework APIs it calls:
   - Look up callee FUN_* names in \`helper_aliases.tsv\` and \`function_map.tsv\`
   - Replace FUN_* with meaningful names
c) Determine the function's purpose from:
   - String literals referenced
   - Framework APIs called (check \`reference-src/\` to understand what those APIs do)
   - Control flow patterns
   - Data structures accessed
d) Clean up the pseudocode:
   - \`undefined8\` → \`uint64_t\`, \`FUN_*\` → meaningful names
   - \`param_N\` → descriptive parameter names based on how they're used
   - Add comments explaining the logic

### Step 3: Write source files
- Produce clean, readable C source (or match the framework language if evident)
- Declare framework APIs as \`extern\` with their proper signatures
- Add comments: \`// @ghidra: <address>\` and \`// calls: <framework_api_name>\`
- Group related functions into logical modules

### Step 4: Compile and verify
- \`clang -std=c17 -target arm64-apple-macos -c <file> -o /dev/null 2>&1\`
- For Zig: \`zig ast-check <file> 2>&1\`
- Only set \`passes: true\` if verification succeeds

### Step 5: Update state
- Update \`output/analysis_plan.json\`: set \`passes: true\`, note what the custom code does
- Append findings to \`output/progress.txt\`

## CRITICAL RULES
- Output must be REAL SOURCE CODE with meaningful names and proper types
- Focus on UNDERSTANDING what the custom code does, not just cleaning syntax
- Use framework API names (from mappings) instead of raw FUN_* addresses
- ONE task per iteration
- NEVER modify the target binary

## Completion
If ALL tasks have \`passes: true\`, output: <promise>CYCLE_DONE</promise>
Otherwise, complete your one task and exit.
CUSTOM_BUILD_EOF
}

# ─── Composition analysis ─────────────────────────────────────────────────────

analyze_composition() {
    echo "Analyzing binary composition..."
    mkdir -p output/composition

    python3 <<'COMPOSITION_PY'
import csv, json, os
from collections import defaultdict, Counter

# Load all functions
all_funcs = {}
with open('output/ghidra/function_boundaries.tsv') as f:
    for row in csv.DictReader(f, delimiter='\t'):
        all_funcs[row['entry_address']] = row

# Load mapped (framework) functions
mapped_addrs = set()
if os.path.exists('output/mapping/function_map.tsv'):
    with open('output/mapping/function_map.tsv') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            mapped_addrs.add(row.get('ghidra_address', ''))

# Load call graph
callers_of = defaultdict(set)  # func -> set of callers
callees_of = defaultdict(set)  # func -> set of callees
if os.path.exists('output/ghidra/call_graph.tsv'):
    with open('output/ghidra/call_graph.tsv') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            caller = row.get('caller_address', row.get('caller', ''))
            callee = row.get('callee_address', row.get('callee', ''))
            if caller and callee:
                callees_of[caller].add(callee)
                callers_of[callee].add(caller)

# ── Step 1: Basic categorization (generic, no hardcoded library names) ──
categories = {
    'framework': [],
    'compiler_system': [],
    'unknown': [],
}
subcats = Counter()

for addr, func in all_funcs.items():
    name = func['name']

    # Framework (mapped to source)
    if addr in mapped_addrs:
        categories['framework'].append(addr)
        continue

    # Compiler-generated trampolines
    if name.startswith('thunk_'):
        categories['compiler_system'].append(addr)
        subcats['thunks'] += 1
        continue

    # System/runtime (double-underscore convention)
    if name.startswith('__'):
        categories['compiler_system'].append(addr)
        subcats['system'] += 1
        continue

    # C++ mangled symbols (framework or third-party internals)
    if name.startswith('_ZN') or name.startswith('_ZL') or name.startswith('_ZTV'):
        categories['compiler_system'].append(addr)
        subcats['cpp_mangled'] += 1
        continue

    # Switch/vtable artifacts
    if name.startswith('caseD_') or name.startswith('switchD_'):
        categories['compiler_system'].append(addr)
        subcats['switch_cases'] += 1
        continue

    # Short libc-style named functions (not FUN_)
    if not name.startswith('FUN_') and name.startswith('_') and len(name) < 30:
        categories['compiler_system'].append(addr)
        subcats['libc_style'] += 1
        continue

    # Everything else = unknown (to be clustered and triaged by agent)
    categories['unknown'].append(addr)

# ── Step 2: Address-proximity clustering (generic, works for any binary) ──
# Group unknown functions by address prefix (6 hex chars = ~64KB blocks)
# Functions from the same library/module tend to be linked contiguously
addr_clusters = defaultdict(list)
for addr in categories['unknown']:
    prefix = addr[:6] if len(addr) > 6 else addr
    addr_clusters[prefix].append(addr)

# ── Step 3: Call-graph propagation from framework ──
# If a function is ONLY called by framework functions, it's likely
# framework-internal (inlined/optimized). Don't hardcode what it is.
framework_addrs = set(categories['framework'])
propagated_framework = []
remaining_unknown = []
for addr in categories['unknown']:
    callers = callers_of.get(addr, set())
    if callers and all(c in framework_addrs for c in callers):
        propagated_framework.append(addr)
    else:
        remaining_unknown.append(addr)

categories['unknown'] = remaining_unknown

# ── Step 4: Build cluster summaries for agent triage ──
total = len(all_funcs)

# Re-cluster remaining unknown by address prefix
unknown_clusters = defaultdict(list)
for addr in categories['unknown']:
    prefix = addr[:6] if len(addr) > 6 else addr
    unknown_clusters[prefix].append(addr)

# Build cluster info with size and connectivity data
cluster_summaries = []
for prefix in sorted(unknown_clusters.keys(), key=lambda k: -len(unknown_clusters[k])):
    addrs = unknown_clusters[prefix]
    total_size = sum(int(all_funcs[a].get('size', 0)) for a in addrs)
    # Count how many framework APIs this cluster calls
    fw_api_calls = 0
    for a in addrs:
        for callee in callees_of.get(a, set()):
            if callee in framework_addrs:
                fw_api_calls += 1
    cluster_summaries.append({
        'prefix': prefix,
        'function_count': len(addrs),
        'total_bytes': total_size,
        'framework_api_calls': fw_api_calls,
    })

result = {
    'total_functions': total,
    'categories': {
        'framework': {
            'count': len(categories['framework']),
            'pct': round(len(categories['framework']) * 100 / total, 1),
            'description': 'Mapped to framework source (already known)',
        },
        'framework_propagated': {
            'count': len(propagated_framework),
            'pct': round(len(propagated_framework) * 100 / total, 1),
            'description': 'Called only by framework (likely inlined/optimized framework code)',
        },
        'compiler_system': {
            'count': len(categories['compiler_system']),
            'pct': round(len(categories['compiler_system']) * 100 / total, 1),
            'subcategories': dict(subcats),
        },
        'unknown': {
            'count': len(categories['unknown']),
            'pct': round(len(categories['unknown']) * 100 / total, 1),
            'description': 'Unclassified — to be triaged by agent into third-party vs custom',
            'cluster_count': len(unknown_clusters),
            'top_clusters': cluster_summaries[:30],
        },
    },
    'analysis_target_count': len(categories['unknown']),
    'mode': 'custom_extraction' if len(categories['framework']) > total * 0.1 else 'full_reconstruction',
}

with open('output/composition/analysis.json', 'w') as f:
    json.dump(result, f, indent=2)

print(f"Framework (mapped):    {result['categories']['framework']['count']:,} ({result['categories']['framework']['pct']}%)")
print(f"Framework (propagated):{result['categories']['framework_propagated']['count']:,} ({result['categories']['framework_propagated']['pct']}%)")
print(f"Compiler/system:       {result['categories']['compiler_system']['count']:,} ({result['categories']['compiler_system']['pct']}%)")
print(f"Unknown (to triage):   {result['categories']['unknown']['count']:,} ({result['categories']['unknown']['pct']}%)")
print(f"  Address clusters:    {len(unknown_clusters)}")
print(f"")
print(f"Analysis target: {result['analysis_target_count']:,} functions in {len(unknown_clusters)} clusters")
print(f"Recommended mode: {result['mode']}")
COMPOSITION_PY
}

# ─── Agent spawner ───────────────────────────────────────────────────────────

spawn_agent() {
    local prompt="$1"
    if [ "$TOOL" = "codex" ] || [ "$TOOL" = "codex-spark" ]; then
        local model="${CODEX_MODEL:-gpt-5.4}"
        [ "$TOOL" = "codex-spark" ] && model="gpt-5.3-codex-spark"
        echo "$prompt" | codex exec \
            --full-auto \
            --json \
            --model "$model" \
            2>&1 || true
    else
        claude -p \
            --model opus \
            --effort "${CLAUDE_EFFORT:-max}" \
            --permission-mode bypassPermissions \
            --dangerously-skip-permissions \
            --output-format=stream-json \
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

    if [ "$ANALYSIS_MODE" = "bundled_app" ] && [ -f "$PLAN" ]; then
        # For bundled apps, total = number of tasks in analysis plan
        total_mapped=$(python3 -c "import json; d=json.load(open('$PLAN')); print(len(d.get('userStories', [])))" 2>/dev/null || echo 0)
    elif [ "$ANALYSIS_MODE" = "custom_extraction" ] && [ -f "output/composition/analysis.json" ]; then
        total_mapped=$(python3 -c "import json; d=json.load(open('output/composition/analysis.json')); print(d.get('analysis_target_count', 0))" 2>/dev/null)
    elif [ "$HAS_FUNCTION_MAP" = true ] && [ -f "output/mapping/function_map.tsv" ]; then
        total_mapped=$(tail -n +2 output/mapping/function_map.tsv | wc -l | tr -d ' ')
    elif [ -f "output/ghidra/function_boundaries.tsv" ]; then
        total_mapped=$(tail -n +2 output/ghidra/function_boundaries.tsv | wc -l | tr -d ' ')
    else
        total_mapped=0
    fi

    # Count function definitions across all source languages
    lifted_funcs=0
    if find output/src -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
        local c_funcs
        c_funcs=$(find output/src \( -name '*.cpp' -o -name '*.c' -o -name '*.h' \) -exec grep -cE '^(static\s+)?(const\s+)?(unsigned\s+)?(struct\s+)?[a-zA-Z_]\w*[\w *]+\w+\s*\([^;]*\)\s*\{?$' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        lifted_funcs=$((lifted_funcs + c_funcs))
    fi
    if find output/src -name '*.zig' 2>/dev/null | grep -q .; then
        local zig_funcs
        zig_funcs=$(find output/src -name '*.zig' -exec grep -cE '^\s*(pub\s+)?(export\s+)?fn\s+' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        lifted_funcs=$((lifted_funcs + zig_funcs))
    fi
    # JavaScript/TypeScript functions
    if find output/src -name '*.js' -o -name '*.ts' 2>/dev/null | grep -q .; then
        local js_funcs
        js_funcs=$(find output/src \( -name '*.js' -o -name '*.ts' \) -exec grep -cE '^\s*(export\s+)?(async\s+)?function\s+|^\s*(const|let|var)\s+\w+\s*=\s*(async\s+)?\(' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        lifted_funcs=$((lifted_funcs + js_funcs))
    fi

    # For bundled_app, count completed tasks instead of function defs
    if [ "$ANALYSIS_MODE" = "bundled_app" ] && [ -f "$PLAN" ]; then
        lifted_funcs=$(python3 -c "import json; d=json.load(open('$PLAN')); print(sum(1 for s in d.get('userStories', []) if s.get('passes')))" 2>/dev/null || echo 0)
    fi

    if [ "$total_mapped" -gt 0 ]; then
        coverage_pct=$((lifted_funcs * 100 / total_mapped))
    else
        coverage_pct=0
    fi

    # Count total LOC across all languages
    local all_src_files total_loc total_files
    all_src_files=$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.zig' -o -name '*.rs' -o -name '*.h' -o -name '*.js' -o -name '*.ts' 2>/dev/null)
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
    all_src=$(find output/src -name '*.cpp' -o -name '*.c' -o -name '*.zig' -o -name '*.rs' -o -name '*.h' -o -name '*.js' -o -name '*.ts' 2>/dev/null)
    if [ -z "$all_src" ]; then
        echo "FAIL: No source files in output/src/"
        BUILD_ERRORS="No source files found in output/src/."
        return 1
    fi

    # ── Gate B: source quantity thresholds ──
    local file_count loc
    file_count=$(echo "$all_src" | wc -l | tr -d ' ')
    loc=$(echo "$all_src" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "Source: $file_count files, $loc LOC"

    if [ "$loc" -lt 500 ]; then
        echo "FAIL: Only $loc LOC (need >=500)."
        BUILD_ERRORS="QUALITY: Only $loc lines of code across $file_count files. Minimum 500 LOC required."
        return 1
    fi

    # ── Gate C: source quality — real function logic ──
    local func_defs=0
    # C/C++ functions
    if find output/src -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
        local c_funcs
        c_funcs=$(find output/src \( -name '*.cpp' -o -name '*.c' -o -name '*.h' \) -exec grep -cE '^(static\s+)?(const\s+)?(unsigned\s+)?(struct\s+)?[a-zA-Z_]\w*[\w *]+\w+\s*\([^;]*\)\s*\{?$' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        func_defs=$((func_defs + c_funcs))
    fi
    # Zig functions
    if find output/src -name '*.zig' 2>/dev/null | grep -q .; then
        local zig_funcs
        zig_funcs=$(find output/src -name '*.zig' -exec grep -cE '^\s*(pub\s+)?(export\s+)?fn\s+' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        func_defs=$((func_defs + zig_funcs))
    fi
    # JavaScript/TypeScript functions
    if find output/src -name '*.js' -o -name '*.ts' 2>/dev/null | grep -q .; then
        local js_funcs
        js_funcs=$(find output/src \( -name '*.js' -o -name '*.ts' \) -exec grep -cE '^\s*(export\s+)?(async\s+)?function\s+|^\s*(const|let|var)\s+\w+\s*=\s*(async\s+)?\(' {} \; 2>/dev/null | awk '{s+=$1}END{print s+0}')
        func_defs=$((func_defs + js_funcs))
    fi
    echo "Function definitions: $func_defs"
    if [ "$func_defs" -lt 10 ]; then
        echo "FAIL: Only $func_defs function definitions (need >=10)."
        BUILD_ERRORS="QUALITY: Only $func_defs function definitions found."
        return 1
    fi

    # ── Gate D: syntax verification per language ──
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

    # JavaScript syntax check (node --check)
    if find output/src -name '*.js' 2>/dev/null | grep -q .; then
        if command -v node &>/dev/null; then
            while IFS= read -r srcfile; do
                file_errors=$(node --check "$srcfile" 2>&1)
                file_rc=$?
                if [ "$file_rc" -ne 0 ]; then
                    compile_rc=$file_rc
                    errors="${errors}${srcfile}: ${file_errors}\n"
                fi
            done < <(find output/src -name '*.js')
        else
            echo "  Warning: node not found, skipping JS syntax check"
        fi
    fi

    # Python syntax check (py_compile)
    if find output/src -name '*.py' 2>/dev/null | grep -q .; then
        if command -v python3 &>/dev/null; then
            while IFS= read -r srcfile; do
                file_errors=$(python3 -m py_compile "$srcfile" 2>&1)
                file_rc=$?
                if [ "$file_rc" -ne 0 ]; then
                    compile_rc=$file_rc
                    errors="${errors}${srcfile}: ${file_errors}\n"
                fi
            done < <(find output/src -name '*.py')
        fi
    fi

    # Go syntax check (go vet)
    if find output/src -name '*.go' 2>/dev/null | grep -q .; then
        if command -v go &>/dev/null; then
            file_errors=$(cd output/src && go vet ./... 2>&1)
            file_rc=$?
            if [ "$file_rc" -ne 0 ]; then
                compile_rc=$file_rc
                errors="${errors}Go vet: ${file_errors}\n"
            fi
        fi
    fi

    # Rust syntax check (rustc --edition 2021)
    if find output/src -name '*.rs' 2>/dev/null | grep -q .; then
        if command -v rustc &>/dev/null; then
            while IFS= read -r srcfile; do
                file_errors=$(rustc --edition 2021 --crate-type lib "$srcfile" -o /dev/null 2>&1)
                file_rc=$?
                if [ "$file_rc" -ne 0 ]; then
                    compile_rc=$file_rc
                    errors="${errors}${srcfile}: ${file_errors}\n"
                fi
            done < <(find output/src -name '*.rs')
        fi
    fi

    if [ "$compile_rc" -ne 0 ] || [ -n "$errors" ]; then
        echo "FAIL: Syntax/compilation errors."
        echo -e "$errors" | head -50
        BUILD_ERRORS="COMPILATION:\n$errors"
        return 1
    fi

    echo "ALL GATES PASSED: $file_count files, $loc LOC, $func_defs functions, syntax clean."
    BUILD_ERRORS=""
    return 0
}

# ─── Phase -1: Detect bundled-app binaries ────────────────────────────────────
# Checks for binaries that embed application source code (JS, Python, etc.)
# in a special segment or appended payload. Each format has its own extractor.

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  BINARY FORMAT DETECTION                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Detect bundled format ──────────────────────────────────────────────────
if otool -l "$BINARY_PATH" 2>/dev/null | grep -q "__BUN"; then
    BUNDLED_FORMAT="bun"
    BUNDLED_LANGUAGE="javascript"
    echo ">>> Detected: Bun compiled app (found __BUN Mach-O segment)"
elif strings "$BINARY_PATH" 2>/dev/null | grep -qE 'NODE_SEA_BLOB|NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'; then
    BUNDLED_FORMAT="node_sea"
    BUNDLED_LANGUAGE="javascript"
    echo ">>> Detected: Node.js Single Executable Application (SEA)"
elif strings "$BINARY_PATH" 2>/dev/null | grep -qE 'electron\.asar|ELECTRON_RUN_AS_NODE'; then
    BUNDLED_FORMAT="electron"
    BUNDLED_LANGUAGE="javascript"
    echo ">>> Detected: Electron application"
elif strings "$BINARY_PATH" 2>/dev/null | grep -qE '_MEIPASS|pyiboot|PyInstaller'; then
    BUNDLED_FORMAT="pyinstaller"
    BUNDLED_LANGUAGE="python"
    echo ">>> Detected: PyInstaller bundled Python application"
elif strings "$BINARY_PATH" 2>/dev/null | grep -qE 'pkg/prelude|pkg\.js\.snapshot'; then
    BUNDLED_FORMAT="pkg"
    BUNDLED_LANGUAGE="javascript"
    echo ">>> Detected: Vercel pkg bundled Node.js application"
else
    echo ">>> No bundled-app format detected. Proceeding with native binary pipeline."
fi
echo ""

if [ -n "$BUNDLED_FORMAT" ]; then
    echo "  Format:   $BUNDLED_FORMAT"
    echo "  Language: $BUNDLED_LANGUAGE"
    echo ""

    mkdir -p output/bundled_app output/src

    # ── Format-specific extraction ─────────────────────────────────────────
    if [ ! -f "output/bundled_app/app_bundle_extracted" ]; then

    if [ "$BUNDLED_FORMAT" = "bun" ]; then
        echo "Extracting embedded application code from __BUN Mach-O segment..."

        BINARY_PATH="$BINARY_PATH" python3 <<'BUN_EXTRACT_PY'
import struct, re, os, json

binary = os.environ.get("BINARY_PATH", "")
if not binary:
    import sys; sys.exit("BINARY_PATH not set")

# Parse Mach-O to find __BUN segment
with open(binary, 'rb') as f:
    magic = struct.unpack('<I', f.read(4))[0]
    if magic == 0xFEEDFACF:  # 64-bit Mach-O
        f.seek(0)
        header = f.read(32)
        _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack('<IIIIIIII', header)

        offset = 32
        bun_offset = None
        bun_size = None
        for _ in range(ncmds):
            f.seek(offset)
            cmd, cmdsize = struct.unpack('<II', f.read(8))

            if cmd == 0x19:  # LC_SEGMENT_64
                f.seek(offset + 8)
                segname = f.read(16).split(b'\x00')[0].decode('ascii', errors='replace')
                if segname == '__BUN':
                    f.seek(offset + 48)
                    bun_offset = struct.unpack('<Q', f.read(8))[0]
                    bun_size = struct.unpack('<Q', f.read(8))[0]
                    break
            offset += cmdsize

        if bun_offset and bun_size:
            f.seek(bun_offset)
            data = f.read(bun_size)

            # Decode and extract readable JS
            text = data.decode('utf-8', errors='replace')

            # Find contiguous readable segments
            segments = []
            current = []
            for i, ch in enumerate(text):
                if ch.isprintable() or ch in '\n\r\t':
                    current.append(ch)
                else:
                    if len(current) > 200:
                        segments.append(''.join(current))
                    current = []
            if len(current) > 200:
                segments.append(''.join(current))

            # Separate app code from Bun builtins
            app_segments = []
            builtin_segments = []
            for seg in segments:
                if '@getInternalField' in seg or '@createInternalModuleById' in seg:
                    builtin_segments.append(seg)
                else:
                    app_segments.append(seg)

            # Save app bundle
            with open('output/bundled_app/app_bundle.js', 'w') as out:
                for seg in app_segments:
                    out.write(seg + '\n')

            # Save builtins separately
            with open('output/bundled_app/bun_builtins.js', 'w') as out:
                for seg in builtin_segments:
                    out.write(seg + '\n')

            # Detect app identity
            all_app = '\n'.join(app_segments[:5])
            app_info = {'format': 'bun', 'bundled_language': 'javascript', 'bun_section_size': bun_size}

            # Look for version, name, copyright
            ver_match = re.search(r'Version:\s*([0-9]+\.[0-9]+\.[0-9]+)', all_app)
            if ver_match:
                app_info['app_version'] = ver_match.group(1)
            copy_match = re.search(r'\(c\)\s*(.+?)\.', all_app)
            if copy_match:
                app_info['copyright'] = copy_match.group(1).strip()
            name_match = re.search(r'//\s*(\w[\w\s]+)\s*is a', all_app)
            if name_match:
                app_info['app_name'] = name_match.group(1).strip()

            with open('output/bundled_app/app_info.json', 'w') as out:
                json.dump(app_info, out, indent=2)

            app_chars = sum(len(s) for s in app_segments)
            builtin_chars = sum(len(s) for s in builtin_segments)
            print(f"  App code:     {app_chars:,} chars ({len(app_segments)} segments)")
            print(f"  Bun builtins: {builtin_chars:,} chars ({len(builtin_segments)} segments)")
            print(f"  Saved to:     output/bundled_app/")

            if 'app_name' in app_info:
                print(f"  App name:     {app_info['app_name']}")
            if 'app_version' in app_info:
                print(f"  App version:  {app_info['app_version']}")
        else:
            print("  Warning: __BUN segment found but could not parse offset/size")
    else:
        print("  Warning: Not a 64-bit Mach-O, skipping __BUN extraction")
BUN_EXTRACT_PY

        touch output/bundled_app/app_bundle_extracted

    elif [ "$BUNDLED_FORMAT" = "node_sea" ]; then
        echo "Node.js SEA extraction — using postject/node sentinel detection..."
        echo "  (Extractor not yet implemented — the AI agent will analyze the binary directly)"
        # TODO: extract embedded blob via NODE_SEA_BLOB sentinel
        touch output/bundled_app/app_bundle_extracted

    elif [ "$BUNDLED_FORMAT" = "electron" ]; then
        echo "Electron app — extracting asar archive..."
        echo "  (Extractor not yet implemented — the AI agent will analyze the binary directly)"
        # TODO: locate and extract .asar from Electron bundle
        touch output/bundled_app/app_bundle_extracted

    elif [ "$BUNDLED_FORMAT" = "pyinstaller" ]; then
        echo "PyInstaller bundle — extracting Python bytecode..."
        echo "  (Extractor not yet implemented — the AI agent will analyze the binary directly)"
        # TODO: use pyinstxtractor or equivalent
        touch output/bundled_app/app_bundle_extracted

    elif [ "$BUNDLED_FORMAT" = "pkg" ]; then
        echo "Vercel pkg bundle — extracting snapshot..."
        echo "  (Extractor not yet implemented — the AI agent will analyze the binary directly)"
        # TODO: extract pkg snapshot blob
        touch output/bundled_app/app_bundle_extracted

    else
        echo "  Warning: format '$BUNDLED_FORMAT' detected but no extractor available."
        touch output/bundled_app/app_bundle_extracted
    fi

    else
        echo "Bundled app already extracted. Skipping."
        cat output/bundled_app/app_info.json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  App: {d.get(\"app_name\",\"unknown\")} v{d.get(\"app_version\",\"?\")}')
fmt=d.get('format','unknown')
print(f'  Format: {fmt}')
" 2>/dev/null
    fi

    echo ""

    # ─── Phase A: Auto-beautify (language-specific formatters) ───────────────
    if [ "$BUNDLED_LANGUAGE" = "javascript" ] && [ -f "output/bundled_app/app_bundle.js" ] && [ ! -f "output/bundled_app/app_beautified.js" ]; then
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  PHASE A: AUTO-BEAUTIFY (js-beautify)                      ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Formatting minified JS with js-beautify..."
        npx js-beautify \
            --type js \
            --indent-size 2 \
            --space-in-paren \
            --brace-style collapse,preserve-inline \
            --wrap-line-length 120 \
            -f output/bundled_app/app_bundle.js \
            -o output/bundled_app/app_beautified.js 2>&1 | tail -3
        if [ -f "output/bundled_app/app_beautified.js" ]; then
            BEFORE=$(wc -c < output/bundled_app/app_bundle.js | tr -d ' ')
            AFTER_LINES=$(wc -l < output/bundled_app/app_beautified.js | tr -d ' ')
            echo "  Beautified: $AFTER_LINES lines (from $(echo "$BEFORE" | awk '{printf "%\047d", $1}') chars minified)"
        else
            echo "  Warning: js-beautify failed, falling back to raw bundle"
            cp output/bundled_app/app_bundle.js output/bundled_app/app_beautified.js
        fi
        echo ""
    elif [ "$BUNDLED_LANGUAGE" = "python" ]; then
        echo "  Python bundle — beautification handled by the AI agent during analysis."
        echo ""
    fi

    # ─── Phase B: Chunk into logical segments ────────────────────────────────
    if [ -f "output/bundled_app/app_beautified.js" ] && [ ! -d "output/bundled_app/chunks" ]; then
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  PHASE B: CHUNKING (split into ~500-line segments)           ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""

        python3 <<'CHUNK_PY'
import re, os, json

infile = "output/bundled_app/app_beautified.js"
outdir = "output/bundled_app/chunks"
os.makedirs(outdir, exist_ok=True)

with open(infile) as f:
    lines = f.readlines()

total = len(lines)
TARGET_CHUNK = 500  # lines per chunk

# Find natural break points (top-level function/class/var declarations)
break_pattern = re.compile(r'^(function |class |var |const |let |async function |export |\(function\()')

breakpoints = [0]
for i, line in enumerate(lines):
    if i > 0 and break_pattern.match(line.lstrip()):
        # Only break if we're at roughly the target size
        if i - breakpoints[-1] >= TARGET_CHUNK * 0.7:
            breakpoints.append(i)

breakpoints.append(total)

# Write chunks
chunks_meta = []
for idx in range(len(breakpoints) - 1):
    start = breakpoints[idx]
    end = breakpoints[idx + 1]
    chunk_lines = lines[start:end]

    # Skip near-empty chunks
    content = ''.join(chunk_lines).strip()
    if len(content) < 100:
        continue

    chunk_name = f"chunk_{idx:03d}_L{start+1}-L{end}.js"
    with open(f"{outdir}/{chunk_name}", 'w') as f:
        f.write(f"// Chunk {idx}: lines {start+1}-{end} of app_beautified.js\n")
        f.writelines(chunk_lines)

    # Extract hints for the AI (string literals, error messages, API URLs)
    strings = re.findall(r'"([^"]{10,80})"', content)
    errors = [s for s in strings if 'error' in s.lower() or 'fail' in s.lower() or 'invalid' in s.lower()]
    urls = [s for s in strings if '/' in s and ('http' in s or 'api' in s or 'oauth' in s)]
    keywords = [s for s in strings if any(k in s.lower() for k in ['config', 'init', 'handler', 'route', 'service', 'model', 'auth', 'server', 'client'])]

    chunks_meta.append({
        'file': chunk_name,
        'start_line': start + 1,
        'end_line': end,
        'lines': end - start,
        'chars': len(content),
        'hint_errors': errors[:5],
        'hint_urls': urls[:5],
        'hint_keywords': keywords[:5],
    })

# Write chunk index
with open(f"{outdir}/index.json", 'w') as f:
    json.dump({'total_lines': total, 'chunks': chunks_meta}, f, indent=2)

print(f"  Total lines: {total:,}")
print(f"  Chunks: {len(chunks_meta)}")
print(f"  Avg chunk: {total // max(len(chunks_meta),1)} lines")
for c in chunks_meta[:5]:
    hints = c['hint_keywords'][:2] or c['hint_errors'][:2] or c['hint_urls'][:1]
    hint_str = ', '.join(hints[:2]) if hints else '(no hints)'
    print(f"    {c['file']}: {c['lines']} lines — {hint_str}")
if len(chunks_meta) > 5:
    print(f"    ... +{len(chunks_meta)-5} more chunks")
CHUNK_PY
        echo ""
    fi

    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  MODE: BUNDLED APP — extracting embedded $BUNDLED_LANGUAGE source  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "The application logic is embedded $BUNDLED_LANGUAGE (format: $BUNDLED_FORMAT)."
    echo "Ghidra decompilation is not needed for app logic extraction."
    echo ""

    # Set analysis mode for the main loop dispatch
    ANALYSIS_MODE="bundled_app"

    gen_bundled_app_plan_prompt() {
        # Determine file extension for the target source files
        local src_ext=".js"
        case "$BUNDLED_LANGUAGE" in
            python) src_ext=".py" ;;
            javascript) src_ext=".js" ;;
            typescript) src_ext=".ts" ;;
            *) src_ext=".txt" ;;
        esac

        cat <<BUNDLED_PLAN_EOF
You are a source code analyst. A bundled application binary has been detected and extracted.

## Binary info
- Format: $BUNDLED_FORMAT
- Embedded language: $BUNDLED_LANGUAGE
- Binary path: \`$BINARY_PATH\`

## Data
- \`output/bundled_app/app_info.json\` — app metadata (format, version, etc.)
- \`output/bundled_app/chunks/\` — extracted source split into ~400-line chunks (if extraction succeeded)
- \`output/bundled_app/\` — raw extracted files (app_bundle*, etc.)
- Chunk filenames follow the pattern: \`chunk_NNN_LSTART-LEND${src_ext}\`

## Job
1. Read \`output/bundled_app/app_info.json\`
2. Run \`ls output/bundled_app/\` and \`ls output/bundled_app/chunks/ 2>/dev/null\` to see what was extracted
3. If chunks exist, sample at intervals (chunk_000, chunk_050, chunk_100, etc.) — read first 30 lines of each
4. If no chunks exist, read the raw extracted files to understand the embedded code
5. Group the code into 15-25 modules by purpose, create \`output/analysis_plan.json\`:
   \`\`\`json
   { "binaryTarget": "$BINARY_PATH", "analysisMode": "bundled_app", "bundledFormat": "$BUNDLED_FORMAT", "cycle": 1,
     "userStories": [{ "id": "US-001", "title": "Module name",
       "chunkRange": { "start": 0, "end": 24 },
       "targetSourceFile": "output/src/module_name${src_ext}",
       "priority": 1, "passes": false }] }
   \`\`\`

   IMPORTANT: Use \`chunkRange\` with numeric start/end indices (NOT glob patterns).
   The build agent will expand \`{"start": 0, "end": 24}\` to read chunk_000 through chunk_024.

6. Write \`output/progress.txt\` with app overview

Keep analysis_plan.json under 30KB. 15-25 tasks max. Group adjacent chunks into modules.

When done: <promise>PLAN_COMPLETE</promise>
BUNDLED_PLAN_EOF
    }

    gen_bundled_app_build_prompt() {
        cat <<BUNDLED_BUILD_EOF
You are a source code deobfuscator and reconstructor. Read extracted and chunked source code from a bundled application binary and rewrite it into clean, readable modules.

## Binary info
- Format: $BUNDLED_FORMAT
- Embedded language: $BUNDLED_LANGUAGE

## Context
1. \`output/analysis_plan.json\` — task list with \`chunkRange\` per task
2. \`output/progress.txt\` — previous findings and name mappings

## How to resolve chunk files
Each task has a \`chunkRange\` field like \`{"start": 0, "end": 24}\`.
To find the actual files, run:
\`\`\`
ls output/bundled_app/chunks/ | sort | head -30
\`\`\`
Then filter for your range:
\`\`\`
ls output/bundled_app/chunks/ | grep -E '^chunk_0(0[0-9]|1[0-9]|2[0-4])_' | head
\`\`\`

## Job
1. Pick the first task in \`output/analysis_plan.json\` where \`passes\` is \`false\`
2. Resolve the chunk files from its \`chunkRange\` (see above)
3. Read the chunk files for this task
4. Rewrite the code into a clean, readable module:
   - Rename ALL mangled/obfuscated identifiers to meaningful names at their DECLARATION site
   - Every reference to a renamed symbol must also be updated consistently
   - Use string literals, error messages, property names, URLs, and call-site context as naming clues
   - Apply language-specific deobfuscation (e.g., for JS: \`!0\` → \`true\`, \`!1\` → \`false\`, \`void 0\` → \`undefined\`)
   - Add brief comments only for non-obvious logic
   - Preserve all logic exactly — do NOT change behavior
   - Output valid, idiomatic $BUNDLED_LANGUAGE code
5. Write to the task's \`targetSourceFile\` path (\`mkdir -p output/src\` first)
6. Append discovered name mappings to \`output/progress.txt\`
7. Update \`output/analysis_plan.json\`: set this task's \`passes\` to \`true\`

ONE task per iteration. When ALL tasks have \`passes: true\`, output: <promise>CYCLE_DONE</promise>
BUNDLED_BUILD_EOF
    }

    # (gen_restructure_prompt and gen_wiring_prompt are defined after the fi block
    #  so they are available for ALL binary types, not just bundled apps)

    _placeholder_restructure_removed=1  # functions moved below fi

gen_restructure_prompt() {
    cat <<'RESTRUCTURE_EOF'
You are a software project architect. Read deobfuscated flat source files and rewrite them into a clean, human-manageable, RE-EXECUTABLE project.

## Input (READ-ONLY — do NOT modify these)
- `output/src/` — flat deobfuscated source files (some are 2000-4000+ LOC)
- `output/progress.txt` — name mappings and subsystem notes

## Output directory
- `output/src-structured/` — write ALL output here (`mkdir -p` first)
- NEVER modify anything in `output/src/`

## Step 0: Detect language and ecosystem (first iteration only)
Before processing any files, inspect `output/src/` to determine:
- **Language**: file extensions, syntax patterns (JS/TS? Go? Rust? C++? Python? Zig?)
- **Module system**: ESM import/export? CommonJS require? Go packages? Rust mod/use? Python import?
- **Runtime**: Node/Bun/Deno? Go binary? Rust binary? CPython?
- **External dependencies**: library imports that are not local modules

Write your findings to `output/src-structured/PROJECT_META.json`:
```json
{
  "language": "<detected language: javascript, python, go, rust, c, cpp, zig, etc.>",
  "moduleSystem": "<detected module system: esm, commonjs, go_packages, rust_mod, python_import, c_include, etc.>",
  "runtime": "<detected runtime: node, bun, deno, cpython, go, rustc, gcc, zig, etc.>",
  "fileExtension": "<.js, .py, .go, .rs, .c, .cpp, .zig, etc.>",
  "syntaxCheckCommand": "<language-appropriate: node --check, python -m py_compile, go vet, rustc --edition 2021, zig ast-check, gcc -fsyntax-only, etc.>",
  "buildTool": "<npm, pip, go, cargo, make, zig, cmake, etc.>",
  "manifestFile": "<package.json, pyproject.toml, go.mod, Cargo.toml, CMakeLists.txt, build.zig, etc.>",
  "externalDependencies": {
    "<dependency_name>": { "hint": "<version_range>", "evidence": "<why this version>" }
  }
}
```

### Version hints for external dependencies
Exact versions are lost during bundling, but you can infer version RANGES from API usage. For each external dependency, record:
- `hint`: a semver range like `>=4.0.0` or `^3.22.0`
- `evidence`: WHY you think this version — which API, class, function, or pattern you saw that narrows it down

Sources of version evidence (check in order):
1. **Embedded version strings**: grep the source for patterns like `version = "1.2.3"`, `VERSION`, `USER_AGENT` containing semver
2. **API surface**: newer APIs narrow the minimum version (e.g. `z.pipe()` → zod >=3.22, `createRoot` → react >=18)
3. **Import paths**: deep imports like `@aws-sdk/client-bedrock-runtime` indicate SDK v3+
4. **String literals**: error messages, user-agent strings, changelog references
5. **Registry lookup by build date**: if no direct evidence is found, determine the binary's build date (from embedded timestamps, version strings, file metadata, etc.) and query the appropriate package registry to find the latest version available at that build date. Record the build date in PROJECT_META.json as `"buildDate"` so this only needs to be determined once.

Update `externalDependencies` in PROJECT_META.json incrementally as you process each source file — new imports may appear in later files that refine earlier guesses.

Use this metadata to drive ALL subsequent decisions (syntax checking, manifest generation, directory conventions, import style). Do NOT hardcode any language-specific assumptions.

## Ultimate Goal
The end state is a project that can be **fully re-executed** — not just readable, but runnable. This means:
1. Clean module boundaries organized by domain
2. Correct dependency wiring (imports/includes resolve, external deps identified)
3. A valid build manifest (package.json, go.mod, Cargo.toml, etc. — whatever fits the detected language)
4. A clear entrypoint so the appropriate runtime can launch the app
5. A human-readable `README.md` that documents the architecture

Think "what would a senior dev need to clone this repo, install deps, and run it?"

## Job

### Phase 1: Analyze ONE source file
1. Read the first source file from `output/src/` that has NOT yet been processed
   - Check `output/restructure_progress.json` to see which files are done (create it if missing)
2. Identify every distinct responsibility/concern in that file
3. Plan how to split it into 200-500 LOC modules

### Phase 2: Split and write
1. For each identified concern, write a focused module to the appropriate domain directory under `output/src-structured/`
2. Each output file must:
   - Have a clear, descriptive filename (kebab-case for JS/TS, snake_case for Go/Rust/Python — match language convention)
   - Contain only ONE logical concern
   - Be 200-500 LOC (hard max 800)
   - Have correct relative imports/includes to other files already in `output/src-structured/`
3. Run the language-appropriate syntax check (from PROJECT_META.json) on every file you write

### Phase 3: Update README.md
After each source file is processed, update `output/src-structured/README.md` with accumulated knowledge:
- **Architecture overview**: what the app does, how modules connect
- **Domain directory guide**: what each directory contains and its role
- **Key modules**: the most important files and what they do
- **External dependencies**: what libraries are used and why
- **Entrypoint & boot sequence**: how the app starts up
- **Build & run instructions**: exact commands to build and execute
- **Notes for contributors**: gotchas, patterns, naming conventions found during decompilation

This README is a living knowledge document — add to it incrementally as you process each file. It should help a human understand the codebase without reading every file.

### Phase 4: Track progress
Update `output/restructure_progress.json`:
```json
{
  "completed": ["source_file_a", ...],
  "remaining": ["source_file_b", ...],
  "outputFiles": 42,
  "totalLOC": 12345
}
```

### Phase 5: Finalize (when all source files are done)
After the last source file is processed:
1. Generate the appropriate build manifest for the detected language:
   - JS/TS: `package.json` with dependencies, `"type": "module"` if ESM, entrypoint, scripts
   - Go: `go.mod` with module path and dependencies
   - Rust: `Cargo.toml` with dependencies and binary target
   - Python: `pyproject.toml` or `requirements.txt`
   - C/C++: `CMakeLists.txt` or `Makefile`
   - Other: whatever is idiomatic for the language
2. Finalize `README.md` with complete architecture and build/run instructions
3. Verify: syntax check all files, imports/includes resolve correctly

### Domain directories
Classify code by its FUNCTIONAL DOMAIN — what it actually does — NOT by the source filename. Source filenames are artifacts of bundling/deobfuscation and have no architectural meaning.

Create directories based on the code's actual domain structure. Common patterns:
`core/`, `api/`, `auth/`, `cli/`, `config/`, `tools/`, `ui/`, `plugins/`, `providers/`, `security/`, `telemetry/`, `remote/`, `validation/`, `parsers/`, `sessions/`, `net/`, `storage/`

Use whatever makes sense for the specific codebase — these are suggestions, not requirements.

### Rules
- NEVER modify `output/src/`
- ONE source file per iteration — do NOT try to process all files at once
- Split by responsibility: keep related classes/functions/types together if they share state or form a cohesive unit
- Preserve ALL exports/public symbols — every export from the source must appear in some output file
- Use the language-idiomatic import/include mechanism between output files
- Do NOT create barrel/index files — direct imports only
- Resolve cross-references from the flat source to correct paths in `output/src-structured/`

Process ONE source file, then output <promise>RESTRUCTURE_PROGRESS</promise>
When ALL files are done, output <promise>RESTRUCTURE_DONE</promise>
RESTRUCTURE_EOF
    }

gen_wiring_prompt() {
    cat <<'WIRING_EOF'
You are a software engineer wiring up a restructured codebase so it can actually execute end-to-end.

## Context
- `output/src-structured/` contains a fully modularized codebase produced by a prior restructuring phase
- `output/src-structured/PROJECT_META.json` describes the language, runtime, and dependencies
- `output/src-structured/README.md` documents the architecture
- `output/src-structured/package.json` (or equivalent manifest) exists but the app cannot yet run
- The code was decompiled from a compiled binary — all logic is present but the **top-level execution glue** (the main() entrypoint that ties modules together) was lost during decompilation

## Goal
Create a working entrypoint so the app boots and runs. This is an iterative process:
1. Analyze → 2. Write entrypoint → 3. Run → 4. Fix errors → repeat until it works

## Job

### Step 1: Analyze the boot sequence
- Read `PROJECT_META.json` for runtime/language info
- Read `README.md` for architecture overview and boot sequence docs
- Find the current `main` field in the manifest (package.json etc.)
- Trace the startup exports: look for functions/constants named like `main`, `start`, `init`, `bootstrap`, `entrypoint`, `CLI_STARTUP_SEQUENCE`, `HANDLER_EXPORTS`, `MAIN_ENTRY_FAST_PATHS` etc.
- Map the call graph: which exported functions call which, in what order
- Identify the dispatch logic: how does the app decide what mode to run (CLI, server, SDK, etc.)

### Step 2: Write the entrypoint
Create the appropriate entrypoint file (e.g., `main.js`, `main.py`, `main.go`, `main.rs` — based on PROJECT_META.json language) that:
1. Imports the necessary modules from the structured codebase
2. Executes the startup sequence in the correct order
3. Handles command-line arguments and environment variables
4. Dispatches to the correct handler based on entrypoint determination
5. Has proper error handling and graceful shutdown

The entrypoint should be minimal glue code — it should CALL the existing functions, not duplicate logic.

### Step 3: Test execution
Run the entrypoint using the runtime from PROJECT_META.json and capture the output:
```bash
# Use the syntaxCheckCommand / runtime from PROJECT_META.json, e.g.:
<runtime> output/src-structured/<entrypoint> --version 2>&1
```
Start with the simplest possible invocation (--version, --help) before trying full execution.

### Step 4: Fix and iterate
If execution fails:
1. Read the error message carefully
2. Identify the root cause (missing import, wrong call order, missing runtime dependency, etc.)
3. Fix the entrypoint OR fix the underlying module if needed
4. Re-run and test again

Common issues to watch for:
- Circular imports — reorder or lazy-import
- Missing runtime-specific APIs — polyfill or stub as needed
- Runtime-only state that needs initialization before use
- Modules that expect to run in a specific order

### Step 5: Update manifest and docs
Once execution works:
1. Update the build manifest (package.json, Cargo.toml, go.mod, etc.) to point to the new entrypoint
2. Update `README.md` with exact build & run instructions
3. Update `PROJECT_META.json` if you discovered new dependencies or runtime requirements

## Rules
- Do NOT rewrite existing modules — only create glue code and fix import issues
- Prefer minimal changes — the restructured code is the source of truth
- Test incrementally: --version first, then --help, then basic execution
- Log what you try and what errors you hit so progress is visible
- If a module needs a small fix (wrong export, missing re-export), fix it in place

Output <promise>WIRING_PROGRESS</promise> after each fix-and-test cycle.
Output <promise>WIRING_DONE</promise> when the app executes successfully.
WIRING_EOF
    }

    # Skip straight to main loop with bundled_app mode
    # (Ghidra, discovery, mapping, composition all skipped)

else
    echo ">>> Standard native binary. Proceeding with Ghidra pipeline."
    echo ""
fi

# ─── Define restructure & wiring prompts (available for ALL binary types) ─────

# ─── Phase 0: Ghidra pre-analysis (run once, skip if bundled app) ─────────────

if [ -z "$BUNDLED_FORMAT" ]; then

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

# ─── Phase 0.75: Composition analysis (when framework source is known) ───────

if [ "$HAS_FUNCTION_MAP" = true ]; then
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  COMPOSITION ANALYSIS                                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""

    if [ ! -f "output/composition/analysis.json" ]; then
        analyze_composition 2>&1 | tee -a "$RECORD_FILE"
    else
        echo "Composition analysis cached."
        python3 -c "
import json
d = json.load(open('output/composition/analysis.json'))
c = d['categories']
print(f\"Framework:        {c['framework']['count']:,} ({c['framework']['pct']}%)\")
fp = c.get('framework_propagated', c.get('third_party', {}))
print(f\"Propagated:       {fp.get('count',0):,} ({fp.get('pct',0)}%)\")
print(f\"Compiler/system:  {c['compiler_system']['count']:,} ({c['compiler_system']['pct']}%)\")
unk = c.get('unknown', c.get('custom_unknown', {}))
print(f\"Unknown:          {unk.get('count',0):,} ({unk.get('pct',0)}%)\")
print(f\"Recommended mode: {d['mode']}\")
" 2>/dev/null
    fi

    # Auto-select mode based on composition
    if [ -f "output/composition/analysis.json" ]; then
        ANALYSIS_MODE=$(python3 -c "import json; print(json.load(open('output/composition/analysis.json')).get('mode', 'full_reconstruction'))" 2>/dev/null)
        if [ "$ANALYSIS_MODE" = "custom_extraction" ]; then
            echo ""
            echo ">>> Mode: CUSTOM EXTRACTION — focusing on unique application logic"
        else
            echo ""
            echo ">>> Mode: FULL RECONSTRUCTION — framework coverage too low for extraction"
        fi
    fi

    echo ""
fi

fi  # end native binary path (Ghidra + discovery + mapping + composition)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP: Plan → Build → Verify → Re-plan if needed
# ═══════════════════════════════════════════════════════════════════════════════

# Handle resume: if plan exists with all tasks done, skip straight to verify+coverage
if [ -f "$PLAN" ] && ! python3 -c "import json,sys; d=json.load(open('$PLAN')); sys.exit(0 if any(not s['passes'] for s in d['userStories']) else 1)" 2>/dev/null; then
    echo "Existing plan found with all tasks complete. Checking coverage..."
    CYCLE=$((CYCLE + 1))
    BUILD_ERRORS=""
    if verify_build; then
        measure_coverage
        if [ "$COVERAGE_PCT" -ge "$TARGET_COVERAGE" ]; then
            echo "Coverage target already met ($COVERAGE_PCT%)."

            # ── RESTRUCTURE phase (resume path) ───────────────────────────
            if type gen_restructure_prompt &>/dev/null; then
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Phase:  RESTRUCTURE"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""

                RESTRUCTURE_PROMPT=$(gen_restructure_prompt)
                RECORD_FILE="$RECORDS_DIR/$(date '+%Y-%m-%d-%H%M%S')-restructure-$TOOL.jsonl"
                RSTEP=0

                while true; do
                    RSTEP=$((RSTEP + 1))
                    echo "======================== RESTRUCTURE step $RSTEP ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"
                    RESULT=$(spawn_agent "$RESTRUCTURE_PROMPT" 2>&1)
                    echo "$RESULT" | tee -a "$RECORD_FILE"

                    if grep -q "RESTRUCTURE_DONE" <<< "$RESULT"; then
                        echo ""
                        echo "╔══════════════════════════════════════════════════════════════╗"
                        echo "║  RESTRUCTURE COMPLETE — Project organized!                 ║"
                        echo "╚══════════════════════════════════════════════════════════════╝"
                        break
                    elif grep -q "RESTRUCTURE_PROGRESS" <<< "$RESULT"; then
                        echo "... step $RSTEP done, continuing..."
                        continue
                    else
                        echo ""
                        echo "⚠ Restructure step $RSTEP did not signal progress. Retrying..."
                        continue
                    fi
                done
            fi

            # ── WIRING phase (resume path) ────────────────────────────────
            if type gen_wiring_prompt &>/dev/null; then
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Phase:  WIRING"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""

                WIRING_PROMPT=$(gen_wiring_prompt)
                RECORD_FILE="$RECORDS_DIR/$(date '+%Y-%m-%d-%H%M%S')-wiring-$TOOL.jsonl"
                WSTEP=0

                while true; do
                    WSTEP=$((WSTEP + 1))
                    echo "======================== WIRING step $WSTEP ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"
                    RESULT=$(spawn_agent "$WIRING_PROMPT" 2>&1)
                    echo "$RESULT" | tee -a "$RECORD_FILE"

                    if grep -q "WIRING_DONE" <<< "$RESULT"; then
                        echo ""
                        echo "╔══════════════════════════════════════════════════════════════╗"
                        echo "║  WIRING COMPLETE — App is executable!                      ║"
                        echo "╚══════════════════════════════════════════════════════════════╝"
                        break
                    elif grep -q "WIRING_PROGRESS" <<< "$RESULT"; then
                        echo "... wiring step $WSTEP done, continuing..."
                        continue
                    else
                        echo ""
                        echo "⚠ Wiring step $WSTEP did not signal progress. Retrying..."
                        continue
                    fi
                done
            fi

            exit 0
        fi
        echo "Coverage: $COVERAGE_PCT% (target: $TARGET_COVERAGE%). Expanding..."
        BUILD_ERRORS="COVERAGE: Only $COVERAGE_PCT% of functions lifted ($COVERAGE_FUNCS/$COVERAGE_TOTAL). Need $TARGET_COVERAGE%. Already completed files: $(ls output/src/ 2>/dev/null | tr '\n' ', ')"
        cp "$PLAN" "output/records/plan_cycle_${CYCLE}.json" 2>/dev/null
        rm -f "$PLAN"
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

    if [ ! -f "$PLAN" ] || ! python3 -c "import json,sys; d=json.load(open('$PLAN')); sys.exit(0 if any(not s['passes'] for s in d['userStories']) else 1)" 2>/dev/null; then

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Phase:  PLAN (cycle $CYCLE)"
        echo "Target: $BINARY_PATH"
        echo "Tool:   $TOOL"
        echo "Mode:   $ANALYSIS_MODE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        if [ "$ANALYSIS_MODE" = "bundled_app" ]; then
            echo "(Bundled app [$BUNDLED_FORMAT] — extracting and deobfuscating $BUNDLED_LANGUAGE code)"
            PLAN_PROMPT=$(gen_bundled_app_plan_prompt)
        elif [ "$ANALYSIS_MODE" = "custom_extraction" ]; then
            echo "(Custom extraction mode — focusing on unique application logic)"
            PLAN_PROMPT=$(gen_custom_plan_prompt "$CYCLE" "$BUILD_ERRORS")
        elif [ ! -f "$PLAN" ] && [ -d "output/src" ] && find output/src -name '*.zig' -o -name '*.cpp' -o -name '*.c' 2>/dev/null | grep -q .; then
            echo "(Expanding coverage — planning next batch)"
            PLAN_PROMPT=$(gen_replan_prompt "$CYCLE" "$BUILD_ERRORS")
        else
            PLAN_PROMPT=$(gen_plan_prompt)
        fi

        echo "======================== PLAN CYCLE $CYCLE ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"

        OUTPUT=$(spawn_agent "$PLAN_PROMPT")
        echo "$OUTPUT" | tee -a "$RECORD_FILE"

        # Recover misplaced files
        [ ! -f "$PLAN" ] && [ -f "analysis_plan.json" ] && mv analysis_plan.json "$PLAN"
        [ ! -f "$PLAN" ] && [ -f "prd.json" ] && mv prd.json "$PLAN"
        [ ! -f "$PROGRESS" ] && [ -f "progress.txt" ] && mv progress.txt "$PROGRESS"

        if [ ! -f "$PLAN" ]; then
            echo "Error: Plan phase did not generate $PLAN"
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

    if [ "$ANALYSIS_MODE" = "bundled_app" ]; then
        BUILD_PROMPT=$(gen_bundled_app_build_prompt)
    elif [ "$ANALYSIS_MODE" = "custom_extraction" ]; then
        BUILD_PROMPT=$(gen_custom_build_prompt)
    else
        BUILD_PROMPT=$(gen_build_prompt)
    fi

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
        if grep -qi 'rate.limit\|429\|too many requests\|overloaded' <<< "$OUTPUT"; then
            echo "Rate limit. Waiting 60s..."
            sleep 60
            ITERATION=$((ITERATION - 1))
            continue
        fi

        # Auto-mark completed tasks (agent may fail to update the plan JSON)
        if [ -f "$PLAN" ]; then
            python3 -c "
import json, os
plan = json.load(open('$PLAN'))
changed = False
for story in plan.get('userStories', []):
    target = story.get('targetSourceFile', '')
    if not story.get('passes') and target and os.path.isfile(target) and os.path.getsize(target) > 100:
        story['passes'] = True
        changed = True
if changed:
    with open('$PLAN', 'w') as f:
        json.dump(plan, f, indent=2)
" 2>/dev/null
        fi

        # Check if all current plan tasks are done
        if python3 -c "import json,sys; d=json.load(open('$PLAN')); sys.exit(0 if all(s.get('passes') for s in d['userStories']) else 1)" 2>/dev/null; then
            echo "All plan tasks complete for cycle $CYCLE."
            break
        fi
        if tail -30 <<< "$OUTPUT" | grep -q '<promise>CYCLE_DONE</promise>'; then
            echo "All plan tasks complete for cycle $CYCLE."
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
            echo "║  SUCCESS — Coverage target reached!                        ║"
            echo "╠══════════════════════════════════════════════════════════════╣"
            echo "║  Functions: $COVERAGE_FUNCS/$COVERAGE_TOTAL ($COVERAGE_PCT%)"
            echo "║  Source:    $COVERAGE_FILES files, $COVERAGE_LOC LOC"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo ""

            # ── RESTRUCTURE phase ──────────────────────────────────────────
            if type gen_restructure_prompt &>/dev/null; then
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Phase:  RESTRUCTURE"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""

                RESTRUCTURE_PROMPT=$(gen_restructure_prompt)
                RSTEP=0

                while true; do
                    RSTEP=$((RSTEP + 1))
                    echo "======================== RESTRUCTURE step $RSTEP ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"
                    RESULT=$(spawn_agent "$RESTRUCTURE_PROMPT" 2>&1)
                    echo "$RESULT" | tee -a "$RECORD_FILE"

                    if grep -q "RESTRUCTURE_DONE" <<< "$RESULT"; then
                        echo ""
                        echo "╔══════════════════════════════════════════════════════════════╗"
                        echo "║  RESTRUCTURE COMPLETE — Project organized!                 ║"
                        echo "╚══════════════════════════════════════════════════════════════╝"
                        break
                    elif grep -q "RESTRUCTURE_PROGRESS" <<< "$RESULT"; then
                        echo "... step $RSTEP done, continuing..."
                        continue
                    else
                        echo ""
                        echo "⚠ Restructure step $RSTEP did not signal progress. Retrying..."
                        continue
                    fi
                done
            fi

            # ── WIRING phase (main loop path) ─────────────────────────────
            if type gen_wiring_prompt &>/dev/null; then
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "Phase:  WIRING"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""

                WIRING_PROMPT=$(gen_wiring_prompt)
                RECORD_FILE="$RECORDS_DIR/$(date '+%Y-%m-%d-%H%M%S')-wiring-$TOOL.jsonl"
                WSTEP=0

                while true; do
                    WSTEP=$((WSTEP + 1))
                    echo "======================== WIRING step $WSTEP ($(date '+%Y-%m-%d %H:%M:%S')) ========================" | tee -a "$RECORD_FILE"
                    RESULT=$(spawn_agent "$WIRING_PROMPT" 2>&1)
                    echo "$RESULT" | tee -a "$RECORD_FILE"

                    if grep -q "WIRING_DONE" <<< "$RESULT"; then
                        echo ""
                        echo "╔══════════════════════════════════════════════════════════════╗"
                        echo "║  WIRING COMPLETE — App is executable!                      ║"
                        echo "╚══════════════════════════════════════════════════════════════╝"
                        break
                    elif grep -q "WIRING_PROGRESS" <<< "$RESULT"; then
                        echo "... wiring step $WSTEP done, continuing..."
                        continue
                    else
                        echo ""
                        echo "⚠ Wiring step $WSTEP did not signal progress. Retrying..."
                        continue
                    fi
                done
            fi

            echo ""
            echo "Record saved: $RECORD_FILE"
            exit 0
        fi

        echo ""
        echo "Verification passed but coverage is $COVERAGE_PCT% (target: $TARGET_COVERAGE%)."
        echo "Archiving plan and planning next batch..."
        BUILD_ERRORS="COVERAGE: Only $COVERAGE_PCT% of functions lifted ($COVERAGE_FUNCS/$COVERAGE_TOTAL). Need $TARGET_COVERAGE%. Already completed files: $(ls output/src/ 2>/dev/null | tr '\n' ', ')"

        # Archive current plan and force re-plan for next batch
        cp "$PLAN" "output/records/plan_cycle_${CYCLE}.json" 2>/dev/null
        rm -f "$PLAN"
    fi

    echo ""
    echo "Starting cycle $((CYCLE + 1))..."
    echo ""
done
