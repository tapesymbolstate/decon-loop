# Decon Agent — Binary Decompilation via Ralph Loop

## Mission

Fully reconstruct buildable source code from target binaries using the Ralph Loop technique:

1. **Decompile** — Extract structure, logic, and protocols from the binary
2. **Deobfuscate** — If recovered code is obfuscated (mangled names, control flow flattening, string encryption, opaque predicates), reverse the obfuscation to produce human-readable source
3. **Rebuild** — Produce compilable source that can be built back into a functionally equivalent binary

The end goal is a complete, readable, buildable codebase — not just analysis artifacts.

## Critical Constraints

- NEVER modify original binaries in `target-binaries/`
- Perform exactly one analysis task per iteration
- Always record discovered code patterns and structural insights in progress.txt
- Save large outputs to files; only write summaries in progress.txt
- Reconstructed source MUST compile. If it doesn't compile yet, mark the task as failing in prd.json and log the build errors in progress.txt
- When deobfuscating, preserve original logic exactly — rename symbols to meaningful names but never alter behavior

## Target Binaries

All binaries to analyze are in `target-binaries/`. The loop script passes the specific target file via the prompt.

## Multi-Cycle Workflow

The loop repeats **Plan → Build → Verify** until source compiles AND passes quality gates:

### Phase 0: Ghidra Pre-Analysis (once)
- Quick: extract function boundaries + call graph → `output/ghidra/function_boundaries.tsv`, `call_graph.tsv`
- Full: decompile all functions → `output/ghidra/all_decompiled.c`, `output/ghidra/functions/`
- Pre-compute module chunks → `output/ghidra/module_chunks.tsv`

### Phase 1: Plan (function-lifting PRD)
- Cycle 1: Analyze Ghidra data, group functions into modules, create lifting tasks
- Cycle 2+: Read verification errors (compilation or quality), re-plan with targeted fixes
- Every PRD task must specify `ghidraFunctions`, `addressRange`, `targetSourceFile`
- NO analysis-only tasks — every task must produce lifted code in `output/src/`

### Phase 2: Build (lift Ghidra pseudocode → clean C/C++)
- Read Ghidra decompiled functions from `output/ghidra/functions/`
- Transform: `undefined8`→`uint64_t`, `FUN_*`→meaningful names, `param_N`→descriptive names
- Preserve all control flow exactly — no invented functionality
- Compile each module with `clang++ -c` (not `-fsyntax-only`)
- When all PRD tasks pass → `<promise>CYCLE_DONE</promise>`

### Phase 3: Verify (4 quality gates)
1. **Source exists**: files present in `output/src/`
2. **Quantity**: ≥500 LOC, ≥5 files
3. **Quality**: ≥25% logic density (if/while/for/switch), ≥10 function definitions — rejects metadata-only stubs
4. **Compilation**: `clang++ -c` succeeds (not syntax-only)

### Completion criteria
Source in `output/src/` passes ALL 4 verification gates. Not just "compiles" — must contain real lifted function implementations from Ghidra decompilation.

## Analysis Tools

Binary analysis tools to invoke via Bash:
- `otool` — Mach-O headers, load commands, symbol tables
- `nm` — Symbol listing
- `strings` — String extraction
- `xxd` / `hexdump` — Hex dumps
- `objdump` — Disassembly
- `dyldinfo` — Dynamic linker info
- `codesign` — Code signature inspection
- `class-dump` — Objective-C class structures (if installed)
- `swift-demangle` — Swift symbol demangling
- `c++filt` — C++ symbol demangling

## Output Structure

```
output/
├── headers/          # Mach-O headers, load commands
├── symbols/          # Symbol tables, exports/imports
├── strings/          # Extracted strings (categorized)
├── classes/          # Class/struct definitions
├── protocols/        # Protocols/interfaces
├── functions/        # Key function disassembly
├── diff/             # Cross-version differences
├── reports/          # Comprehensive analysis reports
├── obfuscation/      # Raw obfuscated artifacts + deobfuscation notes
└── src/              # Reconstructed buildable source code
```

## Build Verification

Each iteration that produces source code must:
1. Compile with `clang++ -c` (real compilation, not `-fsyntax-only`)
2. Log build result in progress.txt
3. Only set `passes: true` if compilation succeeds AND output contains real function implementations

The verify phase checks 4 gates: source exists → quantity thresholds → logic density → compilation.
Metadata structs describing the binary (hardcoded strings, struct literals) are rejected by the quality gate.
