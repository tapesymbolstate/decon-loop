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
- Quick: function boundaries + call graph → `output/ghidra/function_boundaries.tsv`, `call_graph.tsv`
- Full: decompile all functions → `output/ghidra/all_decompiled.c`, `output/ghidra/functions/`
- Module chunks → `output/ghidra/module_chunks.tsv`

### Phase 0.5: Source Discovery & Mapping (once, automatic)
The harness automatically tries to identify the binary and find its source:
1. **`discover_source.py`** — analyzes strings, symbols, embedded paths to identify the software
   - Outputs `output/discovery/identity.json` (name, version, repo URL, languages, confidence)
   - Maintains a known-software database (Bun, Node, Deno, Redis, nginx, etc.) but also does generic detection
   - If identified: shallow-clones the source to `reference-src/<name>/`
2. **`map_to_source.py`** — maps Ghidra functions to original source locations
   - Direct symbol matching (named functions → source function index)
   - String-anchored matching (embedded file paths, error messages → source grep)
   - Call graph propagation (known functions' callees → source callees)
   - Outputs `output/mapping/function_map.tsv`, `helper_aliases.tsv`, `stats.json`

If discovery fails (closed-source binary), the pipeline falls back to pure Ghidra lifting.

### Phase 1: Plan
- If mapping exists: group tasks by SOURCE FILE, prioritize high-confidence mappings
- If no mapping: group by address proximity + call graph clusters
- Every task: `ghidraFunctions`, `addressRange`, `targetSourceFile`, optionally `sourceFiles`
- Output file extension matches source language (.zig, .cpp, .c, .rs)

### Phase 2: Build (hybrid or pure lifting)
**Hybrid mode** (when reference source is available):
- Read Ghidra pseudocode AND original source for each mapped function
- Produce output matching the original: same language, names, types, idioms
- Unmapped functions fall back to cleaned Ghidra pseudocode

**Pure mode** (closed-source binary):
- Read Ghidra pseudocode, clean up types/names, infer meaning from context
- Output as clean C/C++

### Phase 3: Verify (4 quality gates)
1. **Source exists**: files in `output/src/`
2. **Quantity**: ≥500 LOC, ≥5 files
3. **Quality**: ≥25% logic density, ≥10 function definitions
4. **Compilation**: `clang++ -c` / `zig ast-check` succeeds

### Completion criteria
Source passes all 4 gates. Must contain real function implementations, not metadata.

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
├── ghidra/           # Ghidra pre-analysis (function_boundaries, call_graph, decompiled functions)
├── discovery/        # Binary identity detection (identity.json)
├── mapping/          # Function→source mappings (function_map.tsv, helper_aliases.tsv)
├── headers/          # Mach-O headers, load commands
├── symbols/          # Symbol tables, exports/imports
├── strings/          # Extracted strings
├── functions/        # Key function disassembly
├── reports/          # Analysis reports
├── records/          # Execution logs per run
└── src/              # Reconstructed source code (Zig, C++, C — matching original language)

reference-src/        # Cloned original source (gitignored, auto-detected)
```

## Build Verification

Each iteration that produces source code must:
1. Compile with `clang++ -c` (real compilation, not `-fsyntax-only`)
2. Log build result in progress.txt
3. Only set `passes: true` if compilation succeeds AND output contains real function implementations

The verify phase checks 4 gates: source exists → quantity thresholds → logic density → compilation.
Metadata structs describing the binary (hardcoded strings, struct literals) are rejected by the quality gate.
