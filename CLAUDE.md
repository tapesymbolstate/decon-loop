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

The loop repeats **Plan → Build → Verify** until source compiles:

### Phase 1: Plan
- Cycle 1: Inspect binary, generate initial PRD (recon → analysis → reconstruction)
- Cycle 2+: Read build errors from verify phase, generate deeper PRD targeting compilation gaps

### Phase 2: Build
- Iterate through PRD tasks one at a time
- Each task must produce or improve source files in `output/src/`
- Attempt compilation after each source change
- When all PRD tasks pass → `<promise>CYCLE_DONE</promise>`

### Phase 3: Verify
- Attempt full compilation of `output/src/`
- If compilation succeeds → **mission complete**
- If compilation fails → archive current PRD, feed errors to re-plan, start next cycle

### Completion criteria
Source code in `output/src/` compiles with `clang++`/`swiftc` targeting the original architecture. Not "all PRD tasks done" — **actual compilation success.**

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

The reconstructed source in `output/src/` must be compilable. Each iteration that produces source code should:
1. Attempt `clang` / `swiftc` compilation (matching the original target architecture)
2. Log build result (success/failure + errors) in progress.txt
3. Only mark the prd.json task as passing if compilation succeeds
