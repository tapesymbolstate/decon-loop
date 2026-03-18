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

## Two-Phase Workflow

### Phase 1: Plan (auto-generates prd.json)
When `prd.json` does not exist, the agent runs in plan mode:
1. Inspect the target binary (file type, headers, symbols, strings sample)
2. Identify the binary's nature (runtime, library, app, etc.)
3. Generate `prd.json` with prioritized analysis tasks
4. Generate `progress.txt` with initial reconnaissance findings
5. Output `<promise>PLAN_COMPLETE</promise>` when done

### Phase 2: Build (executes prd.json tasks)
When `prd.json` exists, the agent runs in build mode:
1. Read `prd.json` → identify incomplete tasks
2. Read `progress.txt` → review findings from previous iterations
3. Select the highest-priority incomplete task
4. Execute the task using binary analysis tools
5. Save results to the appropriate subdirectory under `output/`
6. If deobfuscation was needed, save both raw and cleaned versions
7. Attempt to compile reconstructed source; log result
8. Update `prd.json` (set passes: true only if output compiles or task doesn't produce source)
9. Append findings, patterns, and caveats to `progress.txt`
10. If ALL tasks are complete, output `<promise>COMPLETE</promise>`

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
