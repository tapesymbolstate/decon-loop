# Decon Loop

Built with [looprinter](https://github.com/tapesymbolstate/looprinter).

> **decon** — short for *deconstruction*. This tool deconstructs compiled binaries back into readable, buildable source code.

Autonomous binary decompilation pipeline that reconstructs buildable source code from compiled binaries. Uses AI agents (Claude or OpenAI Codex) in an iterative loop to plan, lift, and verify decompiled source until it compiles cleanly.

## How It Works

```
Binary ──► Ghidra Analysis ──► Source Discovery ──► Function Mapping ──► AI Loop
                                                                          │
                                                            ┌─────────────┤
                                                            ▼             │
                                                          Plan ──► Build ──► Verify
                                                            ▲                  │
                                                            └──── Re-plan ◄────┘
                                                                (if fails)
```

1. **Ghidra Pre-Analysis** — Extracts function boundaries, call graph, and decompiled pseudocode
2. **Source Discovery** — Identifies the binary (name, version, repo) and clones reference source if open-source
3. **Function Mapping** — Maps Ghidra functions to original source locations via symbol matching, string anchoring, and call graph propagation
4. **Composition Analysis** — Categorizes functions (framework / third-party / compiler / custom) and auto-selects reconstruction mode
5. **AI Loop** — An AI agent iteratively plans tasks, lifts functions into clean source, and verifies compilation

## Prerequisites

- **Ghidra** (headless) — `brew install ghidra`
- **Python 3** — for discovery/mapping scripts
- **clang** / **zig** — for compilation verification
- One of:
  - **Claude CLI** — `npm install -g @anthropic-ai/claude-code`
  - **Codex CLI** — [OpenAI Codex CLI](https://github.com/openai/codex)

## Quick Start

```bash
# Place your target binary
cp /path/to/binary target-binaries/my-binary

# Run with Claude (default)
./loop_decon.sh target-binaries/my-binary

# Run with Codex (gpt-5.4)
./loop_decon.sh target-binaries/my-binary codex

# Run with Codex Spark (gpt-5.3-codex-spark, optimized for fast iteration)
./loop_decon.sh target-binaries/my-binary codex-spark

# Limit to 50 iterations
./loop_decon.sh target-binaries/my-binary codex 50
```

## Usage

### Main Loop

```
./loop_decon.sh <binary_path> [engine] [max_iterations]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `binary_path` | Path to the target binary | (required) |
| `engine` | `claude`, `codex`, or `codex-spark` | `claude` |
| `max_iterations` | Max build iterations (0 = unlimited) | `0` |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `CODEX_MODEL` | Override Codex model name | `gpt-5.4` |
| `CLAUDE_EFFORT` | Claude reasoning effort | `max` |
| `TARGET_COVERAGE` | Function coverage % target | `100` |

### Engine Comparison

| Engine | Model | Best For |
|--------|-------|----------|
| `claude` | Claude Opus | Highest quality lifting, complex binaries |
| `codex` | GPT-5.4 | Strong general-purpose decompilation |
| `codex-spark` | GPT-5.3-Codex-Spark | Fast iteration, real-time speed |

### Ghidra Analysis (standalone)

```
./ghidra_analyze.sh <binary_path> [mode]
```

| Mode | Description | Time |
|------|-------------|------|
| `quick` | Function boundaries + call graph only | ~5-10 min |
| `full` | Full decompilation of all functions (parallel) | ~10-20 min |
| `combined` | Single pass: quick + full (fastest) | ~15-25 min |

### Source Discovery (standalone)

```bash
python3 discover_source.py <binary_path> [--clone] [--output-dir output/discovery]
```

Identifies the binary and optionally clones the reference source to `reference-src/`.

Output: `output/discovery/identity.json`

### Function Mapping (standalone)

```bash
python3 map_to_source.py <binary_path> [--reference-dir reference-src/<name>]
```

Maps Ghidra functions to original source locations. Requires Ghidra analysis and source discovery to have run first.

Output: `output/mapping/function_map.tsv`, `helper_aliases.tsv`, `stats.json`

## Analysis Modes

The pipeline auto-selects a mode based on composition analysis:

| Mode | Trigger | Strategy |
|------|---------|----------|
| **Full Reconstruction** | <10% framework mapping | Lift everything from Ghidra pseudocode |
| **Custom Extraction** | >10% framework mapping | Skip known framework code, focus on custom application logic |

In custom extraction mode, the AI agent triages unknown function clusters into:
- **custom** — application-specific logic (reconstructed)
- **third_party** — recognized libraries like boringssl, zlib (skipped)
- **runtime_generated** — compiler/VM dispatch tables (skipped)

## Output Structure

```
output/
├── ghidra/              # Ghidra analysis data
│   ├── function_boundaries.tsv
│   ├── call_graph.tsv
│   ├── all_decompiled.c
│   ├── module_chunks.tsv
│   └── functions/       # Per-function decompilations by address prefix
├── discovery/           # Binary identity (identity.json)
├── mapping/             # Function-to-source mappings
│   ├── function_map.tsv
│   ├── helper_aliases.tsv
│   └── stats.json
├── composition/         # Binary composition breakdown (analysis.json)
├── records/             # Per-run execution logs and archived PRDs
├── prd.json             # Current task list (auto-generated)
├── progress.txt         # Cumulative findings log
└── src/                 # Reconstructed source code

reference-src/           # Cloned original source (gitignored)
target-binaries/         # Input binaries (never modified)
ghidra-scripts/          # Custom Ghidra headless scripts
```

## Verification Gates

Every cycle checks 4 quality gates before advancing:

1. **Source exists** — files present in `output/src/`
2. **Quantity** — at least 500 LOC across 5+ files
3. **Quality** — at least 25% logic density and 10+ function definitions
4. **Compilation** — `clang++ -c` or `zig ast-check` passes cleanly

## Resuming

The loop is fully resumable. If interrupted, simply re-run the same command — cached Ghidra data, mappings, and completed source files are preserved. The loop picks up from the next incomplete task in the PRD.

## Background Execution

```bash
# Run in background with log output
nohup ./loop_decon.sh target-binaries/my-binary codex-spark > /tmp/decon-loop-output.log 2>&1 &

# Monitor progress
tail -f /tmp/decon-loop-output.log
```
