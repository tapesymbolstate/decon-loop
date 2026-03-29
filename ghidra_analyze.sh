#!/bin/bash
# Ghidra headless analysis wrapper for decon-loop
#
# Usage: ./ghidra_analyze.sh <binary_path> [full|quick|combined]
#
# Modes:
#   quick    — Export function boundaries + call graph only (~5-10 min)
#   full     — Full decompilation of all functions (parallel, ~10-20 min)
#   combined — Single pass: quick + full in one import (fastest, saves ~17 min)
#
# Output goes to output/ghidra/

set -euo pipefail
cd "$(dirname "$0")"

# Ensure JAVA_HOME is set (nohup/cron don't source ~/.zshrc)
if ! java -version &>/dev/null; then
    for jdir in /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
                /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home; do
        if [ -d "$jdir" ]; then
            export JAVA_HOME="$jdir"
            export PATH="$JAVA_HOME/bin:$PATH"
            break
        fi
    done
fi

# Auto-detect Ghidra installation path
if [ -n "${GHIDRA_HEADLESS:-}" ] && [ -f "$GHIDRA_HEADLESS" ]; then
    : # Use explicitly set GHIDRA_HEADLESS
elif command -v analyzeHeadless &>/dev/null; then
    GHIDRA_HEADLESS="$(command -v analyzeHeadless)"
else
    # Search common Homebrew and system locations
    GHIDRA_HEADLESS=$(find /opt/homebrew/Cellar/ghidra /usr/local/Cellar/ghidra /Applications 2>/dev/null \
        -name "analyzeHeadless" -type f 2>/dev/null | head -1 || true)
    if [ -z "$GHIDRA_HEADLESS" ]; then
        echo "Error: Ghidra analyzeHeadless not found. Install Ghidra or set GHIDRA_HEADLESS env var."
        exit 1
    fi
fi
SCRIPTS_DIR="$(pwd)/ghidra-scripts"
PROJECT_DIR="/tmp/ghidra-projects"
OUTPUT_DIR="$(pwd)/output/ghidra"

if [ -z "${1:-}" ]; then
    echo "Usage: ./ghidra_analyze.sh <binary_path> [full|quick|combined]"
    exit 1
fi

BINARY_PATH="$(realpath "$1")"
MODE="${2:-quick}"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: binary not found at $BINARY_PATH"
    exit 1
fi

BINARY_NAME=$(basename "$BINARY_PATH")
PROJECT_NAME="decon_${BINARY_NAME}"

# Clean stale locks (but keep project if it exists for reuse)
rm -f "${PROJECT_DIR:?}/${PROJECT_NAME}.lock" 2>/dev/null
mkdir -p "$PROJECT_DIR" "$OUTPUT_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Ghidra Headless Analysis"
echo "Binary:  $BINARY_PATH"
echo "Mode:    $MODE"
echo "Project: $PROJECT_DIR/$PROJECT_NAME"
echo "Output:  $OUTPUT_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if project already exists (can reuse analysis)
IMPORT_ARGS=("-import" "$BINARY_PATH")
if [ -d "${PROJECT_DIR}/${PROJECT_NAME}.rep" ]; then
    echo "Reusing existing Ghidra project (skipping re-import + re-analysis)"
    IMPORT_ARGS=("-process" "$BINARY_NAME")
fi

if [ "$MODE" = "quick" ]; then
    echo "Running quick analysis (function boundaries + call graph)..."
    "$GHIDRA_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
        "${IMPORT_ARGS[@]}" \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript ExportFunctionInfo.java "$OUTPUT_DIR" \
        -analysisTimeoutPerFile 3600 \
        2>&1 | tee "$OUTPUT_DIR/ghidra_analysis.log"

elif [ "$MODE" = "full" ]; then
    echo "Running full parallel decompilation..."
    "$GHIDRA_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
        "${IMPORT_ARGS[@]}" \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript DecompileAllParallel.java "$OUTPUT_DIR" \
        -analysisTimeoutPerFile 7200 \
        2>&1 | tee "$OUTPUT_DIR/ghidra_analysis.log"

elif [ "$MODE" = "combined" ]; then
    echo "Running combined analysis (quick + full parallel decompilation in one pass)..."
    "$GHIDRA_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
        "${IMPORT_ARGS[@]}" \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript ExportFunctionInfo.java "$OUTPUT_DIR" \
        -postScript DecompileAllParallel.java "$OUTPUT_DIR" \
        -analysisTimeoutPerFile 7200 \
        2>&1 | tee "$OUTPUT_DIR/ghidra_analysis.log"
else
    echo "Unknown mode: $MODE (use 'quick', 'full', or 'combined')"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Analysis complete. Output:"
ls -lh "$OUTPUT_DIR/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
