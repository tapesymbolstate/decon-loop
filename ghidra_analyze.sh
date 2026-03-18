#!/bin/bash
# Ghidra headless analysis wrapper for decon-agent
#
# Usage: ./ghidra_analyze.sh <binary_path> [full|quick]
#
# Modes:
#   quick  — Export function boundaries + call graph only (~5-10 min)
#   full   — Full decompilation of all functions (~30-60 min for 182MB binary)
#
# Output goes to output/ghidra/

set -euo pipefail
cd "$(dirname "$0")"

GHIDRA_HEADLESS="/opt/homebrew/Cellar/ghidra/12.0/libexec/support/analyzeHeadless"
SCRIPTS_DIR="$(pwd)/ghidra-scripts"
PROJECT_DIR="/tmp/ghidra-projects"
OUTPUT_DIR="$(pwd)/output/ghidra"

if [ -z "${1:-}" ]; then
    echo "Usage: ./ghidra_analyze.sh <binary_path> [full|quick]"
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

# Clean stale locks from previous runs, then ensure dirs exist
rm -rf "${PROJECT_DIR:?}/${PROJECT_NAME}" "${PROJECT_DIR:?}/${PROJECT_NAME}.rep" "${PROJECT_DIR:?}/${PROJECT_NAME}.lock" 2>/dev/null
mkdir -p "$PROJECT_DIR" "$OUTPUT_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Ghidra Headless Analysis"
echo "Binary:  $BINARY_PATH"
echo "Mode:    $MODE"
echo "Project: $PROJECT_DIR/$PROJECT_NAME"
echo "Output:  $OUTPUT_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$MODE" = "quick" ]; then
    echo "Running quick analysis (function boundaries + call graph)..."
    "$GHIDRA_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
        -import "$BINARY_PATH" \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript ExportFunctionInfo.java "$OUTPUT_DIR" \
        -deleteProject \
        -analysisTimeoutPerFile 3600 \
        2>&1 | tee "$OUTPUT_DIR/ghidra_analysis.log"

elif [ "$MODE" = "full" ]; then
    echo "Running full decompilation (this will take a while)..."
    "$GHIDRA_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
        -import "$BINARY_PATH" \
        -scriptPath "$SCRIPTS_DIR" \
        -postScript DecompileAll.java "$OUTPUT_DIR" \
        -deleteProject \
        -analysisTimeoutPerFile 7200 \
        2>&1 | tee "$OUTPUT_DIR/ghidra_analysis.log"
else
    echo "Unknown mode: $MODE (use 'quick' or 'full')"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Analysis complete. Output:"
ls -lh "$OUTPUT_DIR/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
