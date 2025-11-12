#!/bin/bash

###############################################################################
# PATTERN TEST TEMPLATE
# Copy this file for each pattern: pattern-1-test.sh, pattern-2-test.sh, etc.
# Then update PATTERN_NAME and EXPECTED_* variables
###############################################################################

set -e

# Configuration
PATTERN_NAME="${PATTERN_NAME:-pattern-1-v2}"
PATTERN_NUMBER="${PATTERN_NUMBER:-1}"
REPO_PATH="${REPO_PATH:-.}"
SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"

mkdir -p "$RESULTS_DIR/patterns"

# Expected metrics (adjust per pattern based on simulation)
EXPECTED_FINDINGS_MIN=5
EXPECTED_FINDINGS_MAX=30
EXPECTED_MEMORY_MAX_MB=500
EXPECTED_TIME_MAX_SEC=3

echo "=========================================="
echo "Pattern $PATTERN_NUMBER Test"
echo "=========================================="
echo "Pattern: $PATTERN_NAME"
echo "Repository: $REPO_PATH"
echo ""

# ============================================================================
# TEST: INDIVIDUAL PATTERN ON CLEAN CODE
# ============================================================================

echo "Test 1: Running on clean code..."

if ! /usr/bin/time -v "$SCANNER_BIN" scan \
    --patterns "$PATTERN_NAME" \
    "$REPO_PATH" \
    --threshold 0.60 \
    --json \
    > "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean.json" \
    2> "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt"; then

    echo "❌ FAIL: Scanner crashed on clean code"
    exit 1
fi

echo "✓ Scan completed"

# Extract metrics
findings=$(grep -o '"severity"' "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean.json" | wc -l || echo "0")
memory_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt" | awk '{print $6}' | head -1 || echo "0")
memory_mb=$((memory_kb / 1024))
elapsed=$(grep "Elapsed" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt" | awk -F: '{print ($1*3600) + ($2*60) + $3}' | head -1 || echo "0")

echo "Results (Clean Code):"
echo "  Findings: $findings"
echo "  Memory: ${memory_mb}MB"
echo "  Time: ${elapsed}s"

# Validate
if [ "$findings" -lt "$EXPECTED_FINDINGS_MIN" ] || [ "$findings" -gt "$EXPECTED_FINDINGS_MAX" ]; then
    echo "⚠️  WARNING: Findings ($findings) outside expected range ($EXPECTED_FINDINGS_MIN-$EXPECTED_FINDINGS_MAX)"
fi

if [ "$memory_mb" -gt "$EXPECTED_MEMORY_MAX_MB" ]; then
    echo "❌ FAIL: Memory ($memory_mb MB) exceeds expected max ($EXPECTED_MEMORY_MAX_MB MB)"
    exit 1
fi

if [ "$(echo "$elapsed > $EXPECTED_TIME_MAX_SEC" | bc)" -eq 1 ]; then
    echo "⚠️  WARNING: Time ($elapsed s) exceeds expected max ($EXPECTED_TIME_MAX_SEC s)"
fi

echo "✓ Clean code test passed"

# ============================================================================
# TEST: INDIVIDUAL PATTERN ON MESSY CODE
# ============================================================================

if [ -d "validation-data/corpus/messy" ]; then
    echo ""
    echo "Test 2: Running on messy code..."

    if ! /usr/bin/time -v "$SCANNER_BIN" scan \
        --patterns "$PATTERN_NAME" \
        "validation-data/corpus/messy" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy.json" \
        2> "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy-metrics.txt"; then

        echo "❌ FAIL: Scanner crashed on messy code"
        exit 1
    fi

    echo "✓ Scan completed"

    findings_messy=$(grep -o '"severity"' "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy.json" | wc -l || echo "0")
    memory_messy_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy-metrics.txt" | awk '{print $6}' | head -1 || echo "0")
    memory_messy_mb=$((memory_messy_kb / 1024))

    echo "Results (Messy Code):"
    echo "  Findings: $findings_messy"
    echo "  Memory: ${memory_messy_mb}MB"

    if [ "$memory_messy_mb" -gt $((EXPECTED_MEMORY_MAX_MB * 2)) ]; then
        echo "⚠️  WARNING: Messy code memory higher than expected"
    fi

    echo "✓ Messy code test passed"
fi

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "=========================================="
echo "✓ Pattern $PATTERN_NUMBER Test PASSED"
echo "=========================================="
echo ""
echo "Results saved to: $RESULTS_DIR/patterns/"
echo "  - pattern-$PATTERN_NUMBER-clean.json"
echo "  - pattern-$PATTERN_NUMBER-messy.json"
echo ""

exit 0
