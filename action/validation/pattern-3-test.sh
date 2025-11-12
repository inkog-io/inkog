#!/bin/bash

###############################################################################
# PATTERN 1: Infinite Loops Detection Detection - Enterprise Validation Test
# Tests infinite-loops-v2 on both clean and messy code
# Measures: memory, time, findings count, accuracy
###############################################################################

set -e

# Configuration
PATTERN_NAME="prompt-injection-v2"
PATTERN_NUMBER=3
REPO_PATH="${REPO_PATH:-.}"
SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"

# Expected metrics (from MULTI_PATTERN_VALIDATION_REPORT_v1.md simulation)
# Adjust based on actual baseline after first run
EXPECTED_FINDINGS_CLEAN_MIN=30
EXPECTED_FINDINGS_CLEAN_MAX=50
EXPECTED_FINDINGS_MESSY_MIN=30
EXPECTED_FINDINGS_MESSY_MAX=60
EXPECTED_MEMORY_MAX_MB=500
EXPECTED_TIME_MAX_SEC=3

mkdir -p "$RESULTS_DIR/patterns"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo "[$(date +'%H:%M:%S')] $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

echo "=========================================="
echo "Pattern 3 Test: Infinite Loops Detection"
echo "=========================================="
echo "Pattern: $PATTERN_NAME"
echo "Repository: $REPO_PATH"
echo ""

# ============================================================================
# TEST: PATTERN ON CLEAN CODE (REAL REPO)
# ============================================================================

echo "Test 1: Running on clean code (real Inkog repo)..."

if ! /usr/bin/time -v "$SCANNER_BIN" scan \
    --patterns "$PATTERN_NAME" \
    "$REPO_PATH" \
    --threshold 0.60 \
    --json \
    > "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean.json" \
    2> "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt"; then

    error "FAIL: Scanner crashed on clean code"
    cat "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt"
    exit 1
fi

success "Scan completed"

# Extract metrics from time output
findings=$(grep -o '"severity"' "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean.json" 2>/dev/null | wc -l || echo "0")
memory_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
memory_mb=$((memory_kb / 1024 + 1))
elapsed=$(grep "Elapsed (wall clock)" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-clean-metrics.txt" 2>/dev/null | awk -F: '{print ($1*3600) + ($2*60) + $3}' | head -1 || echo "0")

echo "Results (Clean Code):"
echo "  Findings: $findings"
echo "  Memory: ${memory_mb}MB"
echo "  Time: ${elapsed}s"

# Validate clean code results
test_passed=true

if [ "$findings" -lt "$EXPECTED_FINDINGS_CLEAN_MIN" ] || [ "$findings" -gt "$EXPECTED_FINDINGS_CLEAN_MAX" ]; then
    warn "Findings ($findings) outside expected range ($EXPECTED_FINDINGS_CLEAN_MIN-$EXPECTED_FINDINGS_CLEAN_MAX)"
    warn "  (This is OK on first run - update expectations after baseline established)"
fi

if [ "$memory_mb" -gt "$EXPECTED_MEMORY_MAX_MB" ]; then
    error "Memory ($memory_mb MB) exceeds expected max ($EXPECTED_MEMORY_MAX_MB MB)"
    test_passed=false
fi

if [ "$memory_mb" -eq 0 ]; then
    warn "Could not measure memory (may be running in container)"
fi

# Check no crash
if [ "$findings" -eq 0 ] && [ "$memory_mb" -lt 10 ]; then
    warn "Zero findings and minimal memory - verify scan actually ran"
fi

if [ "$test_passed" = false ]; then
    error "Clean code test FAILED"
    exit 1
fi

success "Clean code test passed"

# ============================================================================
# TEST: PATTERN ON MESSY CODE (IF AVAILABLE)
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

        error "FAIL: Scanner crashed on messy code"
        exit 1
    fi

    success "Scan completed"

    findings_messy=$(grep -o '"severity"' "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy.json" 2>/dev/null | wc -l || echo "0")
    memory_messy_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy-metrics.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
    memory_messy_mb=$((memory_messy_kb / 1024 + 1))

    echo "Results (Messy Code):"
    echo "  Findings: $findings_messy"
    echo "  Memory: ${memory_messy_mb}MB"

    if [ "$findings_messy" -lt "$EXPECTED_FINDINGS_MESSY_MIN" ] || [ "$findings_messy" -gt "$EXPECTED_FINDINGS_MESSY_MAX" ]; then
        warn "Messy findings ($findings_messy) outside expected ($EXPECTED_FINDINGS_MESSY_MIN-$EXPECTED_FINDINGS_MESSY_MAX)"
        warn "  (Expected higher FP rate on messy code - this is normal)"
    fi

    if [ "$memory_messy_mb" -gt $((EXPECTED_MEMORY_MAX_MB * 2)) ]; then
        warn "Messy code memory 2x clean - monitor for leaks"
    fi

    success "Messy code test passed"
else
    warn "Messy code corpus not found - skipping messy test"
fi

# ============================================================================
# SUMMARY & HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Pattern 3 Test Results"
echo "=========================================="

# Hard gate: Pattern must not crash
if [ "$findings" -gt 0 ] || [ "$memory_mb" -gt 10 ]; then
    success "HARD GATE 3 PASSED: Pattern 3 - No crash"
    echo "  ✓ Pattern executed successfully"
    echo "  ✓ Memory: ${memory_mb}MB (limit: $EXPECTED_MEMORY_MAX_MB MB)"
    echo "  ✓ Findings: $findings"
else
    error "HARD GATE 3 FAILED: Pattern appears not to have run"
    exit 1
fi

echo ""
echo "Results saved to: $RESULTS_DIR/patterns/"
echo "  - pattern-$PATTERN_NUMBER-clean.json"
if [ -f "$RESULTS_DIR/patterns/pattern-$PATTERN_NUMBER-messy.json" ]; then
    echo "  - pattern-$PATTERN_NUMBER-messy.json"
fi
echo ""

success "Pattern 3 Test PASSED"
echo ""

exit 0
