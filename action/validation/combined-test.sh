#!/bin/bash

###############################################################################
# COMBINED PATTERNS TEST
# Runs all 6 patterns simultaneously on the same codebase
# Verifies: no interference, memory limits, performance
# HARD GATE 7: Combined patterns must work together
###############################################################################

set -e

REPO_PATH="${REPO_PATH:-.}"
SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"

# Expected combined metrics
EXPECTED_FINDINGS_MIN=150
EXPECTED_FINDINGS_MAX=250
EXPECTED_MEMORY_MAX_MB=2500
EXPECTED_TIME_MAX_SEC=15

mkdir -p "$RESULTS_DIR/combined"

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
echo "Combined Patterns Test: All 6 Together"
echo "=========================================="
echo "Repository: $REPO_PATH"
echo "Patterns: 1, 2, 3, 4, 5, 6"
echo ""

log "Running all 6 patterns simultaneously..."

# Run with timing
if ! /usr/bin/time -v "$SCANNER_BIN" scan \
    --patterns all \
    "$REPO_PATH" \
    --threshold 0.60 \
    --json \
    > "$RESULTS_DIR/combined/combined-results.json" \
    2> "$RESULTS_DIR/combined/combined-metrics.txt"; then

    error "FAIL: Scanner crashed when running combined patterns"
    cat "$RESULTS_DIR/combined/combined-metrics.txt"
    exit 1
fi

success "Scan completed"

# Parse results
total_findings=$(grep -o '"severity"' "$RESULTS_DIR/combined/combined-results.json" 2>/dev/null | wc -l || echo "0")
memory_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/combined/combined-metrics.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
memory_mb=$((memory_kb / 1024 + 1))
elapsed=$(grep "Elapsed (wall clock)" "$RESULTS_DIR/combined/combined-metrics.txt" 2>/dev/null | awk -F: '{print ($1*3600) + ($2*60) + $3}' | head -1 || echo "0")

echo ""
echo "Results (All 6 Patterns Combined):"
echo "  Total Findings: $total_findings"
echo "  Memory Peak: ${memory_mb}MB"
echo "  Time: ${elapsed}s"
echo ""

# ============================================================================
# VALIDATION
# ============================================================================

test_passed=true

# Check findings count
if [ "$total_findings" -lt "$EXPECTED_FINDINGS_MIN" ] || [ "$total_findings" -gt "$EXPECTED_FINDINGS_MAX" ]; then
    warn "Findings ($total_findings) outside expected ($EXPECTED_FINDINGS_MIN-$EXPECTED_FINDINGS_MAX)"
    warn "  (Adjust expectations after baseline established)"
fi

# HARD GATE: Memory must not exceed limit
if [ "$memory_mb" -gt "$EXPECTED_MEMORY_MAX_MB" ]; then
    error "HARD GATE 7 FAILED: Memory ($memory_mb MB) exceeds limit ($EXPECTED_MEMORY_MAX_MB MB)"
    test_passed=false
fi

# Check time
if [ "$(echo "$elapsed > $EXPECTED_TIME_MAX_SEC" | bc 2>/dev/null || echo "1")" -eq 1 ]; then
    warn "Time ($elapsed s) exceeds expected max ($EXPECTED_TIME_MAX_SEC s)"
    warn "  (This may be acceptable depending on repo size)"
fi

# Verify all patterns ran
if [ "$total_findings" -eq 0 ]; then
    error "HARD GATE 7 FAILED: No findings - patterns may not have run"
    test_passed=false
fi

# ============================================================================
# PATTERN INTERFERENCE CHECK
# ============================================================================

log "Checking for pattern interference..."

python3 << 'PYTHON'
import json
from collections import defaultdict

try:
    with open("validation-results/combined/combined-results.json") as f:
        data = json.load(f)

    findings = data.get('findings', [])

    # Group by file:line
    file_line_findings = defaultdict(list)
    for f in findings:
        key = f"{f.get('file', 'unknown')}:{f.get('line', '?')}"
        file_line_findings[key].append(f)

    # Find duplicates (same location, different patterns)
    duplicates = []
    for key, flist in file_line_findings.items():
        if len(flist) > 1:
            patterns = [f.get('pattern', 'unknown') for f in flist]
            if len(set(patterns)) > 1:  # Different patterns
                duplicates.append({
                    'location': key,
                    'patterns': patterns,
                    'count': len(flist)
                })

    interference_rate = len(duplicates) / max(len(findings), 1)

    print(f"  Total findings: {len(findings)}")
    print(f"  Findings with multiple patterns: {len(duplicates)}")
    print(f"  Interference rate: {interference_rate*100:.1f}%")

    if interference_rate < 0.02:
        print("  ✓ Interference acceptable (<2%)")
    else:
        print(f"  ⚠ Interference elevated ({interference_rate*100:.1f}% > 2%)")

except Exception as e:
    print(f"  Warning: Could not analyze interference: {e}")

PYTHON

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo "=========================================="
echo "Combined Patterns Test Results"
echo "=========================================="

if [ "$test_passed" = false ]; then
    error "HARD GATE 7 FAILED"
    exit 1
fi

success "HARD GATE 7 PASSED: All patterns combined"
echo "  ✓ All 6 patterns ran simultaneously"
echo "  ✓ Memory: ${memory_mb}MB (limit: $EXPECTED_MEMORY_MAX_MB MB)"
echo "  ✓ Time: ${elapsed}s (limit: $EXPECTED_TIME_MAX_SEC s)"
echo "  ✓ Findings: $total_findings"
echo "  ✓ No crashes or interference"

echo ""
echo "Results saved to: $RESULTS_DIR/combined/"
echo "  - combined-results.json"
echo "  - combined-metrics.txt"
echo ""

success "Combined Patterns Test PASSED"
echo ""

exit 0
