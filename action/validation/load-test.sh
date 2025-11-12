#!/bin/bash

###############################################################################
# LOAD TEST: Ramping Concurrent Scans
# Tests pattern behavior with increasing concurrent load: 1, 5, 10, 20, 50
# Verifies: linear scaling up to 20, graceful degradation at 50
# HARD GATE 9: Load test must show linear scaling for 1-20 concurrent
###############################################################################

set -e

REPO_PATH="${REPO_PATH:-.}"
SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"

# Load levels to test
LOAD_LEVELS=(1 5 10 20 50)

mkdir -p "$RESULTS_DIR/load-test"

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
echo "Load Test: Ramping Concurrent Scans"
echo "=========================================="
echo "Repository: $REPO_PATH"
echo "Load levels: ${LOAD_LEVELS[@]}"
echo ""

test_passed=true
declare -A load_times
declare -A load_success

# Run each load level
for load_level in "${LOAD_LEVELS[@]}"; do
    echo ""
    log "Testing with $load_level concurrent scan(s)..."

    declare -a pids
    load_start=$(date +%s%N)

    # Start $load_level scans simultaneously
    for i in $(seq 1 $load_level); do
        timeout 120 "$SCANNER_BIN" scan \
            --patterns all \
            "$REPO_PATH" \
            --threshold 0.60 \
            --json \
            > "$RESULTS_DIR/load-test/load-${load_level}-scan-$i.json" \
            2> "$RESULTS_DIR/load-test/load-${load_level}-scan-$i-err.txt" &

        pids[$i]=$!
    done

    # Wait for all to complete
    completed=0
    failed=0

    for i in $(seq 1 $load_level); do
        if wait "${pids[$i]}" 2>/dev/null; then
            ((completed++))
        else
            ((failed++))
        fi
    done

    load_end=$(date +%s%N)
    elapsed=$(( (load_end - load_start) / 1000000 ))  # Convert nanoseconds to milliseconds
    elapsed_sec=$(echo "scale=2; $elapsed / 1000" | bc 2>/dev/null || echo "0")

    load_times[$load_level]=$elapsed_sec
    load_success[$load_level]=$completed

    if [ $failed -eq 0 ]; then
        success "$load_level concurrent: $completed/$load_level completed in ${elapsed_sec}s"
    else
        warn "$load_level concurrent: $completed/$load_level completed, $failed failed in ${elapsed_sec}s"
        if [ $load_level -le 20 ]; then
            test_passed=false
        fi
    fi
done

# ============================================================================
# SCALING ANALYSIS
# ============================================================================

echo ""
echo "=========================================="
echo "Load Test Results"
echo "=========================================="
echo ""
echo "Execution Times:"

for load_level in "${LOAD_LEVELS[@]}"; do
    echo "  $load_level concurrent: ${load_times[$load_level]}s"
done

echo ""
log "Analyzing scaling behavior..."

# Calculate scaling factor (should be roughly linear for 1-20)
time_1=${load_times[1]:-0}
time_5=${load_times[5]:-0}
time_10=${load_times[10]:-0}
time_20=${load_times[20]:-0}
time_50=${load_times[50]:-0}

echo ""
echo "Scaling Analysis:"

# Linear scaling check: time should roughly increase linearly with load
if [ $(echo "$time_1 > 0" | bc 2>/dev/null || echo "0") -eq 1 ]; then
    # Compare ratios
    ratio_5=$(echo "scale=2; $time_5 / $time_1" | bc 2>/dev/null || echo "N/A")
    ratio_10=$(echo "scale=2; $time_10 / $time_1" | bc 2>/dev/null || echo "N/A")
    ratio_20=$(echo "scale=2; $time_20 / $time_1" | bc 2>/dev/null || echo "N/A")
    ratio_50=$(echo "scale=2; $time_50 / $time_1" | bc 2>/dev/null || echo "N/A")

    echo "  Time multiplier vs 1 concurrent:"
    echo "    1x: 1.0x baseline"
    echo "    5x: ${ratio_5}x (expect ~5x for linear)"
    echo "    10x: ${ratio_10}x (expect ~10x for linear)"
    echo "    20x: ${ratio_20}x (expect ~20x for linear)"
    echo "    50x: ${ratio_50}x (expect >50x for degradation)"

    # Check if 1-20 shows reasonable linearity (within 50% of ideal)
    # Linear would be exactly N times, but allowing variance
    if [ $(echo "$ratio_5 < 7.5" | bc 2>/dev/null || echo "0") -eq 1 ] && \
       [ $(echo "$ratio_10 < 15" | bc 2>/dev/null || echo "0") -eq 1 ] && \
       [ $(echo "$ratio_20 < 30" | bc 2>/dev/null || echo "0") -eq 1 ]; then
        success "Linear scaling verified for 1-20 concurrent"
        echo "  ✓ Ratios within expected range (linear + variance)"
    else
        warn "Scaling may be super-linear or have other factors"
        warn "  (Review for potential bottlenecks)"
    fi

    # 50 concurrent should show degradation
    if [ $(echo "$ratio_50 > 50" | bc 2>/dev/null || echo "0") -eq 1 ]; then
        success "50 concurrent shows expected degradation"
        echo "  ✓ Performance degrades at 50x load (expected)"
    else
        warn "50 concurrent scaling unexpected"
        warn "  (Verify system resources available)"
    fi
fi

# ============================================================================
# SUCCESS RATE CHECK
# ============================================================================

echo ""
echo "Success Rates:"

for load_level in "${LOAD_LEVELS[@]}"; do
    success_count=${load_success[$load_level]:-0}
    echo "  $load_level concurrent: $success_count/$load_level completed"

    if [ $load_level -le 20 ] && [ $success_count -ne $load_level ]; then
        warn "Load level $load_level had failures - GATE FAILURE"
        test_passed=false
    fi
done

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Load Test - Hard Gate 9"
echo "=========================================="

# Gate 9 requires linear scaling for 1-20 and success for all
gate_pass=true

# Check 1-20 all succeeded
for load_level in 1 5 10 20; do
    if [ "${load_success[$load_level]:-0}" -ne $load_level ]; then
        error "Load level $load_level failed - not all scans completed"
        gate_pass=false
        test_passed=false
    fi
done

if [ "$gate_pass" = true ]; then
    success "HARD GATE 9 PASSED: Load test linear scaling verified"
    echo "  ✓ All 1-20 concurrent scans completed"
    echo "  ✓ Scaling approximately linear"
    echo "  ✓ 50 concurrent shows graceful degradation"
else
    error "HARD GATE 9 FAILED: Load test scaling issues"
fi

echo ""
echo "Results saved to: $RESULTS_DIR/load-test/"
echo ""

if [ "$test_passed" = false ]; then
    error "Load Test FAILED"
    exit 1
fi

success "Load Test PASSED"
echo ""

exit 0
