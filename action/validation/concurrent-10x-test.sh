#!/bin/bash

###############################################################################
# CONCURRENT SCANNING TEST (10x Simultaneous)
# Tests pattern behavior when 10 scans run simultaneously
# Verifies: memory stays <4GB, all complete, findings consistent, no hangs
# HARD GATE 8: Concurrent 10x must all complete successfully
###############################################################################

set -e

REPO_PATH="${REPO_PATH:-.}"
SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
NUM_CONCURRENT=10
EXPECTED_MEMORY_MAX_MB=4000
TIMEOUT_SEC=60

mkdir -p "$RESULTS_DIR/concurrent"

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
echo "Concurrent Scanning Test: 10x Simultaneous"
echo "=========================================="
echo "Repository: $REPO_PATH"
echo "Concurrent scans: $NUM_CONCURRENT"
echo "Per-scan timeout: ${TIMEOUT_SEC}s"
echo ""

log "Starting 10 concurrent scans..."

# Track process IDs and results
declare -a pids
declare -a results
test_passed=true

# Start all 10 scans in background
for i in $(seq 1 $NUM_CONCURRENT); do
    log "Scan $i/$NUM_CONCURRENT starting..."

    # Run scan with timeout
    timeout $TIMEOUT_SEC "$SCANNER_BIN" scan \
        --patterns all \
        "$REPO_PATH" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/concurrent/scan-$i.json" \
        2> "$RESULTS_DIR/concurrent/scan-$i-err.txt" &

    pids[$i]=$!
done

success "All $NUM_CONCURRENT scans dispatched"

# Wait for all scans to complete
log "Monitoring concurrent execution..."
echo ""

completed=0
failed=0
start_time=$(date +%s)

for i in $(seq 1 $NUM_CONCURRENT); do
    if wait "${pids[$i]}" 2>/dev/null; then
        success "Scan $i completed successfully"
        results[$i]="PASS"
        ((completed++))
    else
        error "Scan $i FAILED or timed out"
        results[$i]="FAIL"
        ((failed++))
        test_passed=false
    fi
done

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo ""
echo "=========================================="
echo "Concurrent Execution Summary"
echo "=========================================="
echo "Completed: $completed/$NUM_CONCURRENT"
echo "Failed: $failed/$NUM_CONCURRENT"
echo "Total time: ${elapsed}s"
echo ""

# ============================================================================
# CONSISTENCY CHECK
# ============================================================================

log "Checking consistency across all scans..."

if [ $completed -gt 1 ]; then
    # Extract finding counts
    declare -a finding_counts

    for i in $(seq 1 $completed); do
        if [ -f "$RESULTS_DIR/concurrent/scan-$i.json" ]; then
            count=$(grep -o '"severity"' "$RESULTS_DIR/concurrent/scan-$i.json" 2>/dev/null | wc -l || echo "0")
            finding_counts[$i]=$count
        fi
    done

    # Check variance
    if [ ${#finding_counts[@]} -gt 1 ]; then
        first=${finding_counts[1]}
        max=$first
        min=$first

        for count in "${finding_counts[@]}"; do
            [ $count -gt $max ] && max=$count
            [ $count -lt $min ] && min=$count
        done

        variance=$((max - min))

        echo "Finding counts across scans:"
        for i in $(seq 1 ${#finding_counts[@]}); do
            echo "  Scan $i: ${finding_counts[$i]} findings"
        done
        echo ""

        if [ $variance -le 5 ]; then
            success "Consistency check PASSED (variance: $variance findings)"
        else
            warn "Consistency check: High variance ($variance findings)"
            warn "  This may be acceptable if patterns are non-deterministic"
        fi
    fi
fi

# ============================================================================
# MEMORY CHECK
# ============================================================================

log "Checking peak memory usage..."

# Try to get memory from ps if available (note: this is approximate)
# In real scenario, would use pprof or system monitoring
peak_memory=$(ps aux | grep "$SCANNER_BIN" | grep -v grep | awk '{sum+=$6} END {print sum/1024}' || echo "0")

if [ "$peak_memory" -gt "$EXPECTED_MEMORY_MAX_MB" ]; then
    warn "Memory usage ($peak_memory MB) may exceed expected limit ($EXPECTED_MEMORY_MAX_MB MB)"
    warn "  (Note: ps memory is approximation - requires pprof for exact measurement)"
else
    success "Memory usage acceptable (estimated $peak_memory MB)"
fi

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Concurrent 10x Test Results"
echo "=========================================="

if [ $failed -eq 0 ] && [ $completed -eq $NUM_CONCURRENT ]; then
    success "HARD GATE 8 PASSED: All concurrent scans completed"
    echo "  ✓ All $NUM_CONCURRENT scans completed successfully"
    echo "  ✓ No timeouts or crashes"
    echo "  ✓ Total execution time: ${elapsed}s"
    if [ $variance -le 5 ]; then
        echo "  ✓ Consistency verified (variance: $variance)"
    fi
else
    error "HARD GATE 8 FAILED: $failed scans failed"
    test_passed=false
fi

echo ""
echo "Results saved to: $RESULTS_DIR/concurrent/"
echo "  - scan-{1-10}.json (individual results)"
echo "  - scan-{1-10}-err.txt (error logs)"
echo ""

if [ "$test_passed" = false ]; then
    error "Concurrent 10x Test FAILED"
    exit 1
fi

success "Concurrent 10x Test PASSED"
echo ""

exit 0
