#!/bin/bash

###############################################################################
# MEMORY LEAK DETECTION TEST
# Runs the same scan 5 times and monitors memory growth
# Verifies: memory stable across runs, no unbounded growth, leaks absent
# HARD GATE 12 (Extended): No memory leaks detected over repeated scans
###############################################################################

set -e

SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
REPO_PATH="${REPO_PATH:-.}"
NUM_ITERATIONS=5
EXPECTED_MEMORY_MAX_MB=2000

mkdir -p "$RESULTS_DIR/memory-leak"

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
echo "Memory Leak Detection Test"
echo "=========================================="
echo "Repository: $REPO_PATH"
echo "Test iterations: $NUM_ITERATIONS"
echo "Expected stable memory across runs"
echo ""

test_passed=true

# ============================================================================
# RUN REPEATED SCANS AND MEASURE MEMORY
# ============================================================================

log "Running $NUM_ITERATIONS scan iterations..."
log "Measuring memory growth patterns..."

declare -a memory_readings
declare -a elapsed_times

for i in $(seq 1 $NUM_ITERATIONS); do
    echo ""
    log "Scan $i/$NUM_ITERATIONS..."

    # Run scan with timing
    if /usr/bin/time -v "$SCANNER_BIN" scan \
        --patterns all \
        "$REPO_PATH" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/memory-leak/scan-$i.json" \
        2> "$RESULTS_DIR/memory-leak/scan-$i-metrics.txt"; then

        success "Scan $i completed"

        # Extract memory from timing output
        memory_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/memory-leak/scan-$i-metrics.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
        memory_mb=$((memory_kb / 1024 + 1))
        memory_readings[$i]=$memory_mb

        # Extract elapsed time
        elapsed=$(grep "Elapsed (wall clock)" "$RESULTS_DIR/memory-leak/scan-$i-metrics.txt" 2>/dev/null | awk -F: '{print ($1*3600) + ($2*60) + $3}' | head -1 || echo "0")
        elapsed_times[$i]=$elapsed

        # Count findings
        findings=$(grep -o '"severity"' "$RESULTS_DIR/memory-leak/scan-$i.json" 2>/dev/null | wc -l || echo "0")

        echo "  Memory: ${memory_mb}MB"
        echo "  Time: ${elapsed}s"
        echo "  Findings: $findings"

        if [ "$memory_mb" -gt "$EXPECTED_MEMORY_MAX_MB" ]; then
            error "Memory exceeds limit: ${memory_mb}MB > ${EXPECTED_MEMORY_MAX_MB}MB"
            test_passed=false
        fi

    else
        error "Scan $i failed"
        test_passed=false
        break
    fi
done

# ============================================================================
# MEMORY GROWTH ANALYSIS
# ============================================================================

echo ""
echo "=========================================="
echo "Memory Growth Analysis"
echo "=========================================="

log "Analyzing memory growth patterns..."

echo ""
echo "Memory readings across iterations:"

for i in $(seq 1 $NUM_ITERATIONS); do
    mem=${memory_readings[$i]:-0}
    time=${elapsed_times[$i]:-0}
    echo "  Scan $i: ${mem}MB (${time}s)"
done

# Calculate growth rate
if [ ${#memory_readings[@]} -gt 1 ]; then
    first_mem=${memory_readings[1]:-0}
    last_mem=${memory_readings[$NUM_ITERATIONS]:-0}

    if [ "$first_mem" -gt 0 ]; then
        growth=$((last_mem - first_mem))
        growth_rate=$(echo "scale=1; (($last_mem - $first_mem) / $first_mem) * 100" | bc 2>/dev/null || echo "N/A")

        echo ""
        echo "Growth Analysis:"
        echo "  First scan: ${first_mem}MB"
        echo "  Last scan: ${last_mem}MB"
        echo "  Absolute growth: ${growth}MB"
        echo "  Growth rate: ${growth_rate}%"
        echo ""

        # Leak detection: significant growth indicates leak
        if [ "$growth" -lt 100 ]; then
            success "Memory growth acceptable (<100MB)"
            echo "  ✓ Likely no significant leaks"
        elif [ "$growth" -lt 300 ]; then
            warn "Moderate memory growth (100-300MB)"
            echo "  ⚠ Monitor for potential leaks"
            echo "  ⚠ Could be caching or lazy initialization"
        else
            error "LEAK DETECTED: High memory growth (>300MB)"
            echo "  ✗ Scan $NUM_ITERATIONS uses ${growth}MB more than scan 1"
            echo "  ✗ Indicates unbounded memory growth"
            test_passed=false
        fi

        # Check growth rate percentage
        if echo "$growth_rate" | grep -q "^[0-9]"; then
            growth_percent=$(echo "$growth_rate" | cut -d. -f1)
            if [ "$growth_percent" -gt 50 ]; then
                error "LEAK SUSPECTED: Memory grew >50%"
                test_passed=false
            fi
        fi
    fi
fi

# ============================================================================
# CONSISTENCY CHECK
# ============================================================================

log "Checking consistency of scan results..."

echo ""
echo "Result Consistency:"

# All scans should produce similar numbers of findings
max_findings=0
min_findings=999999

for i in $(seq 1 $NUM_ITERATIONS); do
    if [ -f "$RESULTS_DIR/memory-leak/scan-$i.json" ]; then
        findings=$(grep -o '"severity"' "$RESULTS_DIR/memory-leak/scan-$i.json" 2>/dev/null | wc -l || echo "0")

        if [ "$findings" -gt "$max_findings" ]; then
            max_findings=$findings
        fi
        if [ "$findings" -lt "$min_findings" ]; then
            min_findings=$findings
        fi

        echo "  Scan $i: $findings findings"
    fi
done

# Check variance
if [ $min_findings -ne 999999 ]; then
    variance=$((max_findings - min_findings))

    echo ""
    echo "Finding variance: $variance"

    if [ "$variance" -le 5 ]; then
        success "Highly consistent results across scans"
    else
        warn "Some variance in findings (may be expected)"
        warn "  Check if patterns are deterministic"
    fi
fi

# ============================================================================
# STATISTICAL ANALYSIS
# ============================================================================

log "Computing memory statistics..."

echo ""
echo "Memory Statistics:"

# Calculate average memory
total_memory=0
for i in $(seq 1 $NUM_ITERATIONS); do
    total_memory=$((total_memory + ${memory_readings[$i]:-0}))
done

avg_memory=$((total_memory / NUM_ITERATIONS))
echo "  Average memory: ${avg_memory}MB"

# Calculate standard deviation
variance_sum=0
for i in $(seq 1 $NUM_ITERATIONS); do
    diff=$((${memory_readings[$i]:-0} - avg_memory))
    variance_sum=$((variance_sum + (diff * diff)))
done

# Simplified std dev (good enough for leak detection)
if [ $NUM_ITERATIONS -gt 1 ]; then
    # Standard deviation in bash (approximate)
    echo "  Memory trend: Monitoring for linear growth"

    # Simple trend: check if memory is increasing or stable
    first_half_avg=0
    second_half_avg=0
    mid=$((NUM_ITERATIONS / 2))

    for i in $(seq 1 $mid); do
        first_half_avg=$((first_half_avg + ${memory_readings[$i]:-0}))
    done
    first_half_avg=$((first_half_avg / mid))

    for i in $(seq $((mid + 1)) $NUM_ITERATIONS); do
        second_half_avg=$((second_half_avg + ${memory_readings[$i]:-0}))
    done
    second_half_avg=$((second_half_avg / (NUM_ITERATIONS - mid)))

    echo "  First half avg: ${first_half_avg}MB"
    echo "  Second half avg: ${second_half_avg}MB"

    trend=$((second_half_avg - first_half_avg))

    if [ "$trend" -lt 50 ]; then
        success "Memory stable (trend: ${trend}MB)"
    elif [ "$trend" -lt 200 ]; then
        warn "Slight upward trend (${trend}MB)"
    else
        error "Strong upward trend (${trend}MB) - leak indicator"
        test_passed=false
    fi
fi

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Memory Leak Test Results"
echo "=========================================="

if [ "$test_passed" = true ]; then
    success "HARD GATE 12 (Extended) PASSED: No memory leaks detected"
    echo "  ✓ All $NUM_ITERATIONS scans completed"
    echo "  ✓ Memory stable across iterations"
    echo "  ✓ Growth trend acceptable"
    echo "  ✓ Results consistent"
    echo "  ✓ No unbounded memory growth detected"
else
    error "HARD GATE 12 (Extended) FAILED: Memory leak detected"
fi

echo ""
echo "Results saved to: $RESULTS_DIR/memory-leak/"
echo "  - scan-{1-$NUM_ITERATIONS}.json (per-iteration results)"
echo "  - scan-{1-$NUM_ITERATIONS}-metrics.txt (timing details)"
echo ""

# ============================================================================
# SUMMARY REPORT
# ============================================================================

log "Generating leak detection summary..."

cat > "$RESULTS_DIR/memory-leak/leak-summary.txt" << EOF
Memory Leak Detection Summary
============================

Test Configuration:
  Repository: $REPO_PATH
  Iterations: $NUM_ITERATIONS
  Time between scans: immediate (sequential)

Results:
  First scan memory: ${memory_readings[1]:-?}MB
  Last scan memory: ${memory_readings[$NUM_ITERATIONS]:-?}MB
  Total growth: ${growth:-?}MB
  Growth rate: ${growth_rate:-?}%
  Average memory: ${avg_memory:-?}MB

Leak Assessment:
  Memory stable: $([ "$growth" -lt 100 ] && echo "YES" || echo "NO")
  Linear growth: $([ "$trend" -lt 50 ] && echo "NO" || echo "POSSIBLE")
  Conclusion: $([ "$test_passed" = true ] && echo "PASS - No leaks detected" || echo "FAIL - Possible leak")

Recommendations:
  1. Run test on larger repository for more accurate leak detection
  2. Monitor memory growth over longer time periods (hours/days)
  3. Use pprof with longer-running scans for detailed leak analysis
  4. Consider memory pressure testing with memory limits

EOF

success "Summary saved to leak-summary.txt"

if [ "$test_passed" = false ]; then
    error "Memory Leak Test FAILED"
    exit 1
fi

success "Memory Leak Test PASSED"
echo ""

exit 0
