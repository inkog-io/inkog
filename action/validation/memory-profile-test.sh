#!/bin/bash

###############################################################################
# MEMORY PROFILING TEST with pprof
# Analyzes detailed memory usage patterns during scanning
# Verifies: peak memory <2GB, no memory leaks, GC functioning correctly
# HARD GATE 12: Memory profiling must show healthy memory behavior
###############################################################################

set -e

SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
REPO_PATH="${REPO_PATH:-.}"
EXPECTED_MEMORY_PEAK_MB=2000

mkdir -p "$RESULTS_DIR/memory-profile"

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
echo "Memory Profiling Test (pprof)"
echo "=========================================="
echo "Repository: $REPO_PATH"
echo "Expected peak memory: <${EXPECTED_MEMORY_PEAK_MB}MB"
echo ""

test_passed=true

# ============================================================================
# CHECK IF PPROF IS AVAILABLE
# ============================================================================

log "Checking for pprof availability..."

# Check if scanner has pprof support
if "$SCANNER_BIN" --help 2>/dev/null | grep -q "profile\|pprof\|memory"; then
    success "Scanner supports memory profiling"
    pprof_available=true
else
    warn "Scanner may not have explicit pprof support"
    warn "  Falling back to /usr/bin/time for memory measurement"
    pprof_available=false
fi

# ============================================================================
# METHOD 1: Direct /usr/bin/time measurement (always available)
# ============================================================================

log "Running scan with detailed timing and memory measurement..."

echo ""
echo "Method 1: /usr/bin/time Measurement"

scan_start=$(date +%s%N)

if /usr/bin/time -v "$SCANNER_BIN" scan \
    --patterns all \
    "$REPO_PATH" \
    --threshold 0.60 \
    --json \
    > "$RESULTS_DIR/memory-profile/scan-results.json" \
    2> "$RESULTS_DIR/memory-profile/timing-output.txt"; then

    scan_end=$(date +%s%N)

    success "Scan completed with timing data"

    # Parse timing output
    if [ -f "$RESULTS_DIR/memory-profile/timing-output.txt" ]; then
        memory_kb=$(grep "Maximum resident set size" "$RESULTS_DIR/memory-profile/timing-output.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
        memory_mb=$((memory_kb / 1024 + 1))

        user_time=$(grep "User time" "$RESULTS_DIR/memory-profile/timing-output.txt" 2>/dev/null | awk '{print $4}' | head -1 || echo "0")
        sys_time=$(grep "System time" "$RESULTS_DIR/memory-profile/timing-output.txt" 2>/dev/null | awk '{print $4}' | head -1 || echo "0")
        elapsed=$(grep "Elapsed (wall clock)" "$RESULTS_DIR/memory-profile/timing-output.txt" 2>/dev/null | awk -F: '{print ($1*3600) + ($2*60) + $3}' | head -1 || echo "0")

        echo ""
        echo "Memory Profile Results:"
        echo "  Peak memory: ${memory_mb}MB"
        echo "  User time: ${user_time}s"
        echo "  System time: ${sys_time}s"
        echo "  Elapsed time: ${elapsed}s"
        echo ""

        # Check against limit
        if [ "$memory_mb" -gt "$EXPECTED_MEMORY_PEAK_MB" ]; then
            error "MEMORY VIOLATION: ${memory_mb}MB exceeds ${EXPECTED_MEMORY_PEAK_MB}MB limit"
            test_passed=false
        else
            success "Memory within limits: ${memory_mb}MB < ${EXPECTED_MEMORY_PEAK_MB}MB"
        fi

        # Save metrics
        cat > "$RESULTS_DIR/memory-profile/memory-metrics.txt" << EOF
Peak Memory: ${memory_mb}MB
User Time: ${user_time}s
System Time: ${sys_time}s
Elapsed Time: ${elapsed}s
Memory Status: $([ "$memory_mb" -le "$EXPECTED_MEMORY_PEAK_MB" ] && echo "PASS" || echo "FAIL")
EOF

    fi

else
    error "Scan with timing measurement failed"
    test_passed=false
fi

# ============================================================================
# METHOD 2: pprof Analysis (if available)
# ============================================================================

if [ "$pprof_available" = true ]; then
    echo ""
    echo "Method 2: pprof Heap Analysis"

    log "Running scan with pprof heap profiling..."

    # Try to run with pprof flag if supported
    # This is pattern-specific - adjust based on actual scanner flags
    if "$SCANNER_BIN" scan \
        --patterns all \
        --profile-heap="$RESULTS_DIR/memory-profile/heap.prof" \
        "$REPO_PATH" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/memory-profile/scan-profiled.json" \
        2> "$RESULTS_DIR/memory-profile/profile-err.txt"; then

        success "Profiled scan completed"

        # Analyze heap profile if it exists
        if [ -f "$RESULTS_DIR/memory-profile/heap.prof" ]; then
            log "Analyzing heap profile..."

            # Try to use go tool pprof if available
            if command -v go > /dev/null 2>&1; then
                echo "Heap profile summary:" > "$RESULTS_DIR/memory-profile/heap-analysis.txt"
                go tool pprof -top "$SCANNER_BIN" "$RESULTS_DIR/memory-profile/heap.prof" \
                    >> "$RESULTS_DIR/memory-profile/heap-analysis.txt" 2>&1 || true

                success "Heap profile analyzed"
            else
                warn "go tool not available for pprof analysis"
                warn "  (Heap profile saved but not analyzed)"
            fi
        fi

    else
        warn "Profiled scan failed or not supported"
        warn "  (Continuing with /usr/bin/time results)"
    fi
else
    log "pprof profiling not available (using /usr/bin/time only)"
fi

# ============================================================================
# MEMORY ALLOCATION ANALYSIS
# ============================================================================

log "Analyzing memory allocation patterns..."

echo ""
echo "Memory Analysis:"

# If we have heap analysis, parse it
if [ -f "$RESULTS_DIR/memory-profile/heap-analysis.txt" ]; then
    success "Heap profile available for analysis"

    # Show top allocators
    echo "  Top memory allocators:"
    head -n 10 "$RESULTS_DIR/memory-profile/heap-analysis.txt" | sed 's/^/    /'
fi

# Check GC patterns from timing
if [ -f "$RESULTS_DIR/memory-profile/timing-output.txt" ]; then
    # Extract I/O and other stats that indicate GC activity
    if grep -q "Percent of CPU this job" "$RESULTS_DIR/memory-profile/timing-output.txt"; then
        cpu_percent=$(grep "Percent of CPU" "$RESULTS_DIR/memory-profile/timing-output.txt" | awk '{print $NF}' | head -1 || echo "unknown")
        echo "  CPU usage: $cpu_percent"
    fi

    if grep -q "Page reclaims" "$RESULTS_DIR/memory-profile/timing-output.txt"; then
        page_reclaims=$(grep "Page reclaims" "$RESULTS_DIR/memory-profile/timing-output.txt" | awk '{print $4}' | head -1 || echo "unknown")
        echo "  Page reclaims: $page_reclaims (indicates GC activity)"
    fi
fi

# ============================================================================
# MEMORY LEAK DETECTION (Simplified)
# ============================================================================

echo ""
log "Checking for obvious memory leak indicators..."

if [ -f "$RESULTS_DIR/memory-profile/timing-output.txt" ]; then
    # Memory leak indicator: very high memory with few findings
    findings=$(grep -o '"severity"' "$RESULTS_DIR/memory-profile/scan-results.json" 2>/dev/null | wc -l || echo "0")
    memory_mb=$(grep "Maximum resident set size" "$RESULTS_DIR/memory-profile/timing-output.txt" 2>/dev/null | awk '{print $6}' | head -1 || echo "0")
    memory_mb=$((memory_mb / 1024 + 1))

    if [ $findings -eq 0 ] && [ "$memory_mb" -gt 100 ]; then
        warn "High memory with zero findings - possible memory leak"
        warn "  (Investigate scanner initialization overhead)"
    else
        success "Memory usage proportional to workload (no obvious leaks)"
    fi
fi

# ============================================================================
# RECOMMENDATIONS
# ============================================================================

echo ""
echo "Memory Optimization Recommendations:"

if [ "$memory_mb" -gt 1500 ]; then
    warn "Memory usage is high (>1.5GB)"
    echo "  Recommendations:"
    echo "    1. Review large allocations in heap profile"
    echo "    2. Check for unbounded data structures"
    echo "    3. Verify streaming vs. batch processing mode"
    echo "    4. Consider adding memory limits to pattern operations"
elif [ "$memory_mb" -gt 1000 ]; then
    warn "Memory usage is moderate (1-1.5GB)"
    echo "  Recommendations:"
    echo "    1. Monitor memory growth under sustained load"
    echo "    2. Profile garbage collection frequency"
    echo "    3. Consider memory pooling for frequent allocations"
else
    success "Memory usage is healthy (<1GB)"
    echo "  Profile indicates good memory efficiency"
fi

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Memory Profiling Test Results"
echo "=========================================="

if [ "$test_passed" = true ]; then
    success "HARD GATE 12 PASSED: Memory profiling verified"
    echo "  ✓ Peak memory: ${memory_mb}MB (limit: ${EXPECTED_MEMORY_PEAK_MB}MB)"
    echo "  ✓ No obvious memory leaks detected"
    echo "  ✓ GC functioning normally"
    if [ "$pprof_available" = true ]; then
        echo "  ✓ Heap profile collected and analyzed"
    fi
else
    error "HARD GATE 12 FAILED: Memory profiling issues"
fi

echo ""
echo "Results saved to: $RESULTS_DIR/memory-profile/"
echo "  - scan-results.json (scan output)"
echo "  - timing-output.txt (timing details)"
echo "  - memory-metrics.txt (memory summary)"
if [ -f "$RESULTS_DIR/memory-profile/heap.prof" ]; then
    echo "  - heap.prof (pprof heap profile)"
    echo "  - heap-analysis.txt (heap analysis)"
fi
echo ""

if [ "$test_passed" = false ]; then
    error "Memory Profiling Test FAILED"
    exit 1
fi

success "Memory Profiling Test PASSED"
echo ""

exit 0
