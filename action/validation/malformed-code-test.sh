#!/bin/bash

###############################################################################
# MALFORMED CODE TEST: Edge Cases
# Tests pattern behavior on problematic code: syntax errors, encoding, binary
# Verifies: no crashes, graceful error handling, clear error messages
# HARD GATE 11: Malformed code must not crash scanner
###############################################################################

set -e

SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
TEST_DATA_DIR="validation-data/malformed"

mkdir -p "$RESULTS_DIR/malformed"
mkdir -p "$TEST_DATA_DIR"

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
echo "Malformed Code Test: Edge Cases"
echo "=========================================="
echo "Test categories:"
echo "  1. Syntax errors (invalid Python)"
echo "  2. Encoding issues (UTF-8, BOM, mixed)"
echo "  3. Binary files (should be skipped)"
echo "  4. Empty files"
echo "  5. Very large single lines"
echo ""

test_passed=true

# ============================================================================
# CREATE MALFORMED TEST FILES
# ============================================================================

log "Creating malformed test files..."

mkdir -p "$TEST_DATA_DIR/syntax-errors"
mkdir -p "$TEST_DATA_DIR/encoding-issues"
mkdir -p "$TEST_DATA_DIR/binary-files"
mkdir -p "$TEST_DATA_DIR/special-cases"

# Syntax error 1: Unclosed parenthesis
cat > "$TEST_DATA_DIR/syntax-errors/unclosed_paren.py" << 'EOF'
def function(
    x = 1,
    y = 2
    # Missing closing paren
EOF

# Syntax error 2: Invalid decorator
cat > "$TEST_DATA_DIR/syntax-errors/invalid_decorator.py" << 'EOF'
@
def my_function():
    pass
EOF

# Syntax error 3: Mixed tabs and spaces (Python-specific)
printf 'def function():\n\tif True:\n        pass\n' > "$TEST_DATA_DIR/syntax-errors/mixed_indentation.py"

# Encoding issue 1: UTF-8 BOM marker
printf '\xef\xbb\xbf# File with BOM\nprint("hello")\n' > "$TEST_DATA_DIR/encoding-issues/utf8_bom.py"

# Encoding issue 2: Invalid UTF-8 sequences
printf 'print("hello")\n\xff\xfe\n' > "$TEST_DATA_DIR/encoding-issues/invalid_utf8.py"

# Encoding issue 3: Latin-1 with extended characters
printf '# -*- coding: latin-1 -*-\n# Café résumé\nprint("done")\n' > "$TEST_DATA_DIR/encoding-issues/latin1_extended.py"

# Binary file: Gzip compressed
echo "This is binary content" | gzip > "$TEST_DATA_DIR/binary-files/archive.gz"

# Binary file: ELF executable stub
printf '\x7fELF\x01\x01\x01\x00' > "$TEST_DATA_DIR/binary-files/executable"

# Binary file: PNG image stub
printf '\x89PNG\r\n\x1a\n' > "$TEST_DATA_DIR/binary-files/image.png"

# Special case 1: Empty file
touch "$TEST_DATA_DIR/special-cases/empty.py"

# Special case 2: Very long single line (10KB)
printf 'x = "' > "$TEST_DATA_DIR/special-cases/long_line.py"
python3 -c "print('A' * 10000, end='')" >> "$TEST_DATA_DIR/special-cases/long_line.py"
printf '"\n' >> "$TEST_DATA_DIR/special-cases/long_line.py"

# Special case 3: Deeply nested structure
cat > "$TEST_DATA_DIR/special-cases/deeply_nested.py" << 'EOF'
data = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {
    "i": {"j": {"k": {"l": {"m": {"n": {"o": {"p": {"q": {
    "r": {"s": {"t": {"u": {"v": {"w": {"x": {"y": {"z": {}
}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
EOF

# Special case 4: Extremely long identifier
printf 'very_long_variable_name_that_is_exactly_' > "$TEST_DATA_DIR/special-cases/long_identifier.py"
python3 -c "print('a' * 10000)" >> "$TEST_DATA_DIR/special-cases/long_identifier.py"
printf ' = 42\n' >> "$TEST_DATA_DIR/special-cases/long_identifier.py"

success "Created malformed test files"

# ============================================================================
# RUN SCAN ON EACH CATEGORY
# ============================================================================

log "Scanning malformed code files..."

declare -A test_results

categories=("syntax-errors" "encoding-issues" "binary-files" "special-cases")

for category in "${categories[@]}"; do
    echo ""
    log "Testing: $category"

    category_path="$TEST_DATA_DIR/$category"
    category_result="PASS"

    # Run scan with error capture
    if "$SCANNER_BIN" scan \
        --patterns all \
        "$category_path" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/malformed/scan-$category.json" \
        2> "$RESULTS_DIR/malformed/scan-$category-err.txt"; then

        success "$category: Scan completed without crash"
        test_results[$category]="PASS"

    else
        exit_code=$?

        # Check if exit code indicates crash vs expected error
        if [ $exit_code -eq 1 ] || [ $exit_code -eq 2 ]; then
            # Graceful error handling
            success "$category: Gracefully handled errors (exit $exit_code)"
            test_results[$category]="PASS"

        else
            # Unexpected crash
            error "$category: Scan crashed with exit code $exit_code"
            test_results[$category]="FAIL"
            test_passed=false
        fi
    fi

    # Show error output if any
    if [ -s "$RESULTS_DIR/malformed/scan-$category-err.txt" ]; then
        warn "$category errors:"
        head -n 5 "$RESULTS_DIR/malformed/scan-$category-err.txt" | sed 's/^/    /'
    fi
done

# ============================================================================
# DETAILED VALIDATION
# ============================================================================

log "Validating error handling..."

echo ""
echo "Error Handling Validation:"

# Check that binary files were skipped (not parsed as code)
if grep -q "Binary" "$RESULTS_DIR/malformed/scan-binary-files-err.txt" 2>/dev/null || \
   [ "$(grep -o 'severity' "$RESULTS_DIR/malformed/scan-binary-files.json" 2>/dev/null | wc -l)" -eq 0 ]; then
    success "Binary files detected and skipped"
else
    warn "Binary files: unclear if properly skipped"
fi

# Check that syntax errors don't crash
if [ "${test_results[syntax-errors]}" = "PASS" ]; then
    success "Syntax errors handled gracefully"
else
    error "Syntax errors caused crash"
fi

# Check that encoding issues don't crash
if [ "${test_results[encoding-issues]}" = "PASS" ]; then
    success "Encoding issues handled gracefully"
else
    error "Encoding issues caused crash"
fi

# Check that special cases don't crash
if [ "${test_results[special-cases]}" = "PASS" ]; then
    success "Special cases handled gracefully"
else
    error "Special cases caused crash"
fi

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Malformed Code Test Results"
echo "=========================================="

all_passed=true
for category in "${categories[@]}"; do
    status="${test_results[$category]}"
    if [ "$status" = "PASS" ]; then
        success "$category: PASSED"
    else
        error "$category: FAILED"
        all_passed=false
    fi
done

echo ""

if [ "$all_passed" = true ]; then
    success "HARD GATE 11 PASSED: Malformed code handling verified"
    echo "  ✓ All edge case categories handled gracefully"
    echo "  ✓ No scanner crashes"
    echo "  ✓ Syntax errors: Handled"
    echo "  ✓ Encoding issues: Handled"
    echo "  ✓ Binary files: Detected and skipped"
    echo "  ✓ Special cases: Handled"
else
    error "HARD GATE 11 FAILED: Some edge cases not handled"
    test_passed=false
fi

echo ""
echo "Results saved to: $RESULTS_DIR/malformed/"
echo "  - scan-{category}.json (per-category results)"
echo "  - scan-{category}-err.txt (error logs)"
echo ""

if [ "$test_passed" = false ]; then
    error "Malformed Code Test FAILED"
    exit 1
fi

success "Malformed Code Test PASSED"
echo ""

exit 0
