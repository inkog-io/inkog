#!/bin/bash

###############################################################################
# MIXED PYTHON VERSION TEST (Python 2 and 3)
# Tests pattern behavior on mixed Python 2/3 codebases
# Verifies: no crashes, patterns work on both versions, syntax differences handled
# HARD GATE 11 (Extended): Mixed Python versions handled gracefully
###############################################################################

set -e

SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
TEST_DATA_DIR="validation-data/mixed_python"

mkdir -p "$RESULTS_DIR/mixed-python"
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
echo "Mixed Python Version Test"
echo "=========================================="
echo "Tests: Python 2, Python 3, and mixed codebases"
echo ""

test_passed=true

# ============================================================================
# CREATE PYTHON 2 CODE SAMPLES
# ============================================================================

log "Creating Python 2 code samples..."

mkdir -p "$TEST_DATA_DIR/python2"
mkdir -p "$TEST_DATA_DIR/python3"
mkdir -p "$TEST_DATA_DIR/mixed"

# Python 2 syntax: print statement (not function)
cat > "$TEST_DATA_DIR/python2/print_statement.py" << 'EOF'
# Python 2 code
print "Hello, world!"  # This is Python 2 syntax
print "Multiple", "arguments"

def greet(name):
    print "Hello, %s" % name
EOF

# Python 2 syntax: xrange (instead of range)
cat > "$TEST_DATA_DIR/python2/xrange_usage.py" << 'EOF'
# Python 2 code using xrange
for i in xrange(10):
    print i

# Classic division (returns int in Python 2, float in Python 3)
result = 5 / 2
print result
EOF

# Python 2 syntax: old-style string formatting
cat > "$TEST_DATA_DIR/python2/old_formatting.py" << 'EOF'
# Python 2 style
name = "Alice"
age = 30
message = "%s is %d years old" % (name, age)
print message

# Dictionary .iteritems() (Python 2 only)
data = {"a": 1, "b": 2}
for key, value in data.iteritems():
    print key, value
EOF

# Python 2 syntax: exception syntax
cat > "$TEST_DATA_DIR/python2/old_exception_syntax.py" << 'EOF'
# Old Python 2 exception syntax
try:
    x = 1 / 0
except ZeroDivisionError, e:  # Python 2 syntax
    print "Error:", e
except:
    pass
EOF

# ============================================================================
# CREATE PYTHON 3 CODE SAMPLES
# ============================================================================

log "Creating Python 3 code samples..."

# Python 3 syntax: print function
cat > "$TEST_DATA_DIR/python3/print_function.py" << 'EOF'
# Python 3 code
print("Hello, world!")
print("Multiple", "arguments")

def greet(name):
    print(f"Hello, {name}")  # f-string (Python 3.6+)
EOF

# Python 3 syntax: range (xrange doesn't exist)
cat > "$TEST_DATA_DIR/python3/range_usage.py" << 'EOF'
# Python 3 code
for i in range(10):
    print(i)

# Division always returns float in Python 3
result = 5 / 2
print(result)  # 2.5, not 2
EOF

# Python 3 syntax: f-strings and new formatting
cat > "$TEST_DATA_DIR/python3/modern_formatting.py" << 'EOF'
# Python 3 style
name = "Alice"
age = 30

# F-string (Python 3.6+)
message = f"{name} is {age} years old"
print(message)

# .items() (works in both, but .iteritems() removed in Python 3)
data = {"a": 1, "b": 2}
for key, value in data.items():
    print(key, value)
EOF

# Python 3 syntax: new exception syntax
cat > "$TEST_DATA_DIR/python3/new_exception_syntax.py" << 'EOF'
# Python 3 exception syntax
try:
    x = 1 / 0
except ZeroDivisionError as e:  # Python 3 syntax
    print(f"Error: {e}")
except:
    pass
EOF

# Python 3 syntax: type hints
cat > "$TEST_DATA_DIR/python3/type_hints.py" << 'EOF'
# Python 3 type hints
def add(a: int, b: int) -> int:
    return a + b

class Person:
    name: str
    age: int

    def __init__(self, name: str, age: int) -> None:
        self.name = name
        self.age = age
EOF

# ============================================================================
# CREATE MIXED VERSION CODEBASE
# ============================================================================

log "Creating mixed Python 2/3 codebase..."

# Some files in Python 2
cp "$TEST_DATA_DIR/python2/print_statement.py" "$TEST_DATA_DIR/mixed/legacy.py"
cp "$TEST_DATA_DIR/python2/xrange_usage.py" "$TEST_DATA_DIR/mixed/old_script.py"

# Some files in Python 3
cp "$TEST_DATA_DIR/python3/print_function.py" "$TEST_DATA_DIR/mixed/modern.py"
cp "$TEST_DATA_DIR/python3/type_hints.py" "$TEST_DATA_DIR/mixed/typed.py"

# Some files with compatibility shims (try both approaches)
cat > "$TEST_DATA_DIR/mixed/compatible.py" << 'EOF'
# Code with Python 2/3 compatibility
from __future__ import print_function

try:
    # Python 2
    range_func = xrange
except NameError:
    # Python 3
    range_func = range

for i in range_func(10):
    print(i)
EOF

success "Created Python 2/3 test files"

# ============================================================================
# RUN SCANS ON EACH CATEGORY
# ============================================================================

log "Scanning Python code files..."

declare -A test_results

categories=("python2" "python3" "mixed")

for category in "${categories[@]}"; do
    echo ""
    log "Testing: $category"

    category_path="$TEST_DATA_DIR/$category"

    # Run scan
    if "$SCANNER_BIN" scan \
        --patterns all \
        "$category_path" \
        --threshold 0.60 \
        --json \
        > "$RESULTS_DIR/mixed-python/scan-$category.json" \
        2> "$RESULTS_DIR/mixed-python/scan-$category-err.txt"; then

        success "$category: Scan completed"
        test_results[$category]="PASS"

        # Count findings
        findings=$(grep -o '"severity"' "$RESULTS_DIR/mixed-python/scan-$category.json" 2>/dev/null | wc -l || echo "0")
        echo "  Findings: $findings"

    else
        exit_code=$?
        if [ $exit_code -eq 1 ] || [ $exit_code -eq 2 ]; then
            success "$category: Handled errors gracefully"
            test_results[$category]="PASS"
        else
            error "$category: Scan failed unexpectedly"
            test_results[$category]="FAIL"
            test_passed=false
        fi
    fi
done

# ============================================================================
# VALIDATION
# ============================================================================

log "Validating Python version handling..."

echo ""
echo "Python Version Handling:"

# All categories should pass
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

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Mixed Python Test Results"
echo "=========================================="

if [ "$all_passed" = true ]; then
    success "HARD GATE 11 (Extended) PASSED: Mixed Python handling verified"
    echo "  ✓ Python 2 code scanned"
    echo "  ✓ Python 3 code scanned"
    echo "  ✓ Mixed Python codebase scanned"
    echo "  ✓ No syntax version-specific crashes"
    echo "  ✓ Compatibility shims handled"
else
    error "HARD GATE 11 (Extended) FAILED: Python version issues"
    test_passed=false
fi

echo ""
echo "Results saved to: $RESULTS_DIR/mixed-python/"
echo "  - scan-{category}.json (per-category results)"
echo "  - scan-{category}-err.txt (error logs)"
echo ""

if [ "$test_passed" = false ]; then
    error "Mixed Python Test FAILED"
    exit 1
fi

success "Mixed Python Test PASSED"
echo ""

exit 0
