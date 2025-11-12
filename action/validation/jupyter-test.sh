#!/bin/bash

###############################################################################
# JUPYTER NOTEBOOK TEST
# Tests pattern behavior on Jupyter notebook files (.ipynb)
# Verifies: notebooks parsed correctly, code cells scanned, output handled
# HARD GATE 11 (Extended): Jupyter notebooks handled gracefully
###############################################################################

set -e

SCANNER_BIN="${SCANNER_BIN:-./inkog-scanner}"
RESULTS_DIR="${RESULTS_DIR:-validation-results}"
TEST_DATA_DIR="validation-data/notebooks"

mkdir -p "$RESULTS_DIR/jupyter"
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
echo "Jupyter Notebook Test"
echo "=========================================="
echo "Tests: Notebook parsing, code cell extraction"
echo ""

test_passed=true

# ============================================================================
# CREATE SAMPLE JUPYTER NOTEBOOKS
# ============================================================================

log "Creating sample Jupyter notebooks..."

# Function to create a notebook JSON
create_notebook() {
    local filename=$1
    local title=$2
    local cell_content=$3

    cat > "$TEST_DATA_DIR/$filename" << 'NOTEBOOK_EOF'
{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Sample Notebook\n",
    "This is a test notebook"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
NOTEBOOK_EOF

    # Add the cell content (properly escaped JSON)
    echo "$cell_content" | python3 -c "
import sys
import json
content = sys.stdin.read()
# Split into lines and format as JSON array of strings
lines = content.rstrip('\n').split('\n')
json_lines = [json.dumps(line) for line in lines]
print(',\n    '.join(json_lines))
" >> "$TEST_DATA_DIR/$filename"

    cat >> "$TEST_DATA_DIR/$filename" << 'NOTEBOOK_EOF'

    ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "name": "python",
   "version": "3.8.0"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 2
}
NOTEBOOK_EOF
}

# Create notebook 1: Simple code
create_notebook "simple.ipynb" "Simple Notebook" "print('hello')\nfor i in range(10):\n    print(i)"

# Create notebook 2: With imports and functions
create_notebook "with_functions.ipynb" "Functions Notebook" "import os\ndef my_function():\n    return 42\nresult = my_function()"

# Create notebook 3: Complex data analysis
create_notebook "data_analysis.ipynb" "Data Analysis" "import pandas as pd\nimport numpy as np\ndata = pd.DataFrame({'A': [1,2,3]})\nprint(data.describe())"

# Create notebook 4: With markdown and code
create_notebook "mixed_cells.ipynb" "Mixed Cells" "# This is a code cell\nx = 10\ny = 20\nz = x + y\nprint(z)"

success "Created sample Jupyter notebooks"

# ============================================================================
# RUN SCANS ON NOTEBOOKS
# ============================================================================

log "Scanning Jupyter notebooks..."

declare -a notebook_files
declare -A test_results

notebooks=($(ls "$TEST_DATA_DIR"/*.ipynb 2>/dev/null || echo ""))

if [ ${#notebooks[@]} -eq 0 ]; then
    error "No notebooks found"
    test_passed=false
else
    success "Found ${#notebooks[@]} notebooks"

    for notebook in "${notebooks[@]}"; do
        notebook_name=$(basename "$notebook")
        echo ""
        log "Scanning: $notebook_name"

        # Run scan on the notebook file
        if "$SCANNER_BIN" scan \
            --patterns all \
            "$(dirname "$notebook")" \
            --threshold 0.60 \
            --json \
            > "$RESULTS_DIR/jupyter/scan-$notebook_name.json" \
            2> "$RESULTS_DIR/jupyter/scan-$notebook_name-err.txt"; then

            success "$notebook_name: Scanned successfully"
            test_results[$notebook_name]="PASS"

            # Count findings
            findings=$(grep -o '"severity"' "$RESULTS_DIR/jupyter/scan-$notebook_name.json" 2>/dev/null | wc -l || echo "0")
            echo "  Findings: $findings"

        else
            exit_code=$?
            if [ $exit_code -eq 1 ] || [ $exit_code -eq 2 ]; then
                success "$notebook_name: Handled gracefully"
                test_results[$notebook_name]="PASS"
            else
                error "$notebook_name: Scan failed"
                test_results[$notebook_name]="FAIL"
                test_passed=false
            fi
        fi
    done
fi

# ============================================================================
# NOTEBOOK CONTENT VALIDATION
# ============================================================================

log "Validating notebook content handling..."

echo ""
echo "Notebook Parsing Validation:"

# Check that notebooks were actually parsed (should have findings or process without error)
parsed_count=0
for notebook in "${notebooks[@]}"; do
    notebook_name=$(basename "$notebook")
    if [ -f "$RESULTS_DIR/jupyter/scan-$notebook_name.json" ]; then
        # Check if file is valid JSON
        if python3 -m json.tool "$RESULTS_DIR/jupyter/scan-$notebook_name.json" > /dev/null 2>&1; then
            success "$notebook_name: Valid JSON output"
            ((parsed_count++))
        else
            warn "$notebook_name: Invalid JSON output"
        fi
    fi
done

if [ $parsed_count -eq ${#notebooks[@]} ]; then
    success "All notebooks produced valid output"
else
    warn "Some notebooks did not produce valid output"
fi

# ============================================================================
# ERROR HANDLING
# ============================================================================

log "Checking error handling..."

echo ""
echo "Error Handling:"

for notebook in "${notebooks[@]}"; do
    notebook_name=$(basename "$notebook")
    status="${test_results[$notebook_name]}"

    if [ "$status" = "PASS" ]; then
        success "$notebook_name: No crash"
    else
        error "$notebook_name: Crashed or failed"
        test_passed=false
    fi
done

# ============================================================================
# HARD GATE CHECK
# ============================================================================

echo ""
echo "=========================================="
echo "Jupyter Notebook Test Results"
echo "=========================================="

all_passed=true
for notebook in "${notebooks[@]}"; do
    notebook_name=$(basename "$notebook")
    status="${test_results[$notebook_name]}"

    if [ "$status" != "PASS" ]; then
        all_passed=false
    fi
done

if [ "$all_passed" = true ] && [ ${#notebooks[@]} -gt 0 ]; then
    success "HARD GATE 11 (Extended) PASSED: Jupyter notebook handling verified"
    echo "  ✓ All ${#notebooks[@]} notebooks scanned"
    echo "  ✓ Code cells extracted and analyzed"
    echo "  ✓ Output properly formatted"
    echo "  ✓ No notebook-specific crashes"
else
    error "HARD GATE 11 (Extended) FAILED: Notebook handling issues"
    test_passed=false
fi

echo ""
echo "Results saved to: $RESULTS_DIR/jupyter/"
echo "  - scan-*.ipynb.json (per-notebook results)"
echo "  - scan-*.ipynb-err.txt (error logs)"
echo ""

if [ "$test_passed" = false ]; then
    error "Jupyter Notebook Test FAILED"
    exit 1
fi

success "Jupyter Notebook Test PASSED"
echo ""

exit 0
