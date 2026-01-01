#!/bin/bash
#
# Inkog E2E Verification Script
#
# Verifies the complete CLI → Backend pipeline works for both:
# - Python agents (CrewAI, AutoGen, LangChain)
# - No-Code JSON workflows (n8n, Flowise)
#
# Usage:
#   ./scripts/e2e_verify.sh                    # Uses local backend (localhost:8080)
#   INKOG_API_URL=https://api.inkog.io ./scripts/e2e_verify.sh  # Uses production
#
set -e

# Configuration
DEMO_REPO="https://github.com/inkog-io/demo_agent.git"
DEMO_DIR="/tmp/inkog_e2e_demo"
CLI_BINARY="./inkog"
API_URL="${INKOG_API_URL:-http://localhost:8080}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "    Inkog E2E Verification"
echo "========================================"
echo ""
echo "API URL: $API_URL"
echo ""

# Step 1: Clone or update demo agent
echo -e "${YELLOW}[1/5]${NC} Preparing demo_agent..."
if [ -d "$DEMO_DIR" ]; then
    echo "      Updating existing clone..."
    git -C "$DEMO_DIR" pull --quiet 2>/dev/null || true
else
    echo "      Cloning fresh copy..."
    git clone --quiet "$DEMO_REPO" "$DEMO_DIR" 2>/dev/null || {
        echo -e "${RED}WARN${NC}: Could not clone demo_agent. Using local test files."
        # Create minimal test files if clone fails
        mkdir -p "$DEMO_DIR"
        cat > "$DEMO_DIR/agent.py" << 'PYEOF'
# Vulnerable Python agent
import os

api_key = "AKIA1234567890123456"  # Hardcoded AWS key
github_token = "ghp_abcdefghij1234567890abcdefghij123456"

def infinite_loop():
    while True:  # No exit condition
        pass
PYEOF
        cat > "$DEMO_DIR/workflow.json" << 'JSONEOF'
{
  "name": "Vulnerable n8n Workflow",
  "nodes": [
    {
      "name": "HTTP Request",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://api.example.com",
        "authentication": "none",
        "password": "SuperSecretPassword12345!"
      }
    }
  ],
  "credentials": {
    "aws_access_key": "AKIA9876543210987654"
  }
}
JSONEOF
    }
fi
echo -e "${GREEN}      Done${NC}"

# Inject known vulnerable artifact for deterministic testing
echo "      Injecting test artifact (vulnerable_flow.n8n.json)..."
cat > "$DEMO_DIR/vulnerable_flow.n8n.json" << 'N8NEOF'
{
  "nodes": [
    {
      "parameters": {},
      "type": "n8n-nodes-base.loop",
      "id": "loop-1",
      "name": "Infinite Loop",
      "typeVersion": 1,
      "position": [100, 100]
    },
    {
      "parameters": {
        "model": "gpt-4"
      },
      "type": "@n8n/n8n-nodes-langchain.agent",
      "id": "agent-1",
      "name": "AI Agent",
      "typeVersion": 1,
      "position": [300, 100]
    }
  ],
  "connections": {
    "Infinite Loop": {
      "main": [
        [{"node": "AI Agent", "type": "main", "index": 0}]
      ]
    },
    "AI Agent": {
      "main": [
        [{"node": "Infinite Loop", "type": "main", "index": 0}]
      ]
    }
  }
}
N8NEOF

# Step 2: Build CLI
echo -e "${YELLOW}[2/5]${NC} Building CLI..."
go build -o "$CLI_BINARY" cmd/inkog/main.go
echo -e "${GREEN}      Built: $CLI_BINARY${NC}"

# Step 3: Run scan
echo -e "${YELLOW}[3/5]${NC} Running scan against $API_URL..."

# Capture both stdout and exit code
set +e
RESULT=$("$CLI_BINARY" -path "$DEMO_DIR" -server "$API_URL" -output json 2>/dev/null)
SCAN_EXIT=$?
set -e

if [ -z "$RESULT" ]; then
    echo -e "${RED}      ERROR: Empty response from scan${NC}"
    echo "      This may indicate the backend is unreachable."
    echo ""
    echo "      Try:"
    echo "        1. Ensure backend is running at $API_URL"
    echo "        2. Check network connectivity"
    echo ""
    exit 2
fi

# Step 4: Parse results
echo -e "${YELLOW}[4/5]${NC} Parsing results..."

# Helper function to parse JSON (uses jq if available, falls back to python3)
json_query() {
    local query="$1"
    if command -v jq &> /dev/null; then
        echo "$RESULT" | jq -r "$query" 2>/dev/null
    else
        # Python fallback for environments without jq
        echo "$RESULT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('all_findings') or data.get('findings') or []
query = '$query'
if '.py' in query:
    print(len([f for f in findings if f.get('file', '').endswith('.py')]))
elif '.json' in query:
    print(len([f for f in findings if f.get('file', '').endswith('.json')]))
elif 'length' in query:
    print(len(findings))
else:
    print(0)
" 2>/dev/null
    fi
}

# Check if we have valid JSON
if command -v jq &> /dev/null; then
    if ! echo "$RESULT" | jq . > /dev/null 2>&1; then
        echo -e "${RED}      ERROR: Invalid JSON response${NC}"
        echo "      Raw output:"
        echo "$RESULT" | head -20
        exit 2
    fi
else
    if ! echo "$RESULT" | python3 -c "import json, sys; json.load(sys.stdin)" 2>/dev/null; then
        echo -e "${RED}      ERROR: Invalid JSON response${NC}"
        echo "      Raw output:"
        echo "$RESULT" | head -20
        exit 2
    fi
fi

# Count findings by file type
PYTHON_FINDINGS=$(json_query '.py')
JSON_FINDINGS=$(json_query '.json')
TOTAL_FINDINGS=$(json_query 'length')

echo -e "${GREEN}      Parsed successfully${NC}"

# Step 5: Verify findings
echo -e "${YELLOW}[5/5]${NC} Verifying findings..."
echo ""
echo "========================================"
echo "           RESULTS"
echo "========================================"
echo ""
echo "  Python findings (.py):   $PYTHON_FINDINGS"
echo "  JSON findings (.json):   $JSON_FINDINGS"
echo "  Total findings:          $TOTAL_FINDINGS"
echo ""
echo "========================================"

# Determine success/failure
SUCCESS=true
WARNINGS=""

if [ "$PYTHON_FINDINGS" -eq 0 ]; then
    SUCCESS=false
    WARNINGS="${WARNINGS}\n  - No Python findings (agent.py support broken?)"
fi

if [ "$JSON_FINDINGS" -eq 0 ]; then
    SUCCESS=false
    WARNINGS="${WARNINGS}\n  - No JSON findings (workflow.json support broken?)"
fi

if [ "$SUCCESS" = true ]; then
    echo ""
    echo -e "${GREEN}SUCCESS: Both Python AND JSON vulnerabilities detected${NC}"
    echo ""
    echo "The CLI is correctly feeding the Universal Logic Engine."
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}FAILURE: Missing expected findings${NC}"
    echo -e "$WARNINGS"
    echo ""
    echo "Debug: Check the following:"
    echo "  1. Is the backend running at $API_URL?"
    echo "  2. Does demo_agent contain both .py and .json files?"
    echo "  3. Are the patterns detecting secrets correctly?"
    echo ""

    # Show a sample of findings for debugging
    echo "Sample findings (first 3):"
    if command -v jq &> /dev/null; then
        echo "$RESULT" | jq '.all_findings // .findings // [] | .[0:3]' 2>/dev/null || echo "(none)"
    else
        echo "$RESULT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('all_findings') or data.get('findings') or []
for f in findings[:3]:
    print(json.dumps(f, indent=2))
" 2>/dev/null || echo "(none)"
    fi
    echo ""
    exit 1
fi
