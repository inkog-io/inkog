# Inkog Scanner Test Results

## Overview

This document describes the testing of the Inkog GitHub Action on real LangChain and CrewAI agents with intentional security vulnerabilities.

## Test Setup

### Test Agents Created

1. **LangChain Agent** (`test-agents/langchain-example/agent.py`)
   - 250+ lines of realistic LangChain code
   - 8 major security vulnerabilities
   - Uses actual LangChain APIs and patterns

2. **CrewAI Agent** (`test-agents/crewai-example/crew.py`)
   - 300+ lines of realistic CrewAI code
   - 8 major security vulnerabilities
   - Multi-agent architecture with tasks

### Vulnerabilities Intentionally Included

#### Category 1: Prompt Injection (CWE-94, CWE-95)

**LangChain Agent:**
```python
# Line 60-67: search_tool function
prompt = f"Please search for the following user query: {query}"
```

```python
# Line 74-76: database_tool function
system_prompt = f"Execute this query from user: {user_input}"
```

```python
# Line 150+: another_prompt_injection function
instruction = f"User instruction: {user_message}"
```

**CrewAI Agent:**
```python
# Lines 78-81: Task descriptions
description=f"Research the topic: {user_topic}. User query: {user_query}"
```

```python
# Lines 145+: another_injection_example function
template = f"""System: Answer this user query: {user_message}..."""
```

**Expected Detection**: ✅ High confidence prompt injection in f-strings and template literals

#### Category 2: Hardcoded API Keys (CWE-798, CWE-259)

**LangChain Agent (Lines 11-12):**
```python
OPENAI_API_KEY = "sk-proj-1234567890abcdefghij1234567890ab"
STRIPE_API_KEY = "sk_live_abcdefghij1234567890abcdefghijkl"
```

**CrewAI Agent (Lines 9-11):**
```python
OPENAI_API_KEY = "sk-proj-abcdefghij1234567890abcdefghijkl"
ANTHROPIC_API_KEY = "sk-ant-1234567890abcdefghij1234567890"
GITHUB_TOKEN = "ghp_1234567890abcdefghij1234567890abcde"
```

**Expected Detection**: ✅ High confidence hardcoded credentials with exact line numbers and recommendations

#### Category 3: Infinite Loops (CWE-835)

**LangChain Agent (Lines 110-120):**
```python
def vulnerable_loop_example():
    while True:
        print(f"Attempt {attempts}")
        # Loop continues with only arbitrary limit
```

**CrewAI Agent (Lines 110-120):**
```python
def run_vulnerable_loop(self):
    while True:
        print(f"Processing iteration {iteration}")
        # Missing proper exit conditions
```

**Expected Detection**: ✅ High confidence infinite loop pattern

#### Category 4: Unbounded Recursion (CWE-674)

**LangChain Agent (Lines 123-132):**
```python
def recursive_agent(depth: int = 0):
    if depth < 100:  # Arbitrary limit
        return recursive_agent(depth + 1)
```

**CrewAI Agent (Lines 124-137):**
```python
def run_recursive_crew_tasks(self, depth: int = 0):
    if depth < 50:  # Arbitrary depth
        self.run_recursive_crew_tasks(depth + 1)
```

**Expected Detection**: ✅ Medium confidence unbounded recursion without clear base case

#### Category 5: Unsafe Environment Access (CWE-665)

**LangChain Agent (Lines 87-88):**
```python
db_password = os.environ["DATABASE_PASSWORD"]  # Will crash if not set
```

**CrewAI Agent (Lines 140-146):**
```python
db_url = os.environ["DATABASE_URL"]  # No fallback
api_keys = {
    "openai": os.environ["OPENAI_KEY"],  # Will fail if not set
}
```

**Expected Detection**: ✅ Medium confidence unsafe environment variable access

## GitHub Actions Test Workflow

The workflow (`.github/workflows/inkog-test.yml`) performs three levels of testing:

### Level 1: Individual Agent Scans

**LangChain Scan:**
```yaml
./inkog-scanner \
  --path ../test-agents/langchain-example \
  --framework langchain \
  --risk-threshold medium \
  --json-report ../langchain-scan-report.json
```

**CrewAI Scan:**
```yaml
./inkog-scanner \
  --path ../test-agents/crewai-example \
  --framework crewai \
  --risk-threshold medium \
  --json-report ../crewai-scan-report.json
```

### Level 2: Comprehensive Multi-Agent Scan

```yaml
./inkog-scanner \
  --path ../test-agents \
  --framework auto-detect \
  --risk-threshold high \
  --json-report ../complete-scan-report.json
```

This tests framework auto-detection and multi-file scanning.

### Level 3: Validation Tests

Checks that:
- ✅ Expected vulnerabilities are detected
- ✅ Risk scores are in expected ranges
- ✅ Findings can be parsed and analyzed
- ✅ JSON reports are valid

## Expected Test Results

### LangChain Agent Scan Results

```json
{
  "risk_score": 78,
  "findings_count": 8,
  "high_risk_count": 5,
  "medium_risk_count": 3,
  "low_risk_count": 0,
  "findings": [
    {
      "pattern": "Prompt Injection via F-String",
      "severity": "high",
      "confidence": 0.85,
      "file": "test-agents/langchain-example/agent.py",
      "line": 63,
      "message": "Potential prompt injection: User input directly interpolated in prompt string"
    },
    {
      "pattern": "Hardcoded API Key",
      "severity": "high",
      "confidence": 0.95,
      "file": "test-agents/langchain-example/agent.py",
      "line": 11,
      "message": "Hardcoded API key detected in source code"
    },
    {
      "pattern": "Infinite While Loop",
      "severity": "high",
      "confidence": 0.90,
      "file": "test-agents/langchain-example/agent.py",
      "line": 112,
      "message": "Infinite loop detected: 'while True' without break condition"
    }
  ]
}
```

### CrewAI Agent Scan Results

```json
{
  "risk_score": 82,
  "findings_count": 9,
  "high_risk_count": 6,
  "medium_risk_count": 3,
  "low_risk_count": 0,
  "findings_count": 9
}
```

### Metrics Summary

| Metric | LangChain | CrewAI | Combined |
|--------|-----------|--------|----------|
| Risk Score | 75-80 | 80-85 | 78-83 |
| Total Findings | 7-9 | 8-10 | 15-19 |
| High Risk | 4-5 | 5-6 | 9-11 |
| Medium Risk | 2-3 | 2-3 | 4-6 |
| Low Risk | 0-1 | 0-1 | 0-2 |
| Files Scanned | 1 | 1 | 2 |
| Lines of Code | 250+ | 300+ | 550+ |
| Scan Duration | <2s | <2s | <3s |

## Running the Tests

### Option 1: GitHub Actions (Automatic)

The workflow runs automatically when:
- Code is pushed to `test-agents/` directory
- Code is pushed to `action/` directory
- Workflow file is modified

**View Results:**
1. Go to https://github.com/inkog-io/inkog/actions
2. Click on `Inkog Security Scan Tests` workflow
3. View the latest run
4. Check artifacts for JSON reports
5. Review job outputs for detailed findings

### Option 2: Local Testing

After installing Go 1.21+:

```bash
cd action
go mod download
go build -o inkog-scanner ./cmd/scanner

# Test LangChain
./inkog-scanner \
  --path ../test-agents/langchain-example \
  --framework langchain \
  --json-report ../langchain-report.json

# View report
cat ../langchain-report.json | jq '.'
```

## Verification Checklist

When tests run, verify:

- [ ] **Parser works correctly**
  - Files are parsed without errors
  - AST generation completes
  - No timeout issues

- [ ] **Pattern detection**
  - At least 1 prompt injection found (expect 3+)
  - At least 1 hardcoded API key found (expect 2+)
  - At least 1 infinite loop found (expect 1)
  - At least 1 unsafe env access found (expect 1)

- [ ] **Risk scoring**
  - LangChain risk score: 75-85
  - CrewAI risk score: 78-88
  - Combined risk score: 75-85

- [ ] **Output formats**
  - JSON reports are valid and parseable
  - GitHub annotations display correctly in PR
  - All findings have required fields

- [ ] **Performance**
  - LangChain scan: <2 seconds
  - CrewAI scan: <2 seconds
  - Combined scan: <3 seconds

- [ ] **Framework detection**
  - Auto-detect correctly identifies langchain
  - Auto-detect correctly identifies crewai
  - Falls back to "unknown" if no indicators found

## Analysis Commands

To analyze the test results after they run:

```bash
# Download the reports from artifacts
# Then analyze with these commands:

# View full report
cat langchain-report.json | jq '.'

# Get summary metrics
jq '{risk_score, findings_count, high_risk_count, medium_risk_count}' langchain-report.json

# List all findings with pattern and severity
jq '.findings[] | {pattern, severity, confidence, line}' langchain-report.json

# Find specific pattern types
jq '.findings[] | select(.pattern | contains("Prompt"))' langchain-report.json

# Count by severity
jq '[.findings[].severity] | group_by(.) | map({severity: .[0], count: length})' langchain-report.json

# Get findings above certain confidence
jq '.findings[] | select(.confidence > 0.85)' langchain-report.json
```

## Key Successes Expected

✅ **Prompt Injection Detection**: Scanner should identify f-string interpolations with suspicious patterns like "prompt", "query", "user_input" combined with variable interpolation

✅ **Credential Detection**: Regex patterns should match hardcoded API keys, secret keys, and tokens based on length and format

✅ **Loop Pattern Detection**: AST analysis should identify while True loops without break conditions

✅ **Framework Auto-Detection**: Should correctly identify LangChain and CrewAI frameworks based on imports and patterns

✅ **Performance**: Scans should complete in <3 seconds for test agents (~550 LOC total)

✅ **JSON Output**: Reports should be properly formatted with all required fields and valid JSON

## Potential Issues & Solutions

### Issue: No findings detected

**Cause**: Parser not recognizing Python syntax correctly
**Solution**: Verify tree-sitter Python grammar is loaded correctly

### Issue: False positives in safe code

**Cause**: Overly broad pattern matching
**Solution**: Increase confidence thresholds, add context analysis

### Issue: Slow scan performance

**Cause**: Sequential file processing instead of concurrent
**Solution**: Verify concurrent semaphore is working (should use 4-way parallelization)

### Issue: Wrong framework detected

**Cause**: Framework detection logic needs refinement
**Solution**: Check detection logic in `main.go` around line 120

## Next Steps

1. **Run the tests** on GitHub Actions
2. **Analyze the results** using commands above
3. **Verify all expected vulnerabilities** are detected
4. **Document any false positives** or missed detections
5. **Refine patterns** based on findings
6. **Add more test cases** for edge cases
7. **Test on real-world agents** from users
8. **Optimize performance** if needed
9. **Prepare case study** for marketing

## Success Criteria

✅ All 3 pattern detectors working
✅ Risk scores in expected range (75-85)
✅ Scan completes in <3 seconds
✅ JSON reports are valid and complete
✅ GitHub annotations display correctly
✅ No crashes or errors
✅ Framework detection working

---

**Status**: Ready for testing on GitHub Actions
**Last Updated**: 2024-11-04
**Test Files**: LangChain + CrewAI agents with 15+ intentional vulnerabilities
