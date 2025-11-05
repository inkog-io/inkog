# Test Agent Examples

This directory contains realistic LangChain and CrewAI agents with intentional security vulnerabilities for testing the Inkog scanner.

## Purpose

These test agents demonstrate common security issues found in AI agent code:

### Vulnerabilities Included

#### 1. Prompt Injection (CWE-94, CWE-95)
- **File**: Both `langchain-example/agent.py` and `crewai-example/crew.py`
- **Lines**: Search for f-string interpolations in prompt/task descriptions
- **Issue**: User input directly interpolated without sanitization
- **Impact**: Attackers can manipulate agent behavior through input

#### 2. Hardcoded API Keys (CWE-798, CWE-259)
- **File**: Both test agents
- **Example Keys**: `OPENAI_API_KEY`, `STRIPE_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`
- **Issue**: Sensitive credentials stored in source code
- **Impact**: Exposed credentials can be used by attackers

#### 3. Infinite Loops (CWE-835)
- **File**: Both test agents
- **Example**: `vulnerable_loop_example()` in LangChain, `run_vulnerable_loop()` in CrewAI
- **Issue**: Unbounded loops without proper termination conditions
- **Impact**: Resource exhaustion, DoS attacks

#### 4. Unbounded Recursion (CWE-674)
- **File**: Both test agents
- **Example**: `recursive_agent()` in LangChain, `run_recursive_crew_tasks()` in CrewAI
- **Issue**: Recursive functions without clear base cases
- **Impact**: Stack overflow, memory exhaustion

#### 5. Unsafe Environment Variable Access (CWE-665)
- **File**: Both test agents
- **Example**: `os.environ["DATABASE_PASSWORD"]` without default
- **Issue**: Direct dictionary access without fallback values
- **Impact**: Crashes if environment variables not set

## Running Local Tests

### Prerequisites

```bash
cd ../action
go mod download
go build -o inkog-scanner ./cmd/scanner
```

### Test LangChain Agent

```bash
cd ../action
./inkog-scanner \
  --path ../test-agents/langchain-example \
  --framework langchain \
  --risk-threshold medium \
  --json-report langchain-report.json
```

**Expected Output:**
- Multiple high-risk findings for prompt injection
- High-risk findings for hardcoded API keys
- Medium-risk findings for unsafe environment access
- Risk score should be in 70-85 range

### Test CrewAI Agent

```bash
cd ../action
./inkog-scanner \
  --path ../test-agents/crewai-example \
  --framework crewai \
  --risk-threshold medium \
  --json-report crewai-report.json
```

**Expected Output:**
- Similar to LangChain, multiple prompt injection risks
- Hardcoded API keys detected
- Loop/recursion patterns identified
- Risk score should be in 75-90 range

### Test All Agents

```bash
cd ../action
./inkog-scanner \
  --path ../test-agents \
  --framework auto-detect \
  --json-report complete-report.json
```

## Analyzing Results

### View JSON Report

```bash
# Pretty print the JSON report
cat langchain-report.json | jq '.'

# Extract specific metrics
jq '.risk_score' langchain-report.json
jq '.findings_count' langchain-report.json
jq '.high_risk_count' langchain-report.json

# View all findings
jq '.findings' langchain-report.json

# View specific finding types
jq '.findings[] | select(.pattern == "Prompt Injection via F-String")' langchain-report.json
```

## Expected Findings Summary

### LangChain Agent

| Pattern | Expected Count | Severity |
|---------|----------------|----------|
| Prompt Injection | 3-4 | High |
| Hardcoded API Keys | 2-3 | High |
| Hardcoded Passwords | 1 | High |
| Unsafe Environment Access | 1 | Medium |
| Infinite Loop | 1 | High |
| Unbounded Recursion | 1 | Medium |

**Expected Risk Score**: 75-85/100

### CrewAI Agent

| Pattern | Expected Count | Severity |
|---------|----------------|----------|
| Prompt Injection | 3-4 | High |
| Hardcoded API Keys | 3-4 | High |
| Infinite Loop | 1 | High |
| Unbounded Recursion | 1 | High |
| Unsafe Environment Access | 1 | Medium |

**Expected Risk Score**: 80-90/100

## GitHub Actions Integration

The test workflow (`.github/workflows/inkog-test.yml`) will:

1. Build the scanner for each push to test agents
2. Run scans on both LangChain and CrewAI examples
3. Generate JSON reports
4. Upload artifacts for review
5. Create a summary in the workflow run

## Safe Examples

Both test files include `safe_*` functions showing the correct way to handle:
- **Safe Prompt Handling**: Use sanitization or parameterized approaches
- **Safe Credential Management**: Use environment variables with defaults
- **Safe Loops**: Add proper break conditions
- **Safe Recursion**: Define clear base cases

Study these examples for best practices!

## Next Steps

1. **Add More Patterns**: Create agents with additional vulnerability types
2. **Test Framework Detection**: Verify auto-detection works for each framework
3. **Performance Testing**: Measure scan time on larger codebases
4. **Integration Testing**: Test with real LangChain/CrewAI projects
5. **Regression Testing**: Keep these agents for future comparisons

## Important Note

⚠️ **These are intentionally vulnerable code samples for testing purposes only!**

Never use patterns from these agents in production. Always follow security best practices:
- Store credentials in environment variables or secrets management
- Sanitize user input before using in prompts
- Implement proper loop termination conditions
- Define clear recursion base cases
- Use environment variable `.get()` with defaults
