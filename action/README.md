# Inkog GitHub Action

A production-ready AI agent security scanner that detects behavioral risks before deployment.

## Features

- ✅ **3 Security Patterns**: Prompt injection, infinite loops, API key exposure
- ✅ **Fast AST Parsing**: tree-sitter (36x faster than alternatives)
- ✅ **Multi-Framework**: Auto-detects LangChain, CrewAI, AutoGen
- ✅ **GitHub Integration**: Automatic PR annotations + JSON reports
- ✅ **Enterprise-Grade**: Concurrent processing, <10s scan time for 10K LoC
- ✅ **Zero Configuration**: Auto-detect framework and scan intelligently

## Usage

### Quick Start

Add to your GitHub workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  inkog-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Inkog Scanner
        uses: inkog-io/inkog@v1
        with:
          risk-threshold: high
          path: ./
```

### Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `risk-threshold` | Fail on: `low`, `medium`, or `high` risk | `high` | No |
| `framework` | Framework: `auto-detect`, `langchain`, `crewai`, `autogen` | `auto-detect` | No |
| `path` | Directory to scan | `.` | No |
| `json-report` | JSON report output file | `` | No |

### Outputs

| Output | Description |
|--------|-------------|
| `risk-score` | Overall risk score (0-100) |
| `findings-count` | Total number of findings |
| `high-risk-count` | Number of high-risk findings |
| `report-path` | Path to JSON report |

### Example with Outputs

```yaml
- name: Run Inkog Scanner
  id: inkog
  uses: inkog-io/inkog@v1
  with:
    risk-threshold: medium
    json-report: ./inkog-report.json

- name: Check Results
  run: |
    echo "Risk Score: ${{ steps.inkog.outputs.risk-score }}"
    echo "Findings: ${{ steps.inkog.outputs.findings-count }}"
    echo "High Risk: ${{ steps.inkog.outputs.high-risk-count }}"
```

## Detected Patterns

### 1. Prompt Injection (CWE-94, CWE-95)

Detects when user input is directly interpolated into prompt strings without sanitization.

**Example (High Risk):**
```python
# ❌ Dangerous
user_input = request.args.get('query')
prompt = f"Answer the question: {user_input}"

# ✅ Safe
user_input = sanitize_input(request.args.get('query'))
prompt = f"Answer the question: {user_input}"
```

### 2. Infinite Loops (CWE-835)

Identifies infinite loops and unbounded recursion patterns.

**Example (High Risk):**
```python
# ❌ Dangerous
while True:
    process_agent()
    # No break condition!

# ✅ Safe
while True:
    result = process_agent()
    if result.is_complete:
        break
```

### 3. API Key Exposure (CWE-798, CWE-259)

Finds hardcoded credentials and insecure environment variable access.

**Example (High Risk):**
```python
# ❌ Dangerous
api_key = "sk-1234567890abcdefghij"
openai.api_key = api_key

# ✅ Safe
api_key = os.environ.get('OPENAI_API_KEY')
if not api_key:
    raise ValueError("OPENAI_API_KEY not set")
openai.api_key = api_key
```

## Local Testing

### Build

```bash
cd action
go build -o inkog-scanner ./cmd/scanner
```

### Test Scan

```bash
./inkog-scanner --path ../path/to/agent --json-report report.json
```

### Docker Build

```bash
docker build -t inkog:latest .
docker run -v $(pwd):/workspace inkog:latest --path /workspace
```

## Output Examples

### GitHub Actions Annotation

```
::warning file=agent.py,line=23::Prompt Injection: Potential prompt injection vulnerability detected (confidence: 85%)
::error file=agent.py,line=45::Infinite Loop: High risk: Infinite loop pattern detected (confidence: 90%)
```

### JSON Report

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "framework": "langchain",
  "risk_score": 73,
  "findings_count": 2,
  "high_risk_count": 2,
  "medium_risk_count": 0,
  "low_risk_count": 0,
  "scan_duration": "2.5s",
  "files_scanned": 8,
  "lines_of_code": 2150,
  "findings": [
    {
      "id": "prompt_injection_fstring",
      "pattern": "Prompt Injection via F-String",
      "severity": "high",
      "confidence": 0.85,
      "file": "agent.py",
      "line": 23,
      "column": 10,
      "message": "Potential prompt injection: User input directly interpolated in prompt string",
      "remediation": "Use parameterized prompts or sanitize user input before interpolation",
      "cwe_identifiers": ["CWE-94", "CWE-95"]
    }
  ]
}
```

## Performance

- **Startup Time**: 0.88ms (single binary)
- **Parsing**: 36x faster than regex-based alternatives (tree-sitter)
- **Scan Time**: <10 seconds for 10,000 lines of code
- **Memory**: ~50MB for typical scans
- **Concurrent Processing**: 4-way parallelization

## Supported Frameworks

- ✅ LangChain (Python, JavaScript)
- ✅ CrewAI (Python)
- ✅ AutoGen (Python)
- ✅ Custom Python/TypeScript agents
- 🔄 More coming soon

## Supported Languages

- ✅ Python (.py)
- ✅ JavaScript (.js)
- ✅ TypeScript (.ts, .tsx)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully (or no findings above threshold) |
| 1 | Findings detected above risk threshold |

## Security Considerations

- **No Code Execution**: Patterns are matched against AST, never executed
- **No Data Collection**: Scan results stay on your machine
- **No Credentials Stored**: API keys are never logged or transmitted
- **TLS Only**: All communication is encrypted
- **Open Source**: Full transparency and audit trail

## Troubleshooting

### Action Fails with "No supported files found"

Ensure your repository has `.py`, `.js`, or `.ts` files at the path specified.

### Slow Scans

Large codebases (>100K LOC) may take longer. Specify a narrower `path` parameter:

```yaml
- uses: inkog-io/inkog@v1
  with:
    path: ./agents
```

### High False Positives

Adjust `risk-threshold` or check [CWE references](https://cwe.mitre.org) for patterns.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

## License

Apache 2.0 - See [LICENSE](../LICENSE) for details

## Support

- 📖 [Full Documentation](https://docs.inkog.ai)
- 🐛 [Issue Tracker](https://github.com/inkog-io/inkog/issues)
- 💬 [Discussions](https://github.com/inkog-io/inkog/discussions)
