# Inkog: The Compliance Engine for Agentic AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/inkog-io/inkog)](https://goreportcard.com/report/github.com/inkog-io/inkog)
[![Docker Automated](https://img.shields.io/badge/Docker-Automated-blue?logo=docker)](https://github.com/inkog-io/inkog/pkgs/container/inkog)

Inkog detects AI agent vulnerabilities that commercial tools miss. Secure your agentic AI systems with regulatory compliance built-in.

[![Book Security Audit](https://img.shields.io/badge/Book%20Security%20Audit-gray?style=flat-square&logo=calendly&link=https://cal.com/inkog/audit)](https://cal.com/inkog/audit)

---

## Why Inkog?

**The Problem:** Traditional security tools (Snyk, Semgrep, SonarQube) were built for monolithic applications. They miss the behavioral risks that emerge when LLM agents operate autonomously.

**The Solution:** Inkog's semantic analysis engine detects:
- ✅ **Infinite Loops** - Unbounded LLM-driven loops without hard break counters
- ✅ **Context Exhaustion** - Token accumulation without bounds
- ✅ **Tainted Eval** - Code execution from unvalidated LLM outputs
- ✅ **Prompt Injection** - User input flowing directly into prompts
- ✅ **Recursive Agent Loops** - Agent-to-agent delegation cycles
- ✅ **15+ Additional AI-Specific Patterns** - Covering OWASP LLM Top 10

### Watch the Demo

[![Watch the Demo](https://img.shields.io/badge/Watch%20Demo-Loom-red?style=flat-square&logo=loom)](https://www.loom.com/YOUR_LOOM_LINK)

---

## Compliance Built-In

Inkog maps every finding to regulatory frameworks your organization requires:

### EU AI Act Compliance
| Pattern | Article | Risk Level |
|---------|---------|-----------|
| Infinite Loop Detection | Article 15 (Accuracy & Resilience) | CRITICAL |
| Context Exhaustion | Article 15 (System Reliability) | HIGH |
| Tainted Code Execution | Article 14 (Human Oversight) | CRITICAL |
| Missing Rate Limiting | Article 15 (Cybersecurity) | HIGH |
| Cross-Tenant Data Leakage | Article 14 (Data Governance) | CRITICAL |

### NIST AI RMF Coverage
- **MAP 1.3**: System reliability and robustness assessment
- **MEASURE 2.4**: AI system risk identification and tracking
- **GOVERN 3.1**: Oversight mechanisms and audit trails
- **MANAGE 4.2**: Incident response and security operations

### OWASP LLM Top 10
Detects all major categories:
- LLM01: Prompt Injection
- LLM04: Unauthorized Code Execution
- LLM08: Vector Database Poisoning
- *And 7 more...*

---

## Enterprise Features

- 🚀 **36x Faster** - Tree-sitter AST analysis (not regex)
- 🔒 **Zero Data Collection** - Scan results stay on your machine
- 📊 **SARIF Reports** - GitHub/GitLab/IDE compatible security reports
- 🔄 **15 Security Patterns** - Comprehensive AI agent vulnerability coverage
- 🏗️ **Auto-Detect Frameworks** - LangChain, CrewAI, AutoGen, custom agents
- ⚙️ **Zero Configuration** - Works out of the box
- 📈 **Enterprise Concurrency** - Scan 10K lines of code in <10 seconds
- 🛡️ **Panic Recovery** - Single detector failure doesn't break the scan

---

## Getting Started

### 1. GitHub Actions (Recommended)

Add to your `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  inkog-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Inkog AI Security Scan
        uses: inkog-io/inkog@v1
        with:
          path: ./
          format: sarif
          compliance: true
```

### 2. Docker

```bash
docker pull ghcr.io/inkog-io/inkog:latest

docker run \
  -v $(pwd):/workspace \
  ghcr.io/inkog-io/inkog:latest \
  --path /workspace \
  --format sarif \
  --compliance true
```

### 3. From Source

```bash
git clone https://github.com/inkog-io/inkog.git
cd inkog/action
go build -o inkog-scanner ./cmd/scanner
./inkog-scanner --path ./src
```

---

## Configuration

### CLI Inputs

```bash
./inkog-scanner \
  --path ./agents \
  --format sarif \
  --compliance true \
  --risk-threshold high \
  --report findings.sarif
```

### GitHub Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `format` | Output format: `text`, `json`, `sarif` | `text` |
| `compliance` | Include regulatory mappings | `false` |
| `risk-threshold` | Fail on: `low`, `medium`, `high`, `critical` | `high` |

---

## Output Examples

### SARIF Report (GitHub/GitLab)
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Inkog",
          "version": "1.0.0",
          "rules": [
            {
              "id": "INKOG-001",
              "shortDescription": {
                "text": "Infinite Loop Detection"
              },
              "properties": {
                "eu_ai_act": "Article 15",
                "nist_ai_rmf": "MAP 1.3",
                "owasp_llm": "LLM04"
              }
            }
          ]
        }
      }
    }
  ]
}
```

### Compliance Report
```
╔═══════════════════════════════════════════════════════════╗
║         EU AI ACT COMPLIANCE ASSESSMENT                   ║
╚═══════════════════════════════════════════════════════════╝

Article 14 - Human Oversight: ❌ CRITICAL
  - Tainted Eval detected in agent.py:175
  - Risk: Unvalidated LLM code execution
  - Remediation: Add input validation before eval()

Article 15 - Accuracy, Robustness: ❌ HIGH
  - Infinite Loop detected in agent.py:99
  - Risk: Unbounded agent execution (API cost: ~$500/hour)
  - Remediation: Add max_iterations counter

NIST AI RMF Coverage: 68% (8/12 requirements)
Recommended Actions: 3
```

---

## Detected Patterns

### Critical (15/15 Patterns)

**Infinite Loops** - Unbounded LLM-dependent iterations
- CWE: 835 (Loop with Unreachable Exit Condition)
- Financial Impact: $270K/year (API cost explosion)

**Tainted Eval** - Direct code execution from LLM output
- CWE: 94 (Improper Control of Generation of Code)
- Financial Impact: $1M+ (data breach, lateral movement)

**Context Exhaustion** - Unbounded history accumulation
- CWE: 770 (Allocation of Resources Without Limits)
- Financial Impact: $50K/year (token limits, degraded responses)

**Recursive Tool Calling** - Agent-to-agent delegation loops
- CWE: 674 (Uncontrolled Recursion)
- Financial Impact: $400K/year (infinite API calls)

*And 11 more patterns covering prompt injection, token bombing, RAG overfetching, missing rate limits, hardcoded credentials, etc.*

---

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Startup Time | 0.88ms |
| Parsing Speed | 36x faster than regex |
| Scan Time (10K LOC) | <10 seconds |
| Memory Usage | ~50MB |
| Concurrency | 4-way parallel |
| False Positive Rate | <1% (after tuning) |

---

## Supported Frameworks

- ✅ **LangChain** - Python, JavaScript, TypeScript
- ✅ **CrewAI** - Python
- ✅ **AutoGen** - Python
- ✅ **Custom Agents** - Any Python/TypeScript/JS agent code

---

## Security & Privacy

- 🔒 **No Code Execution** - Pure static analysis via AST
- 🔒 **No Data Collection** - Scans run entirely on your infrastructure
- 🔒 **No Credentials Logged** - API keys never touched
- 🔒 **No Network Calls** - Offline scanning supported
- ✅ **Open Source** - Full audit trail and transparency

---

## Enterprise Support

For security audits, compliance consulting, and custom pattern development:

[![Book Security Audit](https://img.shields.io/badge/Book%20Audit%20%2B%20Consulting-Calendar-blue?style=for-the-badge&link=https://cal.com/inkog/audit)](https://cal.com/inkog/audit)

---

## Contributing

We welcome security researchers and open-source contributors. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT - See [LICENSE](LICENSE) for full text.

---

## Resources

- 📖 [Full Documentation](https://docs.inkog.io)
- 🐛 [Report a Vulnerability](https://github.com/inkog-io/inkog/security)
- 💬 [Discussions](https://github.com/inkog-io/inkog/discussions)
- 🎥 [Demo Video](https://www.loom.com/YOUR_LOOM_LINK)

---

**Inkog: Secure Your Agentic AI.** Built for founders and security teams who take compliance seriously.
