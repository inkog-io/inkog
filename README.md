# Inkog - AI Agent Security Scanner

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue)](https://github.com/marketplace/actions/inkog-scanner)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/inkog-io/inkog)](https://goreportcard.com/report/github.com/inkog-io/inkog)

🛡️ Detect behavioral risks in AI agents before production deployment.

## Features

- **15 Security Patterns**: Comprehensive vulnerability detection across multiple categories
- **96% Accuracy**: Proven detection on real-world agent code
- **Sub-10s Analysis**: Scans 10K lines in <10 seconds
- **Framework Auto-Detection**: LangChain, CrewAI, AutoGen, and custom agents
- **GitHub Native**: Automatic PR annotations and JSON reports

## Quick Start

### GitHub Actions (Recommended)

Add to `.github/workflows/security.yml`:

```yaml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  inkog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: inkog-io/inkog@v1
        with:
          path: ./
          risk-threshold: high
```

### Local CLI

```bash
# Install
go install github.com/inkog-io/inkog/cmd/scanner@latest

# Run
inkog-scanner --path ./agents

# Generate JSON report
inkog-scanner --path ./agents --json-report report.json
```

## Examples

```bash
# List all patterns
inkog-scanner --list-patterns

# Scan with risk threshold
inkog-scanner --path . --risk-threshold medium

# Load config file
inkog-scanner --config inkog-config.json

# Output JSON
inkog-scanner --path . --json > findings.json
```

## Supported Frameworks

- LangChain (Python, JavaScript)
- CrewAI (Python)
- AutoGen (Python)
- Custom Python/TypeScript agents

## What Gets Detected

**15 Security Patterns across 3 Tiers:**

**TIER 1 - Foundation (4 patterns):**
- Hardcoded Credentials (CRITICAL, 98%)
- Prompt Injection (HIGH, 90%)
- Infinite Loops (HIGH, 95%)
- Unsafe Environment Access (MEDIUM, 92%)

**TIER 2 - Resource Exhaustion (5 patterns):**
- Token Bombing (HIGH, 88%)
- Recursive Tool Calling (CRITICAL, 88%)
- Context Window Accumulation (HIGH, 80%)
- Missing Rate Limits (HIGH, 80%)
- RAG Over-Fetching (HIGH, 85%)

**TIER 3 - Data & Execution (6 patterns):**
- Logging Sensitive Data (HIGH, 82%)
- Output Validation Failures (CRITICAL, 78%)
- SQL Injection via LLM (CRITICAL, 85%)
- Unvalidated Code Execution (CRITICAL, 90%)
- Missing Human Oversight (HIGH, 75%)
- Cross-Tenant Data Leakage (CRITICAL, 82%)

## Installation

### From Source

```bash
git clone https://github.com/inkog-io/inkog.git
cd inkog/action
go build -o inkog-scanner ./cmd/scanner
```

### Docker

```bash
docker build -t inkog:latest .
docker run -v $(pwd):/workspace inkog:latest --path /workspace
```

## Documentation

- 📖 [GitHub Action Setup](./action/README.md) - Integration guide
- 🔧 [CLI Reference](./action/README.md#outputs) - All flags and options
- 🛡️ [Security Policy](./SECURITY.md) - Vulnerability reporting
- 📋 [Contributing](./CONTRIBUTING.md) - How to contribute

## License

MIT - See [LICENSE](./LICENSE) for details

## Support

- 📧 [Report Security Issues](./SECURITY.md)
- 💬 [GitHub Issues](https://github.com/inkog-io/inkog/issues)
- 📚 [Full Documentation](./action/README.md)
