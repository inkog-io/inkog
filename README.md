<div align="center">
  <img src="logo.png" width="150" alt="Inkog Logo">
</div>

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue)](LICENSE)
[![Build: Passing](https://img.shields.io/badge/Build-Passing-brightgreen)]()
[![Docker: Automated](https://img.shields.io/badge/Docker-Automated-2496ED)](https://ghcr.io/inkog-io/inkog)
[![Slack: Community](https://img.shields.io/badge/Slack-Community-blueviolet)](https://inkog.io/slack)

# Secure your Agent's Logic. Ship with Confidence.

## The Logic Firewall for AI Agents. Prevent Infinite Loops, Token Bombing, and Privacy Leaks across Code and No-Code workflows.

---

![Inkog detecting a Token Bomb in a LangGraph agent](https://placeholder.inkog.io/demo.gif)

*Inkog scanning a LangGraph agent and detecting a token bombing vulnerability.*

[![Book Security Audit](https://img.shields.io/badge/Book_Security_Audit-Contact_Sales-purple?style=for-the-badge)](https://cal.com/inkog/audit)

---

## Quick Start

### Docker (Recommended)

```bash
docker run -v $(pwd):/app ghcr.io/inkog-io/inkog:latest /app
```

### Go Install

```bash
go install github.com/inkog-io/inkog/cmd/cli@latest
inkog .
```

### GitHub Action

```yaml
- name: Run Inkog Security Scan
  uses: inkog-io/inkog@latest
  with:
    path: .
```

---

## Why Inkog?

### Universal IR Engine
Abstracts 15+ agent frameworks into a single intermediate representation. Scans Python ASTs (LangChain, CrewAI) and JSON configs (n8n, Flowise) with identical detection rules.

### Inter-procedural DFG
Implements Backward Slicing to track tainted user input across function boundaries. Detects prompt injection vectors that span multiple files and tool calls.

### Logic Security
Identifies non-deterministic loops ("Doom Loops") and Token Bombing risks. Catches runaway agent behavior that static linters and type checkers miss.

### Hybrid Privacy
Source code is redacted **locally** before transmission. Only the sanitized logic graph is analyzed remotely. Secrets, API keys, and credentials never leave your machine.

---

## Supported Frameworks

**Code-First**
LangChain | LangGraph | CrewAI | Phidata | Smolagents

**SDKs**
OpenAI Agents | LlamaIndex | Semantic Kernel | Haystack

**No-Code / Low-Code**
n8n | Flowise | Langflow | Dify

**Enterprise**
Microsoft AutoGen (AG2) | Vellum

---

## Compliance & Reporting

- Automated mapping to **EU AI Act (Articles 12-15)** and **NIST AI RMF**
- Generates SARIF outputs for GitHub Security tab integration
- Export HTML reports for SOC2 and ISO audits

---

## Common Commands

```bash
# Scan current directory
inkog .

# Verbose output
inkog -path ./src -verbose

# JSON output for CI/CD
inkog -path . -output json > results.json

# HTML report
inkog -path . -output html > report.html

# Filter by severity
inkog -path . -severity critical
```

See [CLI Reference](docs/CLI_REFERENCE.md) for full documentation.

---

## License & Enterprise

**License:** GNU AGPLv3. [View LICENSE](LICENSE)

**Inkog Cloud:** Centralized dashboards, historical trends, and team policy management.

**Contact:** hello@inkog.io

---

## Get Help

- **Issues:** [github.com/inkog-io/inkog/issues](https://github.com/inkog-io/inkog/issues)
- **Security:** security@inkog.io
- **Community:** [inkog.io/slack](https://inkog.io/slack)
