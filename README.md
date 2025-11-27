<div align="center">
  <img src="logo.png" width="150" alt="Inkog Logo">
</div>

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue)](LICENSE)
[![Build: Passing](https://img.shields.io/badge/Build-Passing-brightgreen)]()
[![Docker: Automated](https://img.shields.io/badge/Docker-Automated-2496ED)](https://ghcr.io/inkog-io/inkog)
[![Slack: Community](https://img.shields.io/badge/Slack-Community-blueviolet)](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)

# Secure your Agent's Logic. Ship with Confidence.

## The Logic Firewall for AI Agents. Prevent Infinite Loops, Token Bombing, Privacy Leaks and more for your agents across any Code/No-Code agentic framework.

---

![Inkog detecting a Token Bomb in a LangGraph agent](https://placeholder.inkog.io/demo.gif)

*Inkog scanning a LangGraph agent and detecting a token bombing vulnerability.*

[![Book a Demo](https://img.shields.io/badge/Book_a_Demo-Schedule_Now-purple?style=for-the-badge)](https://cal.com/inkog/demo)

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

### Universal Framework Support
One scanner for 15+ agent frameworks. Analyzes Python code (LangChain, CrewAI) and JSON workflows (n8n, Flowise) with the same detection rules. No framework-specific setup required.

### Cross-File Analysis
Tracks user input as it flows through your codebase—across functions, files, and tool calls. Detects prompt injection vectors that span your entire agent architecture.

### Logic Security
Detects runtime vulnerabilities that linters miss:
- **Infinite Loops** — Agents stuck in cycles with no exit condition
- **Token Bombing** — Unbounded context growth that drains your API budget
- **Recursive Tool Calls** — Tools calling themselves without depth limits
- **Missing Rate Limits** — Unthrottled API calls that can spiral out of control

### Hybrid Privacy
Source code is redacted **locally** before transmission. Only the sanitized logic graph is analyzed remotely. Secrets, API keys, and credentials never leave your machine.

### Extensible Rules
Pluggable YAML-based rule engine. Add custom detection patterns for your organization's specific security policies.

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
- **Community:** [Join our Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)
