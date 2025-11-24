<div align="center">
  <img src="logo.png" width="150" alt="Inkog Logo">
</div>

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue)](LICENSE)
[![Slack Community](https://img.shields.io/badge/Slack-Join%20Community-blueviolet)](https://inkog.io/slack)
[![Docker Automated](https://img.shields.io/badge/Docker-Automated-2496ED)](https://ghcr.io/inkog-io/inkog)

## Secure your AI Agent's Logic. Ship with Confidence.

The first static analysis engine to prevent Infinite Loops, Token Bombing, and Logic Flaws before deployment.

---

![Inkog detecting a Token Bomb in a LangGraph agent](https://placeholder.inkog.io/demo.gif)

*Inkog scanning a LangGraph agent and detecting a token bombing vulnerability in real-time.*

[![Book Security Audit](https://img.shields.io/badge/Book_Security_Audit-Contact_Sales-purple)](https://cal.com/inkog/audit)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
docker run -v $(pwd):/app ghcr.io/inkog-io/inkog:latest /app
```

### Option 2: Go Install

```bash
go install github.com/inkog-io/inkog/cmd/cli@latest
mv $GOPATH/bin/cli $GOPATH/bin/inkog
inkog .
```

### Option 3: GitHub Action

Add to `.github/workflows/security.yml`:

```yaml
- name: Run Inkog Security Scan
  uses: inkog-io/inkog@latest
  with:
    path: .
```

---

## Why Inkog?

### 🛑 Prevent Doom Loops
Detects non-deterministic loops in **LangChain**, **CrewAI**, and **AutoGen** agents that burn API credits and crash systems.

### 🔒 Hybrid Privacy
Your secrets stay local. Only the **redacted code logic** is analyzed in the cloud. API keys, tokens, and credentials never leave your machine.

### ⚖️ Compliance Ready
Findings map to **EU AI Act (Article 15)** and **NIST AI RMF** for regulatory audits and SOC2 evidence.

---

## Framework Support

Inkog detects vulnerabilities in agents built with:

- **LangChain** - Chain composition risks, infinite agent loops
- **CrewAI** - Tool misuse, recursive delegation patterns
- **AutoGen** - State explosion, conversation loops
- ...and more coming soon

Plus native support for Python, JavaScript, TypeScript, Go, Java, Rust, and more.

---

## For Teams

Inkog Open Source is free and ready to use. For enterprise deployments:

- Centralized dashboard & reporting
- Historical trends & risk tracking
- SOC2/ISO audit evidence
- Team collaboration
- Custom security policies

**Early Access:** hello@inkog.io

---

## How It Works

```
Local Detection  →  Redact Secrets  →  Secure Upload  →  Remote Analysis  →  Report
```

Your secrets stay on your machine. Only redacted code is analyzed.

---

## Common Commands

```bash
# Scan current directory
inkog .

# Scan with verbose output
inkog -path ./src -verbose

# Output as JSON (for CI/CD)
inkog -path . -output json > results.json

# Only show critical findings
inkog -path . -severity critical

# Use custom Inkog server
inkog -path . -server https://inkog.company.com
```

For more options, see [CLI Reference](docs/CLI_REFERENCE.md).

---

## Privacy First

- No telemetry. No tracking. No data collection.
- Works offline. Detects secrets locally without a server.
- Open source. Audit everything (AGPLv3).
- Secrets redacted before upload.

See [Privacy Model](docs/CLI_REFERENCE.md#privacy-model) for technical details.

---

## License

GNU AGPLv3. [View LICENSE](LICENSE)

Commercial licenses available. Contact hello@inkog.io.

---

## Get Help

- **GitHub Issues:** https://github.com/inkog-io/inkog/issues
- **Security:** security@inkog.io
- **Community:** https://inkog.io/slack
- **Docs:** [CLI Reference](docs/CLI_REFERENCE.md)

---

**Protect your AI agents. Scan today.**
