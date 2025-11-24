![Inkog](./logo.png)

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue)](LICENSE)
[![Slack Community](https://img.shields.io/badge/Slack-Join%20Community-blueviolet)](https://inkog.io/slack)
[![Docker Automated](https://img.shields.io/badge/Docker-Automated-2496ED)](https://ghcr.io/inkog-io/inkog)

## The Logic Firewall for AI Agents

Prevent **infinite loops**, **token bombing**, and **RCE** before deployment.

---

## The Hook

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

Plus native support for Python, JavaScript, TypeScript, Go, Java, Rust, and more.

---

## Enterprise: Inkog Cloud

**Inkog is Open Source (AGPLv3).** For Teams:

- ✅ Centralized Security Dashboard
- ✅ Historical Trends & Risk Tracking
- ✅ Evidence for SOC2/ISO Audits
- ✅ Team Collaboration & Reporting
- ✅ Custom Security Policies

**Early Access:** hello@inkog.io

---

## How It Works

Inkog uses a **hybrid privacy-first architecture**:

```
1. Local Secret Detection    → Secrets redacted before upload
2. Secure Upload            → Only redacted code leaves your machine
3. Server-Side Logic Analysis → AST analysis detects loops, injection risks
4. Merged Report            → Combined findings with zero secret exposure
```

**Your secrets never touch our servers.**

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

## Privacy & Security

- ✅ **No telemetry.** We don't track your code.
- ✅ **Offline mode.** Works without a server.
- ✅ **Open source.** Audit the code yourself (AGPLv3).
- ✅ **Redaction first.** Secrets detected before upload.

See [Privacy Model](docs/CLI_REFERENCE.md#privacy-model) for technical details.

---

## License

Inkog is licensed under **GNU AGPLv3**.

**Commercial licenses** available for:
- Closed-source distributions
- Proprietary embedded use
- Enterprise deployments

See [LICENSE](LICENSE) or contact hello@inkog.io.

---

## Get Help

- **GitHub Issues:** https://github.com/inkog-io/inkog/issues
- **Security:** security@inkog.io
- **Community:** https://inkog.io/slack
- **Docs:** [CLI Reference](docs/CLI_REFERENCE.md)

---

**Protect your AI agents. Scan today.**
