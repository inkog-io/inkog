<p align="center">
  <img src="logo.png" width="120" alt="Inkog">
</p>

<h1 align="center">Inkog</h1>
<p align="center">Static security scanner for AI agents</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/inkog-io/inkog"><img src="https://goreportcard.com/badge/github.com/inkog-io/inkog" alt="Go Report Card"></a>
</p>

---

## Install

```bash
curl -fsSL https://inkog.io/install.sh | sh
```

Or via Go:

```bash
go install github.com/inkog-io/inkog/cmd/inkog@latest
```

## Quick Start

```bash
# Get your API key at https://app.inkog.io
export INKOG_API_KEY=sk_live_your_key_here

# Scan your agent code
inkog .
```

## What It Detects

Comprehensive detection for:

- **OWASP LLM Top 10** — Prompt injection, insecure output handling, and more
- **OWASP Agentic Security** — Tool misuse, identity spoofing, resource overload
- **EU AI Act** — Article 12, 14, 15 compliance checks
- **Governance Violations** — AGENTS.md manifest validation

[View vulnerability patterns →](https://docs.inkog.io/vulnerabilities)

<img width="2446" height="1316" alt="image" src="https://github.com/user-attachments/assets/fb7c1429-6392-447c-9c1e-612d09c0b58e" />


## Supported Frameworks

**Code-First:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-Code:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## CI/CD Integration

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[Full GitHub Action docs →](https://docs.inkog.io/ci-cd/github-action)

## Policies

Filter findings by security policy:

```bash
# Low noise - only proven vulnerabilities
inkog . --policy low-noise

# Governance-focused (Article 14 controls)
inkog . --policy governance

# EU AI Act compliance
inkog . --policy eu-ai-act
```

[Learn more about policies →](https://docs.inkog.io/cli/policies)

## MCP Server (Claude, ChatGPT, Cursor)

Native integration for AI coding assistants. Scan agent code directly from Claude, ChatGPT, or Cursor.

```bash
npx -y @inkog-io/mcp
```

**7 Security Tools:**
- `inkog-scan` - Vulnerability scanning
- `inkog-explain` - Remediation guidance
- `inkog-governance` - AGENTS.md verification
- `inkog-compliance` - EU AI Act, NIST, OWASP reports
- `inkog-mlbom` - ML Bill of Materials
- `inkog-mcp-audit` - **First tool to audit MCP servers** for security before installation
- `inkog-a2a-audit` - **Multi-agent security** - Detect infinite delegation loops, privilege escalation in CrewAI, Swarm, LangGraph

> **Multi-Agent Security (A2A):** For topology analysis and agent delegation auditing, use the MCP server integration. Ask your AI assistant: *"Audit my CrewAI agents for security issues"* or *"How many agents are in my LangGraph workflow?"*

[MCP Integration Docs →](https://docs.inkog.io/integrations/mcp) | [A2A Security Tutorial →](https://docs.inkog.io/tutorials/securing-multi-agent)

## Roadmap

| Feature | Status |
|---------|--------|
| IDE Extensions (VS Code) | Planned |
| Python SDK | Planned |
| JavaScript SDK | Planned |

## Documentation

- [CLI Reference](https://docs.inkog.io/cli/commands)
- [MCP Server Integration](https://docs.inkog.io/integrations/mcp)
- [Vulnerability Patterns](https://docs.inkog.io/vulnerabilities)
- [GitHub Action](https://docs.inkog.io/ci-cd/github-action)
- [AGENTS.md Governance](https://docs.inkog.io/governance/agents-md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0 — See [LICENSE](LICENSE)
