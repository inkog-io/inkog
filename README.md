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
go install github.com/inkog-io/inkog/cmd/cli@latest
```

## Quick Start

```bash
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

LangChain · LangGraph · CrewAI · AutoGen · LlamaIndex · n8n · Flowise · Langflow · Dify · Copilot Studio · Agentforce · Google ADK

## CI/CD Integration

```yaml
- uses: inkog-io/inkog@v1
  with:
    sarif-upload: true
```

[Full GitHub Action docs →](https://docs.inkog.io/ci-cd/github-action)

## Extensibility

Write custom detection rules in YAML:

```yaml
id: my-new-vulnerability
severity: HIGH
frameworks: [langchain, crewai]
pattern:
  node_type: LLMCall
  condition: missing_rate_limit
message: "Agent makes unbounded LLM calls without rate limiting"
cwe: CWE-770
```

[Write your own rule →](CONTRIBUTING.md#quickstart-write-a-security-rule)

## Roadmap

| Feature | Status |
|---------|--------|
| MCP Security Scanning | Planned |
| PydanticAI Support | Planned |
| IDE Extensions (VS Code) | Planned |

## Documentation

- [CLI Reference](https://docs.inkog.io/cli/commands)
- [Vulnerability Patterns](https://docs.inkog.io/vulnerabilities)
- [GitHub Action](https://docs.inkog.io/ci-cd/github-action)
- [AGENTS.md Governance](https://docs.inkog.io/governance/agents-md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Apache 2.0 — See [LICENSE](LICENSE)
