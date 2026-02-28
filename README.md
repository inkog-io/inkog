<p align="center">
  <img src="logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">The security co-pilot for AI agent development.</h3>

<p align="center">
  Build secure AI agents from the start. Scan for logic bugs, prompt injection, missing guardrails, and compliance gaps — before they reach production.
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="docs/i18n/README.zh-CN.md">简体中文</a> ·
  <a href="docs/i18n/README.ja.md">日本語</a> ·
  <a href="docs/i18n/README.ko.md">한국어</a> ·
  <a href="docs/i18n/README.es.md">Español</a> ·
  <a href="docs/i18n/README.pt-BR.md">Português</a> ·
  <a href="docs/i18n/README.de.md">Deutsch</a> ·
  <a href="docs/i18n/README.fr.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/inkog-io/inkog/releases"><img src="https://img.shields.io/github/v/release/inkog-io/inkog?label=release" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/inkog-io/inkog"><img src="https://goreportcard.com/badge/github.com/inkog-io/inkog" alt="Go Report Card"></a>
  <a href="https://github.com/inkog-io/inkog/actions/workflows/ci.yml"><img src="https://github.com/inkog-io/inkog/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-Join%20us-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

<p align="center">
  <img src="demo.gif" width="800" alt="Inkog scanning AI agent code for vulnerabilities">
</p>

---

AI agents can loop forever, drain your API budget in minutes, execute arbitrary code from user input, or make high-stakes decisions with zero human oversight. Most of these flaws pass code review because they look like normal code — the danger is in the runtime behavior.

Inkog scans your agent code statically and catches these problems before deployment. One command, works across 20+ frameworks, maps findings to EU AI Act and OWASP LLM Top 10.

## When to Use Inkog

- **Building an AI agent** — Scan during development to catch infinite loops, prompt injection, and missing guardrails before they ship
- **Adding security to CI/CD** — Add `inkog-io/inkog@v1` to GitHub Actions for automated security gates on every PR
- **Preparing for EU AI Act** — Generate compliance reports mapping your agent to Article 14, NIST AI RMF, OWASP LLM Top 10
- **Reviewing agent code** — Use from Claude Code, Cursor, or any MCP client to get security analysis while you code
- **Auditing MCP servers** — Check any MCP server for tool poisoning, privilege escalation, or data exfiltration before installing
- **Verifying AGENTS.md** — Validate that governance declarations match actual code behavior
- **Building multi-agent systems** — Detect delegation loops, privilege escalation, and unauthorized handoffs between agents

## Quick Start

No install needed:

```bash
npx -y @inkog-io/cli scan .
```

Or install permanently:

| Method | Command |
|--------|---------|
| **Install script** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **Binary** | [Download from Releases](https://github.com/inkog-io/inkog/releases) |

```bash
# Get your free API key at https://app.inkog.io
export INKOG_API_KEY=sk_live_...

inkog .
```

## What It Catches

| Category | Examples | Why it matters |
|----------|----------|----------------|
| **Infinite loops** | Agent re-calls itself with no exit condition, LLM output fed back as input without a cap | Your agent runs forever and racks up API costs |
| **Prompt injection** | User input flows into system prompt unsanitized, tainted data reaches tool calls | Attackers can hijack your agent's behavior |
| **Missing guardrails** | No human-in-the-loop for destructive actions, no rate limits on LLM calls, unconstrained tool access | One bad decision and your agent goes rogue |
| **Hardcoded secrets** | API keys, tokens, and passwords in source code (detected locally, never uploaded) | Credentials leak when you push to GitHub |
| **Compliance gaps** | Missing human oversight (EU AI Act Article 14), no audit logging, missing authorization checks | You're legally required to have these controls by August 2026 |

[Full detection catalog →](https://docs.inkog.io/vulnerabilities)

## Supported Frameworks

**Code-first:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-code:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true   # Shows findings in GitHub Security tab
```

[Full CI/CD docs →](https://docs.inkog.io/ci-cd/github-action)

<details>
<summary><strong>Scan policies</strong></summary>

```bash
inkog . --policy low-noise        # Only proven vulnerabilities
inkog . --policy balanced          # Vulnerabilities + risk patterns (default)
inkog . --policy comprehensive     # Everything including hardening tips
inkog . --policy governance        # Article 14 controls, authorization, audit trails
inkog . --policy eu-ai-act         # EU AI Act compliance report
```

[Policy reference →](https://docs.inkog.io/cli/policies)

</details>

## MCP Server

Scan agent code directly from Claude, ChatGPT, or Cursor:

```bash
npx -y @inkog-io/mcp
```

7 tools including MCP server auditing and multi-agent topology analysis. [MCP docs →](https://docs.inkog.io/integrations/mcp)

## Community

- [Documentation](https://docs.inkog.io) — CLI reference, detection patterns, integrations
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — Questions, feedback, feature requests
- [Issues](https://github.com/inkog-io/inkog/issues) — Bug reports and feature requests
- [Contributing](CONTRIBUTING.md) — We welcome PRs

## Star History

<a href="https://star-history.com/#inkog-io/inkog&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=inkog-io/inkog&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=inkog-io/inkog&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=inkog-io/inkog&type=Date" />
 </picture>
</a>

## License

Apache 2.0 — See [LICENSE](LICENSE)
