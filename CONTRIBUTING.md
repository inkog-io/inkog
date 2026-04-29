<div align="center">

# Contributing to Inkog

**Welcome.**

Help us secure the agentic AI stack. Whether you're filing a bug, improving the CLI, or proposing a new framework — contributions are welcome.

[![Slack](https://img.shields.io/badge/Join-Slack_Community-blueviolet?style=for-the-badge)](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)

</div>

---

## What Lives Where

Inkog is split across two repos:

| Repo | License | What's there |
|------|---------|--------------|
| **`inkog-io/inkog`** (this repo) | Apache 2.0 | The CLI: scanner orchestration, output formatting, client-side secret detection, the GitHub Action |
| **`inkog-io/inkog-backend`** | Proprietary | Detection engine: Universal IR, framework adapters, YAML rules, governance evaluators |

The CLI is a **dumb client** by design — it detects secrets locally (so they never leave your machine), uploads redacted code to the backend for analysis, and renders the results. All vulnerability detection runs server-side.

This means contribution paths look different depending on what you want to change. Here's the map.

---

## Ways to Contribute

### File a great bug report or feature request
Open an issue. Use the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) or [feature request](.github/ISSUE_TEMPLATE/feature_request.md) templates — both prompt for the info we need to act fast.

### Request support for a new framework
The Universal IR makes adapter additions tractable. File a [framework support request](.github/ISSUE_TEMPLATE/framework_support.md) with example agent code from the framework. Adapter implementation happens in the backend repo, but issues and discussion live here.

### Improve the CLI
Direct PRs welcome on:
- **Output formatting** — text/JSON/SARIF/HTML report rendering (most of this lives in `cmd/inkog/main.go`)
- **Client-side secret patterns** — `pkg/patterns/secrets/` (regex + Shannon entropy with FP filtering)
- **Scan flow** — file walking, gitignore handling, redaction (`pkg/cli/scanner.go`)
- **Bug fixes** — anything in this repo
- **Tests** — `go test ./...`

### Improve documentation
- README, this file, [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md), [docs/CI_CD_INTEGRATION.md](docs/CI_CD_INTEGRATION.md)
- Translations live in [`docs/i18n/`](docs/i18n/) — 7 languages currently supported

### Share CI/CD integration examples
[`examples/ci/`](examples/ci/) holds workflow templates for GitHub Actions, GitLab, Azure DevOps, Jenkins, etc. New providers welcome.

---

## Architecture Primer

Knowing where things live makes contributions easier — even if your PR only touches the CLI.

### CLI flow

```
1. Parse flags, resolve API key
2. Walk filesystem → detect secrets locally (regex + entropy)
3. Redact ALL detected secrets from file contents (privacy first)
4. Upload redacted files as multipart POST /api/v1/scan
5. Receive findings, merge with local secret findings
6. Render results (text / json / sarif / html)
```

**Hard constraints**: Pure Go, `CGO_ENABLED=0`, no tree-sitter, no backend imports. The CLI must cross-compile to darwin/linux/windows without native dependencies.

### Universal IR (server side)

Code in any framework gets transformed into a single intermediate representation before detection rules run:

```
  Code/Config        Framework Adapter         InkogGraph (IR)        Rules + Conditions        Findings
  ──────────  ────►  ─────────────────  ────►  ───────────────  ────► ────────────────────  ───►  ────────
   Python              python_generic          18 IR node types        100+ condition handlers
   TypeScript          typescript              (LLMCallNode,            (is_tainted,
   YAML/JSON           langgraph                ToolCallNode,            is_dangerous,
   ...                 crewai                   LoopNode, …)             has_sanitization, …)
                       n8n / flowise /
                       langflow / dify
                       agentforce / copilot /
                       google_adk
```

Detection rules query IR node properties (e.g. `LLMCallNode.is_tainted`), not framework-specific patterns. This is what makes the engine framework-agnostic — and what makes "add a framework" mean "write an adapter that emits IR nodes," not "write rules per framework."

### Adding framework support

When you file a framework support request, the work breaks down like this (mostly in the backend repo):

1. **Adapter** — parses the framework's source/config and emits IR nodes (e.g. agent definition → `AgentDefinitionNode`, tool registration → `ToolCallNode`, supervisor pattern → `DelegationNode`). For code-first frameworks this uses tree-sitter ASTs; for no-code frameworks (n8n, Flowise) it traverses the JSON workflow graph.
2. **Adapter tests** — fixtures in `pkg/ir/adapters/testdata/` that pin expected IR output for representative agents.
3. **Real-world validation** — run the adapter against open-source agents from that framework, confirm zero crashes and acceptable findings.
4. **Pattern coverage** — most rules already work via the IR; framework-specific patterns (e.g. AG2's `register_function`) may need new condition handlers in `pkg/rules/conditions/handlers.go`.

The CLI side is usually no work at all — the framework just shows up in scan output once the backend ships.

If you want to drive an adapter end-to-end, [open an issue](https://github.com/inkog-io/inkog/issues/new?template=framework_support.md) — we'll loop you in on the backend PR.

---

## Development Setup

### Requirements
- Go 1.21+
- Git
- An [Inkog API key](https://app.inkog.io) for end-to-end testing

### Build and test

```bash
git clone https://github.com/inkog-io/inkog.git
cd inkog

# Build (pure Go, no CGO)
make build

# Run tests
make test

# Lint
make lint

# Run against a sample
INKOG_API_KEY=sk_live_... ./inkog ./examples
```

### Test against a local backend (for backend contributors)

```bash
INKOG_API_KEY=sk_live_... ./inkog -path ./examples -server http://localhost:8080
```

### Project structure

```
inkog/
├── cmd/inkog/main.go      # CLI entry point + all output formatters (3300+ lines)
├── pkg/
│   ├── cli/               # Scanner, HTTP client, gitignore, progress, config
│   ├── contract/          # Shared types with backend (Finding, ScanRequest, policies)
│   └── patterns/secrets/  # Local secret detection (regex + entropy + FP filtering)
├── docs/                  # CLI reference, CI/CD integration, translations
├── examples/ci/           # Workflow templates
├── action.yml             # The inkog-io/inkog GitHub Action
└── .github/               # Workflows, issue templates
```

---

## Pull Request Guidelines

### Commit messages
Conventional commits:

```
feat: add support for SARIF severity levels
fix: handle empty file edge case in scanner
docs: clarify --policy flag in CLI reference
chore: bump go.mod dependencies
```

### Before opening a PR
- [ ] `make test` passes
- [ ] `make lint` passes (`go vet` + `gofmt`)
- [ ] No secrets, API keys, or real customer data in code or test fixtures
- [ ] If user-visible, mention the change in the PR description (we'll port it to `CHANGELOG.md` on release)
- [ ] If output format changes, manual scan output included in PR description

### Security check
The CLI scans itself in CI. You can run it locally before pushing:

```bash
INKOG_API_KEY=sk_live_... ./inkog .
```

Or use the [Inkog MCP server](https://github.com/inkog-io/inkog-mcp) for inline feedback in Claude Code or Cursor.

---

## Governance & Licensing

| Component | License |
|-----------|---------|
| **CLI (this repo)** | Apache 2.0 |
| **Detection engine** | Proprietary |

Your CLI contributions are Apache 2.0 — usable in any project including proprietary ones. By submitting a PR you agree to this license for the contributed code.

### Code of Conduct
We follow the [Contributor Covenant](https://www.contributor-covenant.org/). Be respectful. Assume good intent. Help others succeed. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

### Reporting security issues
Don't open a public issue. Email `security@inkog.io`. See [SECURITY.md](SECURITY.md).

---

## Getting Help

- **Slack:** [Join the community](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)
- **Issues:** [Ask a question](https://github.com/inkog-io/inkog/issues/new?labels=question)
- **Email:** hello@inkog.io

---

<div align="center">

**Thank you for helping secure the agent ecosystem.**

</div>
