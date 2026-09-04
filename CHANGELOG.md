# Changelog

All notable changes to the Inkog CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.3] — 2026-09-04

Release-pipeline fix. Same features as 1.2.2.

### Fixed
- **Release binaries** — v1.2.2 shipped four stale prebuilt binaries (built 2026-05-15) that had been committed to the repository and swept up by the artifact glob. Binaries are no longer tracked in git, the workflow uploads only the file it just built and verifies the embedded version, and `inkog -version` no longer prints a doubled `v`.

## [1.2.2] — 2026-09-04

Superseded by 1.2.3 (its macOS and Linux binaries were stale). Changes below are what 1.2.3 delivers.

Finding suppressions now work end to end, OWASP references move to the 2026 editions, and the Agent Capability Surface summary ships after every scan.

### Added
- **Agent Capability Surface** — every scan prints agents, tools, and control gaps with a link to the dashboard surface view; the legacy Governance Status block is hidden when the surface is active.
- **`-type` flag** — override the Deep scan target (`agent` or `copilot_studio`); deep-only exports are steered to `-deep`.
- **`.inkogignore` upload** — suppression files are now sent with the scan so server-side suppressions (file rules and inline `# inkog:ignore` comments) apply. Previously the file was silently dropped.
- **Secret patterns** — six additional 2026 AI-provider keys and Stripe restricted keys are redacted client-side.
- **Fixture notice** — when uploaded files were classified as test or example fixtures (and therefore produce no findings), the scan summary says so and how to scan them directly.
- **Deep analysis warnings** — Deep rules that could not be evaluated upstream are reported as a warning instead of being listed as strengths; a Deep scan where every rule failed is reported as failed rather than clean.

### Changed
- **OWASP references** now use the OWASP GenAI LLM Top 10 **2026** ids (`LLM10:2026`) and the OWASP Top 10 for Agentic Applications 2026 (`ASI01`–`ASI10`); the server emits the same ids on every finding.
- Discrete `cwe` and `owasp_category` fields are populated deterministically from the server response.
- Dashboard links point to `/dashboard/agents/{id}`.
- Go toolchain bumped to 1.24 for builds.

### Removed
- **`make docker-build`** — there is no Dockerfile or published image; use `npx -y @inkog-io/cli scan .`, the install script, Homebrew, or a release binary.

## [1.2.1] — 2026-04-29

A documentation refresh and infrastructure patch. No changes to detection logic — scan results are identical to v1.2.0.

### Added
- **CHANGELOG.md** — release history covering v1.0.0 → v1.2.0 in Keep a Changelog format
- **Dependabot** — weekly automated updates for Go modules and GitHub Actions
- **Framework-support issue template** — checklist for detection categories and example agent code

### Changed
- **GitHub Action** (`inkog-io/inkog@v1`) — downloads pre-built binaries instead of building from source; CI scans run ~10× faster (~60s → ~5s, supports macOS/Linux/Windows + amd64/arm64)
- **CONTRIBUTING.md** — rewritten with Universal IR primer and clearer adapter-contribution guide
- **SECURITY.md** — adds supported versions table, points to GitHub Security Advisories, expands scope to cover the MCP server and GitHub Action

## [1.2.0] — 2026-04-13

### Added
- **Deep scan** (`inkog -deep .`) — orchestrator-driven analysis layered on top of the core static engine. Catches subtle logic flaws that pattern matching alone misses. HTML report support via `-deep -output html`.
- **Skill scan** (`inkog skill-scan`) — audit `SKILL.md` packages for tool poisoning, command injection, and excessive permissions. Works on local paths and remote repos via `--repo`.
- **MCP server scan** (`inkog mcp-scan`) — audit MCP servers for data exfiltration, privilege escalation, and unsafe tool definitions. Scan by registry name or `--repo` URL.
- **MLBOM generation** — Machine Learning Bill of Materials documenting agent components, tools, and data flows.
- **Inkog Red (preview)** — `inkog red` launches adversarial testing against running agents (prompt injection, jailbreaks, tool misuse). Early access — [waitlist](https://inkog.io/red).
- **AI provider secret detection** — client-side detection now catches Anthropic, Google Gemini, Groq, and HuggingFace API keys alongside existing providers.
- **AG2 framework support** — full detection for AG2 (formerly AutoGen) agent patterns, including multi-agent topology extraction.
- **Azure AI Foundry support** — added to the supported framework list.
- **`NO_COLOR` support** — respects the `NO_COLOR` environment variable for CI/CD and piped output.
- **Upload progress bar** — visual progress indicator during code upload.
- **CI/CD templates** — ready-to-use pipeline configs for GitHub Actions, GitLab CI, Azure DevOps, and Jenkins (thanks @monssefbaakka).
- **`-agent-name` flag** — explicit agent naming on the dashboard (falls back to source path).
- **npx support** — `npx -y @inkog-io/cli scan .` for zero-install usage.

### Changed
- Scan output is now branded as **Inkog Core** (alongside **Inkog Deep**) for clarity.
- JSON output emits `[]` instead of `null` for empty finding arrays.
- Enriched server-side fields (`strengths`, agent profile metadata) now flow through to text output.
- Pre-flight check positioning across CLI strings and docs.

### Fixed
- `fmt.Sscanf` return value now checked.
- `SecurityStrength` deserialization aligned with backend API contract.

## [1.1.0] — 2026-02-11

### Added
- **`.gitignore` support** — scanner respects repo `.gitignore` rules during file walk.
- **`-max-files` flag** (default 500) — caps file count on large repos with agent-relevance prioritization.
- **Server-side policy support** — `--policy` flag now passes through to the backend for governance filtering.
- **Homebrew install** — `brew tap inkog-io/inkog && brew install inkog`.
- **Binary downloads** — pre-built artifacts for darwin/linux/windows on each release.

### Changed
- HTTP client timeout increased to match backend processing time.
- 4-layer secret detection FP filtering pipeline (entropy, context, docstrings, variable names).
- Multiple secret detection precision passes (V5 → V12) reducing FPs across PEM constants, Algolia keys, hex hashes, SRI hashes, base64, default DB passwords, cookbook/samples/tutorials directories.

### Fixed
- URLs no longer flagged as hardcoded credentials.
- Relative path handling and compliance count accuracy.
- Governance policy filter behavior.
- Narrowed `nonce_seed` regex to reduce noise.

## [1.0.0] — 2026-01-09

Initial public release.

### Added
- **CLI scanner** for AI agent codebases — detects infinite loops, prompt injection, missing guardrails, hardcoded secrets, and compliance gaps.
- **Five security policies** — `low-noise`, `balanced` (default), `comprehensive`, `governance`, `eu-ai-act`.
- **Output formats** — `text`, `json`, `sarif`, `html`.
- **Diff mode** (`-diff -baseline`) — show only new findings since baseline, with regression detection for CI gates.
- **Client-side secret redaction** — secrets detected and redacted locally before code is uploaded for analysis.
- **GitHub Action** (`inkog-io/inkog@v1`) — composite action with SARIF upload to GitHub Security tab and PR comment integration.
- **Compliance mapping** — findings mapped to EU AI Act (Article 14), NIST AI RMF, OWASP LLM Top 10.
- **Multi-framework support** — LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents, Semantic Kernel, LlamaIndex, Haystack, DSPy, Phidata, Smolagents, PydanticAI, Google ADK, n8n, Flowise, Langflow, Dify, Microsoft Copilot Studio, Salesforce Agentforce.
- **Cross-platform builds** — darwin (amd64, arm64), linux (amd64, arm64), windows (amd64).

[Unreleased]: https://github.com/inkog-io/inkog/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/inkog-io/inkog/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/inkog-io/inkog/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/inkog-io/inkog/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/inkog-io/inkog/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/inkog-io/inkog/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/inkog-io/inkog/releases/tag/v1.0.0
