# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Inkog CLI (`github.com/inkog-io/inkog`) is the open-source **dumb client** for the Inkog AI Agent Security Platform. It detects hardcoded secrets locally, redacts them, uploads clean code to the Inkog backend API for vulnerability analysis, and displays merged results. All detection logic lives server-side — the CLI has zero analysis intelligence.

**Hard constraints**: Pure Go (CGO_ENABLED=0), no tree-sitter, no backend imports. The CLI must cross-compile to darwin/linux/windows without native dependencies.

## Commands

```bash
make build           # Build binary (CGO_ENABLED=0, version from git tags)
make build-prod      # Stripped production binary (-ldflags="-s -w")
make build-all       # Cross-platform builds (darwin/linux/windows, amd64/arm64)
make test            # Run all tests: go test -v ./...
make lint            # go vet + golangci-lint (if installed)
make fmt             # go fmt ./...
make install         # Install to $GOPATH/bin

# Run a single test
go test -v -run TestShouldScanFile_SupportedExtensions ./pkg/cli/
go test -v -run TestDetectSecrets ./pkg/patterns/secrets/

# Run CLI locally without building
go run cmd/inkog/main.go -path ../demo_agent

# Test against local backend server
INKOG_API_KEY="sk_live_..." ./inkog -path ../demo_agent -server http://localhost:8080

# Test against production
INKOG_API_KEY="sk_live_..." ./inkog -path ../demo_agent
```

## Architecture

```
CLI Flow:
1. Parse flags, resolve API key (env > ~/.inkog/config.json > interactive first-run)
2. Walk filesystem → detect secrets locally (regex + Shannon entropy)
3. Redact ALL detected secrets from file contents (privacy-first: redact even FPs)
4. Upload redacted files as multipart form to POST /api/v1/scan
5. Receive findings from server, merge with local secret findings
6. Output merged results (text/json/sarif/html) to stdout, progress to stderr
```

API key resolution order: `INKOG_API_KEY` env var → `~/.inkog/config.json` → interactive first-run experience (anonymous preview + key prompt). Without a key, non-interactive mode exits with error.

Server URL priority: `-server` flag → `INKOG_SERVER_URL` env var → `https://api.inkog.io` default.

## Key Files

**`cmd/inkog/main.go` (3300+ lines)** — This is a monolith containing:
- Flag parsing and `main()` (lines ~210-400)
- All four output formatters: `outputText`, `outputJSON`, `outputSARIF`, `outputHTML`
- Tiered display logic (`displayTierSection`, `displayTieredCodeFrame`, etc.)
- HTML report generation with embedded CSS/JS (~1200 lines of HTML templates)
- SARIF report builder
- Baseline save/load and diff output
- First-run experience: anonymous preview → conversion menu → key saving
- Agent report grouping and framework detection

**`pkg/cli/scanner.go`** — `HybridScanner`: the core scan orchestrator.
- `Scan()` drives the 5-step pipeline (detect → redact → upload → merge → return)
- `scanLocalSecretsAndCollectFiles()` walks the filesystem respecting gitignore, excluded dirs, blocked files, and file extensions
- `redactSecretsFromFiles()` runs `DetectSecretsForRedaction` (unfiltered) to redact ALL potential secrets before upload
- `truncateFileMap()` enforces max-files limit, prioritizing agent-relevant files by keyword scoring
- `PickBestAgentFile()` selects the single best file for anonymous preview scanning

**`pkg/cli/client.go`** — `InkogClient`: HTTP client with retry logic.
- `SendScan()` sends multipart form to `/api/v1/scan` with exponential backoff (3 retries)
- `SendAnonymousScan()` sends single file to `/api/v1/scan/anonymous` (no API key)
- Handles 429/409 rate limits with `Retry-After`, 5xx with backoff, 4xx without retry
- Auth errors return formatted signup CTA message

**`pkg/contract/contract.go`** — Shared types between CLI and server.
- `Finding` struct with risk tier, taint tracking, compliance mapping, governance fields
- `ScanRequest`/`ScanResponse` for the API contract
- `FilterByPolicy()` implements all 5 security policies (low-noise/balanced/comprehensive/governance/eu-ai-act)
- `ComputeDiff()` for baseline comparison
- `SeverityLevels` map: CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10

**`pkg/patterns/secrets/`** — Client-side secret detection (regex + entropy).
- `patterns.go`: `PatternDefinitions` map with 11 pattern types (api_key, aws_access_key, private_key, stripe_key, etc.). Extensive FP filtering: env var references, public key prefixes, docstrings, Algolia search keys, human-readable identifiers, hex-only values.
- `entropy.go`: Shannon entropy detection (threshold 4.5, 5.0 for JSON). Requires credential context keywords OR known secret format prefixes. File-level flood detection (>15 findings → keep only context-backed ones).
- `context.go`: `ShouldSkipFile()` suppresses findings (not redaction) for test files, fixtures, docs, migrations, CI configs, lock files, etc. `IsPlaceholderValue()` filters common FP values. `AdjustConfidence()` lowers confidence for comments, notebooks, marketplace configs, field names, etc.

**Two detection paths**: `DetectSecrets()` (for reporting — applies FP filtering) vs `DetectSecretsForRedaction()` (for privacy — returns ALL raw findings, no filtering). Redaction always uses the unfiltered path.

**`pkg/cli/gitignore.go`** — Custom `.gitignore` parser with glob matching (supports `*`, `?`, `**`, negation `!`, directory-only `/`).

**`pkg/cli/progress.go`** — Terminal spinner (briandowns/spinner) for interactive output. Writes to stderr. Disabled in quiet mode (JSON output or CI).

**`pkg/cli/config.go`** — Reads/writes API key to `~/.inkog/config.json`.

## Gotchas

- **JSON output key**: Server findings are under `server_findings` (not `findings`) in JSON output. Top-level keys: `local_secrets`, `server_findings`, `all_findings`, `compliance_report`, `topology_map`.
- **main.go is huge**: At 3300+ lines, `cmd/inkog/main.go` contains all output formatting, HTML templates, SARIF generation, and the first-run flow. Any output change likely requires editing this file.
- **Two secret detection paths**: `DetectSecrets()` (filtered, for user-facing findings) and `DetectSecretsForRedaction()` (unfiltered, for privacy). Redaction MUST use the unfiltered path — otherwise secrets that look like FPs could leak to the server.
- **File extension allow-list**: Only files matching `DefaultScanExtensions` in `scanner.go` are scanned. Adding language support requires updating this map.
- **Max files limit**: Default 500 files (`DefaultMaxFiles`). Files are prioritized by agent-relevance keywords when truncated.
- **Quiet mode**: Triggered by `-output json` or `CI` env var. Suppresses spinners, colors, and progress messages.
- **Exit codes**: `0` = no findings, `1` = findings found (or regression in diff mode). Used by CI to gate PRs.
- **Version injection**: `AppVersion`, `BuildTime`, `GitCommit` are set via `-ldflags` at build time. Without ldflags, version shows as `1.0.0-dev`.

## GitHub Action

`action.yml` — Composite GitHub Action (`inkog-io/inkog@v1`) for CI integration. Builds CLI from source, runs JSON + text + SARIF scans, uploads SARIF to GitHub Security tab, and posts PR comments with findings summary. Supports diff mode (only fail on regressions) and baseline management. Key inputs: `api-key` (required), `policy`, `diff`, `baseline`, `fail-on-findings`, `comment-on-pr`, `sarif-upload`.

## CI

GitHub Actions (`.github/workflows/ci.yml`): builds with `CGO_ENABLED=0` and runs `go test -v ./...` on Go 1.21. Lint job runs `golangci-lint`. Release workflow (`.github/workflows/release.yml`) triggers on version tags (`v*`) and builds cross-platform binaries for GitHub Releases with checksums.

The monorepo also has integration tests in `.github/workflows/inkog-test.yml` (in the parent) that test policy modes, SARIF output, diff mode, and vulnerable code detection against the live API.

## Security Policies

Policies filter findings client-side via `contract.FilterByPolicy()`:
- `low-noise`: Only tier 1 (vulnerability)
- `balanced` (default): Tier 1 + 2 (vulnerability + risk_pattern)
- `comprehensive`: All tiers
- `governance`: Only findings with governance category/compliance mapping
- `eu-ai-act`: Governance + EU AI Act compliance mappings + high-severity findings
