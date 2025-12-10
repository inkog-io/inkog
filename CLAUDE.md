# Inkog Public CLI: `inkog-io/inkog`

## Repository Identity

- **GitHub:** `github.com/inkog-io/inkog` (Public)
- **Role:** The Official Inkog CLI
- **Status:** Production (v1.0.0+)
- **License:** Apache 2.0

## Vision

The Inkog CLI is the **primary entry point** for developers securing AI agents. It's a **dumb client** that communicates with the Inkog backend on Fly.io. It prioritizes three pillars:

1. **User Experience:** Beautiful, fast, intuitive output
2. **Speed:** Instant feedback. Secrets detected in <500ms locally
3. **Privacy:** Secrets redacted *before* upload. Never send raw credentials to the server

The CLI must function as a **standalone dumb client**—it can work without a backend server, detecting secrets locally and refusing to upload if there's no connection.

## Architectural Constraint: Strict Isolation

```
✅ ALLOWED:
├── Standard library (fmt, io, os, net/http)
├── pkg/patterns/secrets (Local regex patterns)
├── pkg/contract (Request/response types)
└── Third-party: JSON, CLI parsing, table rendering

❌ FORBIDDEN:
├── tree-sitter imports
├── AST engine imports
├── Backend internal engine
└── CGO dependencies
```

**Why:** The CLI is distribution-focused. It must remain Pure Go (CGO_ENABLED=0) for maximum portability across Linux, macOS, Windows.

## Tech Stack

- **Language:** Go 1.21+ (Pure Go, no CGO)
- **Distribution:** Binary (curl install), Homebrew, Docker
- **Dependencies:** Minimal. No tree-sitter, no heavy external libraries

## Architecture: Dumb Client → Fly.io API

```
User's Machine          Inkog Cloud (Fly.io)
┌─────────────────┐     ┌──────────────────────┐
│  Local Scan     │────→│  REST API Server     │
│  (Secrets)      │     │  (Pure Go, Port 8080)│
│                 │     │                      │
│  • Detect       │────→│  Analysis Engine     │
│  • Redact       │     │  (Worker subprocess) │
│  • Upload       │     │                      │
└─────────────────┘     └──────────────────────┘
                              ↓
                        Structured Logs (Stderr)
                        JSON Response (Stdout)
```

**Key Principle:** The CLI is stateless. It sends redacted code, receives findings, and returns. No persistent state.

## Project Structure

```
inkog/ (inkog-io/inkog on GitHub)
├── cmd/
│   └── cli/              Main CLI entry point (cmd/cli/main.go)
├── pkg/
│   ├── cli/              Core CLI logic
│   │   ├── scanner.go    Hybrid scanning (local + remote)
│   │   ├── output.go     Rich text output formatting
│   │   └── uploader.go   Secure file upload
│   ├── patterns/
│   │   └── secrets/      **LOCAL ONLY** regex patterns for secrets
│   │                     (API keys, passwords, tokens, etc.)
│   └── contract/         Shared request/response types (from backend)
├── docs/
│   └── CLI_REFERENCE.md  Complete CLI documentation
├── README.md             Public-facing documentation
├── LICENSE               Apache 2.0
├── go.mod
└── CLAUDE.md             This file
```

## Development Rules

### Rule 1: Strict Isolation
- Zero imports from `inkog-backend/cmd` or `inkog-backend/pkg/ast_engine`
- If you need something from backend, define it in `pkg/contract` and import it

### Rule 2: Privacy First

**Secret Redaction Pipeline:**

```go
Step 1: Walk filesystem locally
Step 2: Detect secrets (regex) in each file
Step 3: Redact found secrets BEFORE upload
Step 4: Send only redacted content to server
Step 5: Server performs logic analysis on clean code
```

**Code Example:**
```go
// ✅ CORRECT: Redact before upload
secrets := DetectSecrets(filePath, content)
redacted := RedactSecrets(content, secrets)
uploader.SendToServer(redacted)  // secrets NOT in upload

// ❌ WRONG: Sending secrets to server
uploader.SendToServer(content)   // Could expose secrets!
```

### Rule 3: Output Quality

Output must be **"Screenshot Ready"** for social media and documentation:

- Use ASCII tables (not JSON in default output)
- Rich formatting (colors, icons, box-drawing)
- Severity-based grouping
- Show remediation guidance
- Include CWE/CVSS metadata

**Example:**
```
╔════════════════════════════════════════════════════════╗
║           🔍 Inkog Security Scan Results               ║
╚════════════════════════════════════════════════════════╝

🔴 CRITICAL (1 finding)
  └─ Hardcoded API Key [agent.py:42]
     CWE-798 | CVSS 9.1 | OWASP A01

🟠 HIGH (3 findings)
  ├─ SQL Injection Risk [database.py:15]
  ├─ Infinite Loop [agent.py:95]
  └─ Eval Usage [agent.py:189]

Risk Score: 65/100
```

### Rule 4: Contract Alignment

The CLI output must match `pkg/contract` structs exactly:

```go
type Finding struct {
    ID         string
    PatternID  string
    File       string
    Line       int
    Column     int
    Severity   string  // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    Confidence float32
    CWE        string
    Message    string
    // ... more fields
}
```

Validate every Finding before displaying. If a field is missing, don't crash—show a placeholder.

## Development Workflow

### Test Locally (No Server)
```bash
# Detects secrets locally, no server upload
go run cmd/cli/main.go -path ../demo_agent
```

### Build Binary
```bash
# Pure Go, no CGO
CGO_ENABLED=0 go build -o inkog cmd/cli/main.go
```

### Test Against Local Server
```bash
# Terminal 1: Start backend server locally
cd ../inkog-backend
go run cmd/server/main.go

# Terminal 2: Run CLI against local server
./inkog -path ../demo_agent -server http://localhost:8080
```

### Test Against Fly.io Production
```bash
# Uses default Fly.io endpoint (https://inkog-api.fly.dev)
./inkog -path ../demo_agent
```

### Distribution Channels
```bash
# Homebrew (tap setup)
brew install inkog-io/inkog/inkog

# Docker (from GitHub Container Registry)
docker run -v $(pwd):/app ghcr.io/inkog-io/inkog:latest /app

# Direct binary download
curl -L https://releases.inkog.io/inkog-latest-darwin | tar xz

# GitHub Releases
https://github.com/inkog-io/inkog/releases
```

## Secret Patterns (pkg/patterns/secrets)

These are **client-side only**. Never send raw patterns to server.

Supported patterns:
- ✅ API Keys (AWS, GitHub, OpenAI, Stripe)
- ✅ Passwords (hardcoded in code)
- ✅ Tokens (JWT, OAuth, bearer)
- ✅ Database URLs (connection strings)
- ✅ SSH Private Keys
- ✅ Certificates (PEM format)

**Adding a new pattern:**
```go
// patterns/secrets/newpattern.go
var NewPatternRegex = regexp.MustCompile(`regex_here`)

func DetectNewPattern(content []byte) []Finding {
    // Detection logic
}
```

## Hybrid Scanning Architecture

```
┌─────────────────────────────────────────────────┐
│          CLI Hybrid Scanner Flow                 │
├─────────────────────────────────────────────────┤
│ 1. Scan for secrets locally (REGEX)             │
│ 2. Redact secrets from files                    │
│ 3. Upload REDACTED content to server            │
│ 4. Server analyzes redacted code (AST + logic)  │
│ 5. Merge local + remote results                 │
│ 6. Display unified report                       │
└─────────────────────────────────────────────────┘
```

## Error Handling

Graceful degradation:

- Server unreachable? → Show local secrets only (offline mode)
- Parse error on file? → Log warning, continue scanning
- Invalid response from server? → Show partial results
- Redaction failed? → Block upload (privacy first!)
- Fly.io API timeout? → Fallback to local findings

All errors logged to stderr. Findings always logged to stdout (JSON or text).

## Public vs. Private: The Dual Codebase

This repository (`inkog-io/inkog`) is **100% open source** (Apache 2.0). It contains:
- ✅ CLI logic (scanning, output, communication)
- ✅ Client-side secret detection (local regex patterns)
- ✅ API contract types (request/response schemas)

The **core vulnerability detection logic** lives in the private `inkog-backend` repository:
- Private: AST analysis engine, vulnerability patterns, machine learning models
- Private: Compliance mappings, remediation guidance, pattern metadata

**Key:** The CLI is a thin, dumb client. It sends redacted code to the backend API, which returns findings. The CLI never knows _how_ the backend works, only the contract.

## Contributing

**Before adding a feature to the CLI:**

1. ✅ Does it depend on tree-sitter? → REJECT (client-only)
2. ✅ Does it export secrets? → REJECT (privacy first)
3. ✅ Is output "screenshot ready"? → ACCEPT
4. ✅ Does it align with `pkg/contract`? → ACCEPT
5. ✅ Can it work offline? → IDEAL (fallback mode)

**For backend features:** These belong in `inkog-backend` (private repo). File a GitHub issue in this repo if you have a feature request.

## Commands

```bash
# Scan local directory (secrets only, no upload)
inkog -path /path/to/code

# Full hybrid scan with Fly.io API (default)
inkog -path /path/to/code
# Uses: https://inkog-api.fly.dev

# Full hybrid scan (explicit)
inkog -path /path/to/code -server https://inkog-api.fly.dev

# Self-hosted server
inkog -path /path/to/code -server https://inkog.company.internal

# Verbose output (see request/response details)
inkog -path /path/to/code -verbose

# Output as JSON (for CI/CD parsing)
inkog -path /path/to/code -output json > results.json

# Filter by severity
inkog -path /path/to/code -severity critical

# Show version
inkog -version
```

**Note:** This is a **dumb client**. It has no state, no configuration file, no cache. Every invocation is stateless.

## v1.0.0 Release Status

✅ **STABLE** - Ready for production use.

Core features:
- ✅ Local secret detection
- ✅ Hybrid scanning (local + Fly.io API)
- ✅ Multiple output formats (text, JSON, HTML)
- ✅ Structured logging (stderr)
- ✅ Offline fallback mode
- ✅ Auth middleware (ready for monetization)
- ✅ Docker distribution

## Future Roadmap

**CLI Features (This Repository):**
- [ ] **Pre-commit hook** for local-only scanning
- [ ] **GitHub Action** for automated PR scans
- [ ] **SARIF output** for GitHub Security tab integration
- [ ] **Performance:** Parallel file scanning
- [ ] **UX:** Interactive severity filtering in terminal

**Backend Features (Private Repository):**
- [ ] Extended language support (Go, Rust, Java)
- [ ] Taint tracking across function boundaries
- [ ] LLM-powered remediation suggestions
- [ ] Custom rule engine

**Ecosystem (Future Products):**
- [ ] **VS Code Extension:** Real-time scanning
- [ ] **Python/JavaScript SDK:** Programmatic API
- [ ] **Inkog Cloud Dashboard:** Team reporting & trends
