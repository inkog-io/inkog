# Inkog Ecosystem: The Face

## Vision

The CLI is the **primary entry point** for developers. It prioritizes three pillars:

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

## Project Structure

```
inkog-cli/
├── cmd/
│   └── cli/              Main CLI entry point
├── pkg/
│   ├── cli/              Core CLI logic
│   │   ├── scanner.go    Hybrid scanning (local + remote)
│   │   ├── output.go     Rich text output formatting
│   │   └── uploader.go   Secure file upload
│   ├── patterns/
│   │   └── secrets/      **LOCAL ONLY** regex patterns for secrets
│   │                     (API keys, passwords, tokens, etc.)
│   └── contract/         Shared request/response types (from backend)
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

### Test Locally
```bash
go run cmd/cli/main.go -path ../demo_agent
```

### Build Binary
```bash
CGO_ENABLED=0 go build -o inkog cmd/cli/main.go
```

### Test Against Local Server
```bash
# Terminal 1: Start backend
cd ../inkog-backend
go run cmd/server/main.go

# Terminal 2: Run CLI
./inkog -path ../demo_agent -server http://localhost:8080
```

### Distribution
```bash
# Homebrew (tap setup needed)
brew install inkog-io/inkog/inkog

# Docker
docker run inkog:latest -path /src

# Direct binary
curl https://releases.inkog.io/inkog-latest-darwin | tar xz
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

- Server unreachable? → Show local secrets only
- Parse error on file? → Log warning, continue scanning
- Invalid response from server? → Show partial results
- Redaction failed? → Block upload (privacy first!)

## Contributing

Before adding a feature:

1. ✅ Does it depend on tree-sitter? → REJECT
2. ✅ Does it export secrets? → REJECT
3. ✅ Is output "screenshot ready"? → ACCEPT
4. ✅ Does it align with pkg/contract? → ACCEPT

## Commands

```bash
# Scan local directory (secrets only, no upload)
inkog -path /path/to/code

# Full hybrid scan with server
inkog -path /path/to/code -server https://api.inkog.io

# Custom server (self-hosted)
inkog -path /path/to/code -server https://my-inkog.company.com

# Verbose output
inkog -path /path/to/code -verbose

# Output as JSON (for CI/CD)
inkog -path /path/to/code -format json > results.json

# Fail if CRITICAL findings exist (for CI/CD gates)
inkog -path /path/to/code -fail-on critical
```

## Future Roadmap

- [ ] **IDE Extensions:** VS Code, JetBrains, Sublime
- [ ] **CI/CD Integration:** GitHub Actions, GitLab CI, CircleCI
- [ ] **Report Export:** HTML, PDF, SARIF formats
- [ ] **Custom Rules:** User-defined pattern definitions
- [ ] **Python SDK:** `pip install inkog` for programmatic access
