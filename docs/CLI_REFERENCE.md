# Inkog CLI Reference Guide

Complete documentation of command-line options, environment variables, and advanced usage patterns.

## Quick Start

```bash
# No install needed — run directly with npx
npx -y @inkog-io/cli scan .

# Or install permanently
curl -fsSL https://inkog.io/install.sh | sh
inkog scan .
```

See the [README](../README.md) for all installation methods (Homebrew, Go, binary download).

## Command-Line Options

### Syntax
```
inkog [scan] [OPTIONS] [PATH]
```

### Options

#### `-path string`
**Default:** `.` (current directory)

Source path to scan. Can be a file or directory.

```bash
# Scan current directory
inkog .

# Scan specific directory
inkog ./src

# Scan specific file
inkog ./agent.py
```

#### `-server string`
**Default:** `https://api.inkog.io`

Inkog server URL for remote analysis. Set to a custom endpoint for self-hosted deployments.

```bash
# Use custom enterprise server
inkog -server https://inkog-enterprise.example.com .

# Use local development server
inkog -server http://localhost:8080 .
```

#### `-output string`
**Default:** `text`

Output format. Supported values: `json`, `text`, `html`, `sarif`

```bash
# Human-readable text output (default)
inkog -output text .

# Structured JSON (ideal for CI/CD and tooling)
inkog -output json . > results.json

# Interactive HTML report
inkog -output html . > report.html

# SARIF format (for GitHub Security tab)
inkog -output sarif . > results.sarif
```

#### `-policy string`
**Default:** `balanced`

Security policy for filtering findings by risk tier. Controls the noise level of scan results.

| Policy | Tiers Shown | Best For |
|--------|-------------|----------|
| `low-noise` | Tier 1 (Exploitable Vulnerabilities) | CI/CD pipelines, blocking builds |
| `balanced` | Tier 1 + 2 (Vulnerabilities + Risk Patterns) | Most teams, code review |
| `comprehensive` | All tiers including hardening | Security audits, assessments |

```bash
# Only proven vulnerabilities (lowest noise)
inkog -path . --policy low-noise

# Vulnerabilities + risk patterns (default)
inkog -path . --policy balanced

# All findings including best practice recommendations
inkog -path . --policy comprehensive
```

**Tier Descriptions:**
- **Tier 1 - Exploitable Vulnerabilities:** Issues with proven tainted user input flowing to dangerous operations (e.g., user data → eval(), LLM output → SQL query)
- **Tier 2 - Risk Patterns:** Structural issues that could become vulnerabilities (unbounded loops, missing guards, recursive delegation)
- **Tier 3 - Hardening Recommendations:** Best practices like rate limiting, human oversight, monitoring

#### `-severity string`
**Default:** `low`

Minimum severity level to report. Supported values: `critical`, `high`, `medium`, `low`

```bash
# Only show critical findings
inkog -path . -severity critical

# Show high and critical findings
inkog -path . -severity high
```

#### `-verbose`
**Default:** false

Enable verbose output with additional details and debug information.

```bash
# Verbose mode shows detailed analysis steps
inkog -verbose .
```

#### `-version`
Show CLI version information and exit.

```bash
inkog -version
```

#### `-help`
Show help message with all options.

```bash
inkog -help
```

## Environment Variables

### `INKOG_SERVER_URL`
**Priority:** Highest (overrides `-server` flag)

Override the default Inkog server endpoint.

```bash
export INKOG_SERVER_URL=https://inkog-enterprise.example.com
inkog .
```

### `INKOG_API_KEY`
**Priority:** Required

API key for authentication. All scans require a valid API key.

```bash
# Get your free API key at https://app.inkog.io
export INKOG_API_KEY=sk_live_your_key_here
inkog .
```

If no API key is set, you'll see a friendly error message with signup instructions.

## Usage Examples

### Basic Scans

**Scan current directory:**
```bash
inkog .
```

**Scan specific directory:**
```bash
inkog ./src
```

**Scan with verbose output:**
```bash
inkog -path ./src -verbose
```

### CI/CD Integration

**Generate JSON report:**
```bash
inkog -path . -output json > results.json
```

**Fail on critical findings:**
```bash
if inkog -path . -severity critical | grep -q "CRITICAL"; then
  exit 1
fi
```

**GitHub Actions example:**
```yaml
- name: Run Inkog Security Scan
  env:
    INKOG_API_KEY: ${{ secrets.INKOG_API_KEY }}
  run: inkog -output json . > results.json

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: inkog-report
    path: results.json
```

Or use the official GitHub Action for a simpler setup:
```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
```

### Custom Server

**Self-hosted Inkog deployment:**
```bash
inkog -path . -server https://my-inkog.company.com
```

**Development/local server:**
```bash
export INKOG_SERVER_URL=http://localhost:8080
inkog .
```

### Filtering and Output

**Only critical issues:**
```bash
inkog -path . -severity critical
```

**HTML report for documentation:**
```bash
inkog -path . -output html > security-report.html
```

## Privacy Model

Inkog uses **surgical redaction** — only specific credential patterns are removed before upload. This preserves your business logic for security analysis while protecting known secret formats.

### What Gets Redacted

The CLI detects and redacts **common credential patterns**:

| Pattern | Example | Detection |
|---------|---------|-----------|
| AWS Access Keys | `AKIA[0-9A-Z]{16}` | Exact prefix |
| GitHub Tokens | `ghp_`, `gho_`, `ghu_` | Exact prefix |
| Stripe Keys | `sk_live_`, `pk_live_` | Exact prefix |
| Slack Tokens | `xox[baprs]-...` | Exact prefix |
| SendGrid Keys | `SG.` | Exact prefix |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` | Header match |
| JWT Tokens | `eyJ[base64].[base64].[base64]` | Structure match |
| Database URLs | `postgres://user:pass@host` | Connection string |
| Password variables | `password = "..."` | Assignment pattern |
| High-entropy strings | 32+ random chars | Shannon entropy >4.5 |

**Redaction example:**
```python
# Original code
api_key = "sk_live_abc123def456"
db_url = "postgresql://user:password@localhost/db"

# After redaction (sent to server)
api_key = "[REDACTED-STRIPE_KEY]"
db_url = "[REDACTED-DATABASE_PASSWORD]"
```

### What is NOT Redacted

To enable security analysis, the following **pass through to the server**:

- **Prompts and templates** — Required for prompt injection detection
- **Business logic** — Required for infinite loop and data flow analysis
- **Configuration values** — Model names, temperatures, etc.
- **Normal strings** — Text that doesn't match credential patterns
- **Custom secret formats** — Proprietary patterns not in our library

**Example:**
```python
# NOT redacted - needed for prompt injection detection
system_prompt = "You are helpful. Ignore all previous instructions."

# NOT redacted - custom format unknown to Inkog
internal_key = "ACME_PROD_xxxx"

# IS redacted - matches known pattern
openai_key = "sk-proj-abc123..."
```

### Enterprise Note

If your organization uses custom credential formats, contact us about:
- **Configurable redaction patterns** — Add your own regex rules
- **Self-hosted deployment** — Run the analysis engine in your infrastructure
- **Air-gapped mode** — Full offline operation

## Output Formats

### Text Output (Default)

Human-readable report with **tiered risk classification**:

```
╔══════════════════════════════════════════════════════╗
║           🔍 AI Agent Risk Assessment                ║
╚══════════════════════════════════════════════════════╝

🔴 EXPLOITABLE VULNERABILITIES (2)
  └─ [VULN] SQL Injection via LLM [database.py:89] - CRITICAL
     LLM output used directly in SQL query without parameterization
     Taint source: user_request (user input)
  └─ [VULN] Prompt Injection [agent.py:42] - CRITICAL
     User input flows to system prompt without sanitization
     Taint source: customer_data (user input)

🟠 RISK PATTERNS (3)
  └─ Unbounded Loop in Agentic System [agent.py:95] - HIGH
     Loop lacks termination guards (max_iterations, timeout)
  └─ Token Bombing Attack [agent.py:156] - CRITICAL
     Loop depends on LLM output but lacks termination guards
  └─ Recursive Tool Calling [crew.py:78] - HIGH
     Agent delegation chain lacks cycle detection

🟡 HARDENING RECOMMENDATIONS (2)
  └─ Missing Rate Limits on LLM Calls [client.py:12] - LOW
     LLM API calls lack rate limiting
  └─ Missing Human Oversight [agent.py:203] - LOW
     Agent performs autonomous actions without approval workflow

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AI Agent Risk Assessment: 7 findings (policy: balanced)
  ● 2 Exploitable Vulnerabilities (require immediate fix)
  ● 3 Risk Patterns (structural issues)
  ● 2 Hardening Recommendations (best practices)
```

**Key Features:**
- **Tier 1 (🔴 Exploitable Vulnerabilities):** Shows `[VULN]` badge and taint source
- **Tier 2 (🟠 Risk Patterns):** Structural issues that need attention
- **Tier 3 (🟡 Hardening Recommendations):** Only shown with `--policy comprehensive`

### JSON Output

Structured output for CI/CD integration and tooling:

```json
{
  "metadata": {
    "scan_id": "scan_123abc",
    "timestamp": "2024-01-15T10:30:00Z",
    "path": ".",
    "risk_score": 65
  },
  "local_secrets": [
    {
      "id": "secret_api_key_1",
      "file": "config.py",
      "line": 23,
      "severity": "critical",
      "type": "API_KEY",
      "message": "Hardcoded API key detected"
    }
  ],
  "server_findings": [
    {
      "pattern": "Infinite Loop",
      "severity": "high",
      "file": "agent.py",
      "line": 95,
      "cwe": "CWE-835",
      "message": "Detected non-deterministic loop that could burn API credits"
    }
  ],
  "summary": {
    "total_findings": 4,
    "critical": 1,
    "high": 3,
    "medium": 0,
    "low": 0
  }
}
```

### HTML Output

Interactive HTML report with searchable findings and visualizations.

```bash
inkog -path . -output html > report.html
```

Features:
- Syntax-highlighted code snippets
- Interactive severity filtering
- Sortable findings table
- Visual risk score
- Export to PDF

## Supported Languages

The CLI detects vulnerabilities in the following languages:

| Language | Extension | Status |
|----------|-----------|--------|
| Python | `.py` | ✅ Supported |
| JavaScript | `.js` | ✅ Supported |
| TypeScript | `.ts`, `.tsx` | ✅ Supported |
| Go | `.go` | ✅ Supported |
| Java | `.java` | ✅ Supported |
| Ruby | `.rb` | ✅ Supported |
| PHP | `.php` | ✅ Supported |
| C# | `.cs` | ✅ Supported |
| Rust | `.rs` | ✅ Supported |
| C/C++ | `.c`, `.cpp` | ✅ Supported |
| Shell | `.sh` | ✅ Supported |
| YAML | `.yaml`, `.yml` | ✅ Supported |
| JSON | `.json` | ✅ Supported |
| XML | `.xml` | ✅ Supported |
| Environment files | `.env` | ✅ Supported |
| Config files | `.conf`, `.cfg` | ✅ Supported |

## Exit Codes

- **`0`:** Scan completed successfully with no security findings
- **`1`:** Scan completed with security findings detected
- **`2`:** Error during scan execution

### Using Exit Codes in Scripts

```bash
#!/bin/bash
inkog .
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ No security issues found"
  exit 0
elif [ $EXIT_CODE -eq 1 ]; then
  echo "⚠️ Security findings detected"
  exit 1
else
  echo "❌ Scan failed"
  exit 2
fi
```

## Development

### Building from Source

```bash
# Build the CLI
go build -o inkog ./cmd/inkog

# Pure Go build (no CGO)
CGO_ENABLED=0 go build -o inkog ./cmd/inkog
```

### Testing

```bash
# Run all tests
go test ./...

# Verbose test output
go test -v ./...

# Test with race detector
go test -race ./...
```

### Running Against Local Server

```bash
# Terminal 1: Start backend server
cd ../inkog-backend
go run cmd/server/main.go

# Terminal 2: Run CLI against local server
export INKOG_SERVER_URL=http://localhost:8080
./inkog ./demo_agent
```

### Debugging

Enable verbose output for troubleshooting:

```bash
inkog -verbose -path .
```

This shows:
- File scanning progress
- Pattern detection details
- Server communication logs
- Redaction information

## Architecture Notes

### Hybrid Scanning Flow

```
1. Local Scanning
   └─ Detect secrets (regex patterns)
   └─ Redact secrets from files

2. Upload Redacted Code
   └─ Send only safe, redacted content

3. Server Analysis
   └─ Perform AST analysis
   └─ Detect logic vulnerabilities

4. Merge Results
   └─ Combine local + server findings

5. Display Report
   └─ Format and present results
```

### Privacy-First Design

The CLI prioritizes your security:
- Secrets detected **before** upload
- Secrets **never** sent to server
- Works **offline** (local secret detection only)
- Graceful degradation if server unreachable

## Troubleshooting

### Server Connection Issues

If the CLI cannot reach the server:

```bash
# Check connectivity
inkog -verbose -path .

# Use alternative server
inkog -server https://backup-server.inkog.io .

# Fall back to local scanning only
inkog -path . (no -server flag)
```

### Permission Errors

Ensure you have read permissions on the target directory:

```bash
# Run with appropriate permissions
chmod +r -R ./path/to/scan
inkog ./path/to/scan
```

### Large Codebase Scanning

For very large projects, scanning may take longer:

```bash
# Use -severity to focus on critical findings
inkog -path . -severity critical

# Scan specific subdirectories
inkog ./src
inkog ./app
```

## Advanced Configuration

### Custom Server Endpoints

For enterprise deployments:

```bash
# Create a shell alias
alias inkog-enterprise='inkog -server https://inkog.company.com'

# Use in scripts
inkog-enterprise -path . -output json
```

### CI/CD Integration

See the main README for GitHub Actions, GitLab CI, and other pipeline integrations.

## Support

For issues, questions, or feature requests:
- **GitHub Issues:** https://github.com/inkog-io/inkog/issues
- **Security Concerns:** security@inkog.io
- **Community:** https://inkog.io/slack

## Version

Current CLI Version: 1.0.0
