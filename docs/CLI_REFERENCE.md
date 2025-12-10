# Inkog CLI Reference Guide

Complete documentation of command-line options, environment variables, and advanced usage patterns.

## Command-Line Options

### Syntax
```
inkog [OPTIONS] [PATH]
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
**Default:** `https://inkog-api.fly.dev`

Inkog server URL for remote analysis. Set to a custom endpoint for self-hosted deployments.

```bash
# Use custom enterprise server
inkog -server https://inkog-enterprise.example.com .

# Use local development server
inkog -server http://localhost:8080 .
```

#### `-output string`
**Default:** `text`

Output format. Supported values: `json`, `text`, `html`

```bash
# Human-readable text output (default)
inkog -path . -output text

# Structured JSON (ideal for CI/CD and tooling)
inkog -path . -output json > results.json

# Interactive HTML report
inkog -path . -output html > report.html
```

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
**Priority:** Optional (reserved for future use)

API key for authentication with enterprise servers.

```bash
export INKOG_API_KEY=your-api-key-here
inkog .
```

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
  run: inkog -path . -output json > results.json

- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: inkog-report
    path: results.json
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

Human-readable report with color-coded severity levels:

```
╔════════════════════════════════════════════════════════╗
║           🔍 Inkog Security Scan Results               ║
╚════════════════════════════════════════════════════════╝

🔴 CRITICAL (1 finding)
  └─ Hardcoded API Key [agent.py:42]
     CWE-798 | CVSS 9.1

🟠 HIGH (3 findings)
  ├─ Infinite Loop [agent.py:95]
  ├─ Token Bombing Risk [agent.py:156]
  └─ Prompt Injection [agent.py:203]

Risk Score: 65/100
```

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
go build -o inkog ./cmd/cli

# Pure Go build (no CGO)
CGO_ENABLED=0 go build -o inkog ./cmd/cli
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
