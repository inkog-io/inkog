# Inkog CLI - Hybrid Privacy Security Scanner

The public CLI for Inkog, a security scanner designed for AI agent and LLM applications. This repository contains the command-line interface that performs client-side secret detection and communicates with the Inkog backend for advanced logic analysis.

## Overview

Inkog uses a **hybrid privacy model** to protect your code while providing comprehensive security scanning:

1. **Local Secret Detection**: Secrets (API keys, tokens, credentials) are detected and redacted on your machine
2. **Server-Side Analysis**: Redacted code is sent to the Inkog server for logic analysis
3. **Privacy First**: Your actual secrets never leave your local environment
4. **Complete Scanning**: Server analysis detects complex vulnerabilities like infinite loops, token bombing, and prompt injection

## Features

- **Local Secret Detection**: Identifies hardcoded credentials in your codebase
- **Client-Side Privacy**: Secrets are redacted before any data leaves your machine
- **Hybrid Scanning**: Combines local pattern matching with server-side AST analysis
- **Multiple Output Formats**: JSON, text, and HTML reports
- **CI/CD Integration**: Easy integration into automated pipelines

## Installation

```bash
go install github.com/inkog-io/inkog-cli/cmd/cli@latest
```

Or build from source:

```bash
go build -o inkog ./cmd/cli
```

## Usage

### Basic Scan

```bash
inkog /path/to/your/project
```

### Scan with Verbose Output

```bash
inkog -path ./src -verbose
```

### JSON Output for CI/CD

```bash
inkog -path . -output json > results.json
```

### Custom Server URL

```bash
inkog -path . -server https://your-inkog-server.com
```

### Filter by Severity

```bash
inkog -path . -severity high
```

## Configuration

### Environment Variables

- `INKOG_SERVER_URL`: Override the default server endpoint (highest priority)
  ```bash
  export INKOG_SERVER_URL=https://inkog-enterprise.example.com
  inkog .
  ```

- `INKOG_API_KEY`: API key for authentication (optional, for future use)

### Default Server

The CLI defaults to `http://localhost:8080` for development. For production, set:

```bash
export INKOG_SERVER_URL=https://api.inkog.io
```

## Command-Line Options

```
Usage:
  inkog [OPTIONS] [PATH]

Options:
  -path string        Source path to scan (default: .)
  -server string      Inkog server URL (default: https://api.inkog.io)
  -output string      Output format: json, text, html (default: text)
  -severity string    Minimum severity level: critical, high, medium, low (default: low)
  -verbose            Enable verbose output
  -version            Show version information
  -help               Show this help message

Examples:
  # Scan current directory
  inkog .

  # Scan with verbose output
  inkog -path ./src -verbose

  # Scan and output as JSON
  inkog -path . -output json

  # Scan using custom server
  inkog -path . -server https://inkog-enterprise.example.com
```

## Privacy Model

### What Stays Local

- Your API keys and credentials
- Private authentication tokens
- Database connection strings
- Any data identified as a "secret"

### What Gets Sent to Server

- Redacted source code (with secrets replaced)
- File structure and relationships
- Control flow patterns (for logic analysis)
- Metadata (line numbers, severity levels)

### How Redaction Works

The CLI uses pattern-based detection to identify secrets:
- AWS credentials
- API keys (various providers)
- Private keys
- Database passwords
- OAuth tokens
- And more...

Identified secrets are replaced with `[REDACTED_<TYPE>]` before sending to the server.

## Output Formats

### Text (Default)

Human-readable report with color-coded severity levels and detailed explanations.

### JSON

Structured output for integration with CI/CD pipelines:

```json
{
  "local_secrets": [
    {
      "id": "secret_api_key_123_1",
      "file": "config.py",
      "line": 123,
      "severity": "critical",
      "message": "Hardcoded API key detected"
    }
  ],
  "server_findings": [
    {
      "pattern": "Infinite Loop",
      "severity": "high",
      "file": "agent.py",
      "line": 45
    }
  ],
  "all_findings": [...]
}
```

### HTML

Interactive HTML report with searchable findings and visualizations.

## Supported Languages

- Python (.py)
- JavaScript (.js)
- TypeScript (.ts, .tsx)
- Go (.go)
- Java (.java)
- Ruby (.rb)
- PHP (.php)
- C# (.cs)
- Rust (.rs)
- C/C++ (.c, .cpp)
- Shell scripts (.sh)
- YAML (.yaml, .yml)
- JSON (.json)
- XML (.xml)
- Environment files (.env)
- Config files (.conf, .cfg)

## Exit Codes

- `0`: Scan completed successfully with no security issues
- `1`: Scan completed with security findings detected

## Development

### Building

```bash
go build -o inkog ./cmd/cli
```

### Testing

```bash
go test ./...
```

### Running Against Local Server

```bash
export INKOG_SERVER_URL=http://localhost:8080
inkog ./demo_agent
```

## Architecture

This repository is the **PUBLIC** part of Inkog:

- **Public**: CLI code, CLI contracts, client-side secret detection
- **Private**: Backend detection logic, AST analysis engine, vulnerability registry

The CLI communicates with the backend server via a well-defined contract (`pkg/contract/contract.go`).

## Related Repositories

- **inkog-backend** (Private): Detection engine, AST analysis, security patterns
- **inkog-product** (Monolithic): Development and testing repository

## License

Proprietary - Inkog Inc.

## Support

For issues, questions, or security concerns:
- GitHub Issues: https://github.com/inkog-io/inkog-cli/issues
- Security: security@inkog.io

## Version

Current Version: 1.0.0
