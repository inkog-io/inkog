# Inkog - AI Agent Security Scanner

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue)](https://github.com/marketplace/actions/inkog-scanner)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

🛡️ Detect behavioral risks in AI agents before production deployment for Enterprises & Startups.

## Quick Start

```yaml
# .github/workflows/agent-security.yml
name: Agent Security Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: inkog-io/inkog@v1
        with:
          framework: langchain
          risk_threshold: medium
```

## Features

- 🎯 **96% Accuracy** - Proven patterns on prompt injection detection
- 🔄 **Pre-deployment Detection** - Identifies infinite loops before they happen
- 🔒 **Data Risk Detection** - Detects data exposure risks
- 📊 **EU AI Act Compliance** - Built for regulatory requirements (€35M fines starting Aug 2026)
- ⚡ **Sub-10 Second Analysis** - 5-minute GitHub integration

## Supported Frameworks

- LangChain
- CrewAI
- AutoGen
- Custom Python/TypeScript agents

## Technology

- **Language:** Go (0.88ms startup, not Python)
- **Parser:** tree-sitter (36x faster than alternatives)
- **Database:** PostgreSQL with JSONB
- **Infrastructure:** AWS Lambda + Docker + gVisor

## Pricing

- **Free:** 1,000 scans/month
- **Team:** $497/month
- **Enterprise:** $50K/year with compliance

## Getting Started

For GitHub Actions integration, see the [GitHub Action Documentation](./action/README.md).

For local CLI development, see [SETUP.md](./SETUP.md).

## Documentation

- [GitHub Action](./action/README.md) - Integration guide & usage
- [Architecture](./ARCHITECTURE.md) - Technical design
- [Setup Guide](./SETUP.md) - Developer setup
- [Roadmap](./ROADMAP.md) - What's coming next
- [Contributing](./CONTRIBUTING.md) - How to contribute
- Full docs: [docs.inkog.ai](https://docs.inkog.ai)

## Contributing

We're currently in early development. Contributions coming soon!

## License

Apache 2.0
