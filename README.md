# README.md content:

# Inkog - AI Agent Security Scanner

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue)](https://github.com/marketplace/actions/inkog-scanner)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

🛡️ Detect behavioral risks in AI agents before production deployment.

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

- 🎯 96% accuracy on prompt injection detection
- 🔄 Identifies infinite loops before they happen  
- 🔒 Detects data exposure risks
- 📊 EU AI Act compliance reports
- ⚡ Sub-10 second analysis

## Supported Frameworks

- LangChain
- CrewAI  
- AutoGen
- Custom Python/TypeScript agents

## Documentation

See [docs.inkog.ai](https://docs.inkog.ai) for full documentation.

## License

Apache 2.0
