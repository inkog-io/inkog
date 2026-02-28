<div align="center">

# Contributing to Inkog

**Welcome, Researcher.**

By contributing to Inkog, you join an elite network of engineers securing the Agentic AI stack.

[![Slack](https://img.shields.io/badge/Join-Slack_Community-blueviolet?style=for-the-badge)](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)

</div>

---

## Ways to Contribute

| Contribution | Impact | Skill Required |
|-------------|--------|----------------|
| **Rule Writing (YAML)** | Highest | Security knowledge only |
| **Core Engine (Go)** | High | Go, AST parsing |
| **Documentation** | High | Technical writing |
| **Bug Reports** | Medium | Reproducing issues |

---

## Quickstart: Write a Security Rule

The fastest path to contribution. **No Go experience required.**

### Prerequisites
- Knowledge of an attack pattern (prompt injection, infinite loops, token bombing, etc.)
- A text editor
- 15 minutes

### Step 1: Copy the Template

```bash
cp rules/template.yaml rules/my-new-rule.yaml
```

### Step 2: Define Your Pattern

```yaml
id: my-new-vulnerability
name: "Descriptive Name"
severity: HIGH
frameworks:
  - langchain
  - crewai

pattern:
  node_type: LLMCall
  condition: missing_rate_limit

message: |
  This agent makes unbounded LLM calls without rate limiting.
  An attacker could trigger infinite API spend.

cwe: CWE-770
references:
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/

metadata:
  author: your-github-handle
  created: 2024-12-06
```

### Step 3: Add a Test Case

Create a file that should trigger your rule:

```bash
# rules/tests/my-new-rule/vulnerable.py
```

```python
# This should be flagged by the rule
from langchain import LLMChain

chain = LLMChain(llm=llm, prompt=prompt)
while True:
    chain.run(user_input)  # No rate limit!
```

### Step 4: Open a Pull Request

```bash
git checkout -b rule/my-new-vulnerability
git add rules/
git commit -m "rule: Add detection for [vulnerability name]"
git push origin rule/my-new-vulnerability
```

Open a PR with:
- **Title:** `rule: [Brief description]`
- **Body:** Explain the attack vector and why this matters

---

## Rewards & Recognition

We believe contributors deserve more than a "thanks."

| Milestone | Reward |
|-----------|--------|
| **1 Merged Rule** | Name permanently in Rule Registry |
| **3 Merged Rules** | Exclusive "Inkog Researcher" swag pack |
| **5 Merged Rules** | "Triage" access (review incoming rules) |
| **10+ Rules** | "Maintainer" status + Direct Slack channel |

Your GitHub handle is embedded in every rule you write:

```yaml
metadata:
  author: your-handle  # <- This is permanent
```

---

## Development Setup

### Requirements

- Go 1.21+
- Docker (optional, for containerized testing)
- Git

### The Golden Path

```bash
# Clone the repository
git clone https://github.com/inkog-io/inkog.git
cd inkog

# Run the CLI locally
go run cmd/inkog/main.go -path ./examples

# Run tests
go test ./...

# Build the binary
go build -o inkog cmd/inkog/main.go
```

### Project Structure

```
inkog/
├── cmd/inkog/          # CLI entry point
├── pkg/
│   ├── cli/          # Scanner, output formatting
│   ├── contract/     # API types
│   └── patterns/     # Local detection patterns
├── rules/            # Community-contributed YAML rules
└── docs/             # Documentation
```

---

## Pull Request Guidelines

### Commit Messages

We follow conventional commits:

```
rule: Add detection for recursive tool calls
feat: Support SARIF output format
fix: Handle empty file edge case
docs: Update CLI reference
```

### PR Checklist

- [ ] Rule includes test case (if applicable)
- [ ] `go test ./...` passes
- [ ] No secrets or credentials in code
- [ ] Follows existing code style

### Security Scanning

Before submitting agent-related code, run Inkog to catch security issues:

```bash
npx -y @inkog-io/cli scan . --policy balanced
```

If you have the Inkog MCP server installed in Claude Code or Cursor, use the `inkog_scan` tool directly for inline security feedback.

---

## Governance & Licensing

### License Model

| Component | License | Why |
|-----------|---------|-----|
| **CLI (This Repo)** | Apache 2.0 | Enterprise-friendly, maximizes adoption |
| **Detection Rules** | Apache 2.0 | Maximizes adoption |
| **Backend (Server)** | Proprietary | Protects core IP |

This means:
- The CLI can be used anywhere (even proprietary projects)
- Rules you contribute can be used anywhere
- Your attribution is preserved

### Code of Conduct

We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
Be respectful. Assume good intent. Help others succeed.

---

## Getting Help

Stuck? We're here.

- **Slack:** [Join the community](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw)
- **Issues:** [Open a question](https://github.com/inkog-io/inkog/issues/new?labels=question)
- **Email:** hello@inkog.io

---

<div align="center">

**Thank you for securing the agent ecosystem.**

*Every rule you write protects thousands of developers.*

</div>
