# Using Inkog with AG2

[AG2](https://github.com/ag2ai/ag2) is an open-source multi-agent framework founded by Chi Wang and Qingyun Wu — the original creators of AutoGen — who left Microsoft in late 2024 to build AG2 under open, community governance. AG2 inherits the familiar AutoGen 0.2 architecture and continues active development at [ag2ai/ag2](https://github.com/ag2ai/ag2), while Microsoft's AutoGen 0.4 went in a separate direction.

> **Namespace note:** AG2 uses `from autogen import ...` as its canonical Python namespace. The `ag2`, `autogen`, and `pyautogen` packages on PyPI are all aliases that install the same AG2 framework. Inkog detects both `from autogen` and `from ag2` imports and labels them as **AG2**.

---

## What Inkog Finds in AG2 Projects

Inkog performs two layers of analysis on AG2 code:

1. **Local secret detection** — finds hardcoded API keys, tokens, and credentials before they leave your machine, then redacts them before upload
2. **Server-side vulnerability analysis** — analyzes your agent architecture for LLM-specific risks: prompt injection paths, tool misuse, excessive permissions, insecure data handling, and more

---

## Common Vulnerabilities in AG2 Code

### Hardcoded API Keys in LLMConfig

The most frequent finding in AG2 projects. Developers often hardcode keys during prototyping and forget to move them to environment variables.

```python
# BAD — inkog detects and flags this
from autogen import ConversableAgent, LLMConfig

llm_config = LLMConfig(
    model="gpt-4o-mini",
    api_key="sk-proj-abc123...",  # hardcoded key
)
```

```python
# GOOD — load from environment
import os
from autogen import ConversableAgent, LLMConfig

llm_config = LLMConfig(
    model="gpt-4o-mini",
    api_key=os.environ["OPENAI_API_KEY"],
)
```

### API Keys in OAI_CONFIG_LIST

AG2 projects often use a `OAI_CONFIG_LIST` file for LLM configuration. Committing this file with real keys is a common source of credential leaks.

```json
[
  {
    "model": "gpt-4o-mini",
    "api_key": "sk-proj-abc123..."
  }
]
```

Add `OAI_CONFIG_LIST` to your `.gitignore` and use `OAI_CONFIG_LIST_sample` (with placeholder values) as the committed template instead.

### API Keys in Tool Configuration

Tool definitions that call external APIs often embed credentials directly:

```python
# BAD — API key hardcoded in tool config
def search_web(query: str) -> str:
    headers = {"Authorization": "Bearer serpapi-key-xyz789"}
    ...
```

### Overly Permissive Code Execution

AG2's `UserProxyAgent` can execute code locally. Unrestricted execution is a significant risk:

```python
# BAD — no sandbox, no restrictions
user_proxy = UserProxyAgent(
    name="executor",
    code_execution_config={"work_dir": "/", "use_docker": False},
)
```

---

## Multi-Agent Research Assistant — Example Walkthrough

A typical AG2 multi-agent setup uses a `GroupChat` with specialized agents:

```python
# research_team.py  (AG2 0.11)
import os
from autogen import ConversableAgent, GroupChat, GroupChatManager, LLMConfig

llm_config = LLMConfig(
    model="gpt-4o-mini",
    api_key=os.environ["OPENAI_API_KEY"],
)

researcher = ConversableAgent(
    name="researcher",
    system_message="You are a research specialist. Search and gather information.",
    llm_config=llm_config,
)

summarizer = ConversableAgent(
    name="summarizer",
    system_message="You synthesize research findings into clear summaries.",
    llm_config=llm_config,
)

critic = ConversableAgent(
    name="critic",
    system_message="You review summaries for accuracy and gaps.",
    llm_config=llm_config,
)

group_chat = GroupChat(
    agents=[researcher, summarizer, critic],
    messages=[],
    max_round=6,
)

manager = GroupChatManager(groupchat=group_chat, llm_config=llm_config)

researcher.initiate_chat(manager, message="Research the latest developments in agentic AI security.")
```

Running `inkog` on this project scans for hardcoded credentials across all files and sends the redacted code to the Inkog backend for vulnerability analysis — checking for prompt injection risks in system messages, tool permission issues, and data handling patterns.

---

## Quickstart

```bash
# Install inkog
curl -fsSL https://inkog.io/install.sh | sh

# Set your API key
export INKOG_API_KEY=sk_live_...   # get one at https://app.inkog.io

# Scan your AG2 project
inkog -path ./my-ag2-project

# JSON output for programmatic use
inkog -path . -output json > security-report.json

# Only show high-severity findings
inkog -path . -policy low-noise
```

Inkog automatically detects the AG2 framework from your imports and labels the report accordingly.

---

## CI/CD Integration

Add security scanning to your AG2 project's GitHub Actions workflow:

```yaml
- name: Scan AG2 agent for vulnerabilities
  uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    policy: balanced
    sarif-upload: true   # uploads to GitHub Security tab
```

For diff mode (only fail on new findings compared to a baseline):

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    diff: true
    baseline: .inkog-baseline.json
```

---

## Distinguishing AG2 from Microsoft AutoGen 0.4

Inkog detects both frameworks:

| Import pattern | Detected as |
|---------------|-------------|
| `from autogen import ...` | **AG2** |
| `from ag2 import ...` | **AG2** |
| `from autogen_agentchat import ...` | **AutoGen** (Microsoft v0.4) |
| `from autogen_core import ...` | **AutoGen** (Microsoft v0.4) |
| Directory named `ag2/` | **AG2** |
| Directory named `autogen/` | **AutoGen** |

---

## Further Reading

- [AG2 Documentation](https://docs.ag2.ai/)
- [AG2 GitHub](https://github.com/ag2ai/ag2)
- [Build with AG2 — example projects](https://github.com/ag2ai/build-with-ag2)
- [AG2 release notes](https://github.com/ag2ai/ag2/releases)
- [Inkog CLI reference](./CLI_REFERENCE.md)
- [Inkog GitHub Action](https://docs.inkog.io/ci-cd/github-action)
