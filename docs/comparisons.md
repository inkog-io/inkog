# How Inkog compares

Honest comparison with the tools developers actually evaluate alongside Inkog. Where Inkog wins, where it loses, and where another tool is genuinely the better fit.

## Direct alternatives — same problem, same time of day (pre-deploy, code-level)

These are the tools you'd consider instead of Inkog if you're trying to ship a secure agent.

### [SplxAI Agentic Radar](https://github.com/splx-ai/agentic-radar)
**Closest direct competitor.** Static scanner for agentic workflows with topology visualization and prompt-hardening features. Excellent topology graph, established commercial backing (SplxAI), and **~30× more GitHub stars** than Inkog. Detects vulnerabilities and maps to a generic risk taxonomy.

**Where Inkog wins**: framework breadth (we cover 21 frameworks across code-first and no-code; they cover ~4 Python frameworks), article-level EU AI Act / NIST / ISO 42001 / OWASP mappings (they use a generic bucket taxonomy), MCP server auditing, AGENTS.md governance verification, MLBOM generation, no-code workflow support (n8n, Flowise, Langflow, Dify, Copilot Studio, Agentforce).

**Where they win**: bigger community, more mature topology visualization, longer track record, established commercial customer base.

### [Snyk Agent Scan](https://github.com/snyk/agent-scan)
**Different scan target.** Snyk scans your **developer environment** — `~/.claude`, Cursor, Windsurf, Gemini CLI, Codex configs — for installed MCP servers and agent skills. Detects prompt injection in skill definitions, tool poisoning, hardcoded secrets in MCP server manifests.

**Where Inkog wins**: we scan the **agent application code itself** (the LangGraph nodes, CrewAI crews, AutoGen workflows you're shipping). Compliance mappings, broader code-vulnerability detection (SQL injection via LLM, recursive tool-calling, RAG over-fetching), SARIF for the GitHub Security tab.

**Where they win**: Snyk brand and distribution, deeper coverage of the dev-environment ecosystem, explicit "agent skills" tool-shadowing and toxic-flow detection, much larger user base.

**Verdict**: not actually competitive — Snyk audits your laptop, Inkog audits your repo. Use both.

### [AgentShield](https://github.com/affaan-m/agentshield)
Tightly-focused OSS scanner for Claude Code configs (`.claude/`, settings.json, hooks, MCP servers, skills). Detects hardcoded secrets, permission misconfigs, hook injection, prompt-injection vectors. Has an auto-fix mode.

**Where Inkog wins**: vastly broader scope. AgentShield only audits Claude Code dev environments; Inkog audits the full agent codebase across 21 frameworks. Plus compliance mappings, MLBOM, MCP server auditing, SARIF.

**Where they win**: tightly focused on Claude Code (smaller scope = simpler UX), built-in `--fix` auto-remediation, three-agent deep-analysis pipeline.

### [Trent AI](https://trent.ai/)
Conversational security advisor for Claude Code / Lovable / OpenClaw — produces posture snapshots, prioritized remediation plans, and auto-applies fixes via Claude Code or CI.

**Where Inkog wins**: deterministic scanner with explicit findings and SARIF; Inkog covers any framework (Trent is Claude-Code-shaped). Inkog is a CLI you can drop into existing CI.

**Where they win**: continuous-loop UX with auto-remediation, deeper integration with Claude Code workflow, conversational design-time advisor (Inkog has none of this).

## Different category — complementary, not competitive

These tools solve a different part of the agent-security problem. **Use Inkog plus one of these**, not Inkog instead of them.

| Tool | What it does | Why it's not a replacement for Inkog |
|------|--------------|---------------------------------------|
| [Lakera AI Red Teaming](https://www.lakera.ai/ai-red-teaming) + Lakera Guard | Runtime adversarial probing + runtime guardrails on a deployed agent | Tests a running endpoint; can't see your code |
| [Microsoft AI Red Teaming Agent](https://learn.microsoft.com/en-us/azure/foundry/concepts/ai-red-teaming-agent) | Cloud-hosted runtime probing of Azure Foundry agents (PyRIT-based) | Azure-only; runtime, not pre-deploy |
| [Straiker](https://www.straiker.ai/) | Discover + Ascend (red-team) + Defend (runtime guardrails) | Behavioral / runtime; doesn't read source code |
| [Crucible Security](https://crucible-security.github.io/crucible-website/) | OSS adversarial scanner — 1,000+ attack vectors against an agent URL | Black-box runtime; needs a live endpoint |
| [NVIDIA Garak](https://github.com/NVIDIA/garak) | OSS LLM vulnerability scanner — probes for prompt injection, jailbreaks, data leakage | Runtime probing of LLM endpoints; not code analysis |
| [Agentic Security (msoedov)](https://github.com/msoedov/agentic_security) | OSS LLM endpoint fuzzer | Runtime probing only |
| [Giskard OSS](https://github.com/Giskard-AI/giskard-oss) | LLM/agent evaluation — quality, hallucination, robustness, safety tests | Eval framework; doesn't find code-level security bugs |
| [Patronus AI](https://www.patronus.ai/) | Continuous LLM evaluation — hallucination, factuality, PII, safety | Eval-focused; tests answer quality, not source code |

Inkog does adversarial testing too via [`inkog red`](https://docs.inkog.io/red), but the static-code-analysis core is the differentiator.

## Different category — enterprise platforms

| Tool | What it does | Why it's a different conversation |
|------|--------------|------------------------------------|
| [Endor Labs](https://www.endorlabs.com/) | Reachability-based SCA / "AI SAST" for code that uses AI libraries | Strong on Python imports + CVEs, doesn't understand agent semantics |
| [Cisco AI Defense](https://www.cisco.com/c/en/us/products/security/ai-defense/index.html) (ex-Robust Intelligence) | Runtime model validation, model firewalling, enterprise platform | Not a developer CLI — different buyer, different scope |
| [GuardFive](https://guardfive.com/) | MCP-server-focused security (currently a landing site, no public product) | Pre-launch; nothing shippable to compare |

These compete on enterprise platform readiness, not on the developer workflow Inkog targets.

## Where Inkog clearly loses today

Brutally honest:

- **Stars / mindshare**: 28 stars vs 5,308 (Giskard), 2,284 (Snyk Agent Scan), 1,852 (Agentic Security), 956 (SplxAI). Inkog is genuinely young.
- **Runtime defense**: Straiker, Lakera, and Cisco have production runtime guardrails. Inkog Red probes; it doesn't block.
- **Hallucination / answer-quality eval**: Giskard wins outright. Inkog tests for security and compliance, not whether the agent gives correct answers.
- **Auto-remediation UX**: AgentShield has `--fix`; Trent applies fixes via Claude Code. Inkog reports; you remediate.
- **Detection backend openness**: Inkog's CLI is Apache 2.0 but the engine is closed. Giskard and Crucible are fully open-source.

## When Inkog is the right answer

If you need:
- **One scanner across many agent frameworks** — including no-code workflows (n8n, Flowise, Langflow, Dify, Copilot Studio, Agentforce) and code frameworks (LangChain, LangGraph, CrewAI, AutoGen, AG2, Semantic Kernel, Azure AI Foundry, etc.)
- **Article-level regulatory traceability** — EU AI Act Article 14 / 15, NIST AI RMF map/measure/manage, ISO 42001, OWASP LLM Top 10 — not just generic risk buckets
- **Pre-deploy / shift-left** — runs in CI on every PR, fails the build on regressions, posts SARIF to the GitHub Security tab
- **MCP server auditing** — first OSS tool to scan MCP servers for tool poisoning, privilege escalation, data exfiltration
- **AGENTS.md governance verification** — checks that your declared controls match what the code actually does
- **MLBOM generation** — Machine Learning Bill of Materials for supply-chain compliance

…Inkog is the most complete option on the market today.

## Honest one-paragraph positioning

Inkog is a static, framework-aware security scanner for AI-agent codebases that runs in CI before deploy. The differentiator is a Universal IR ("LLVM for agents") that lets one ruleset detect agent-specific vulnerabilities — recursive tool calls, missing human oversight, prompt injection sinks, RAG over-fetching, MCP tool poisoning — across 21 code and no-code frameworks, with article-level mappings to EU AI Act, NIST AI RMF, ISO 42001, and OWASP LLM Top 10. It is **not** a runtime firewall (use Lakera or Straiker), **not** a hallucination evaluator (use Giskard), **not** a developer-environment auditor (use Snyk Agent Scan or AgentShield). It's the pre-deploy code review for the agent layer. The closest direct alternative is SplxAI Agentic Radar, which is more mature and better-known but covers fewer frameworks and lacks article-level compliance mapping.
