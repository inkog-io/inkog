---
name: Framework Support Request
about: Request detection support for an agent framework or no-code platform
title: '[FRAMEWORK] '
labels: framework-support
assignees: ''
---

## Framework

- **Name:**
- **Language / runtime:** (Python / TypeScript / no-code workflow JSON / etc.)
- **Homepage / repo:**
- **Why it matters:** (popularity, your use case, ecosystem traction)

## Example Agent Code

A small, representative agent built with this framework. The smaller and more idiomatic, the faster we can build an adapter.

```python
# Paste a minimal example here, or link to one in a public repo
```

## Patterns We Should Detect

Which Inkog detection categories apply to agents in this framework? Tick what you'd want to catch:

- [ ] Infinite / unbounded loops
- [ ] Token bombing / context window exhaustion
- [ ] Prompt injection (user input → LLM call without sanitization)
- [ ] SQL injection via LLM output
- [ ] Recursive tool calling without depth limits
- [ ] Missing human oversight (Article 14)
- [ ] Missing authorization on sensitive tools
- [ ] Hardcoded secrets in agent config
- [ ] Cross-tenant data leakage
- [ ] RAG over-fetching
- [ ] Other:

## How Agents Are Defined

Briefly: how does this framework let you define an agent? Class? Decorator? YAML config? JSON workflow? Drag-and-drop graph?

## How Tools Are Registered

How does an agent declare its tools/skills/functions? Tool registration is what most detection rules hang off of.

## Existing Coverage

Have you tried scanning this framework with `inkog`? If so:
- What did it detect?
- What did it miss?
- Any false positives?

## Volunteering

- [ ] I'd like to help validate the adapter once it's built
- [ ] I can provide a non-trivial real-world repo to test against
- [ ] I'd like to contribute to the adapter implementation
