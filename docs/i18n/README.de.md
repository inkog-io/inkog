<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">Sicherheitslucken in KI-Agenten finden.</h3>

<p align="center">
  Logikfehler, Prompt-Injection, fehlende Schutzmechanismen und Compliance-Lucken scannen — bevor sie in Produktion gehen.
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pt-BR.md">Português</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

<p align="center">
  <a href="https://github.com/inkog-io/inkog/releases"><img src="https://img.shields.io/github/v/release/inkog-io/inkog?label=release" alt="Release"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://goreportcard.com/report/github.com/inkog-io/inkog"><img src="https://goreportcard.com/badge/github.com/inkog-io/inkog" alt="Go Report Card"></a>
  <a href="https://github.com/inkog-io/inkog/actions/workflows/ci.yml"><img src="https://github.com/inkog-io/inkog/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-Beitreten-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

KI-Agenten konnen in Endlosschleifen geraten, Ihr API-Budget in Minuten aufbrauchen, beliebigen Code aus Benutzereingaben ausfuhren oder risikoreiche Entscheidungen ohne menschliche Aufsicht treffen. Die meisten dieser Fehler bestehen Code-Reviews, weil sie wie normaler Code aussehen — die Gefahr liegt im Laufzeitverhalten.

Inkog scannt Ihren Agenten-Code statisch und fangt diese Probleme vor dem Deployment ab. Ein einziger Befehl, funktioniert mit uber 20 Frameworks, ordnet Ergebnisse dem EU AI Act und OWASP LLM Top 10 zu.

## Schnellstart

Keine Installation erforderlich:

```bash
npx -y @inkog-io/cli scan .
```

Oder dauerhaft installieren:

| Methode | Befehl |
|---------|--------|
| **Installationsskript** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **Binary** | [Von Releases herunterladen](https://github.com/inkog-io/inkog/releases) |

```bash
# Kostenlosen API-Key unter https://app.inkog.io erhalten
export INKOG_API_KEY=sk_live_...

inkog .
```

## Was erkannt wird

| Kategorie | Beispiele | Warum es wichtig ist |
|-----------|----------|---------------------|
| **Endlosschleifen** | Agent ruft sich selbst ohne Abbruchbedingung auf, LLM-Ausgabe wird ohne Limit als Eingabe zuruckgefuhrt | Ihr Agent lauft endlos und treibt API-Kosten hoch |
| **Prompt-Injection** | Benutzereingaben fliessen unsanitisiert in den System-Prompt, kontaminierte Daten erreichen Tool-Aufrufe | Angreifer konnen das Verhalten des Agenten kapern |
| **Fehlende Schutzmechanismen** | Keine menschliche Genehmigung fur destruktive Aktionen, kein Rate-Limiting bei LLM-Aufrufen, uneingeschrankter Tool-Zugriff | Eine falsche Entscheidung und Ihr Agent lauft Amok |
| **Hardcodierte Secrets** | API-Keys, Tokens und Passworter im Quellcode (lokal erkannt, nie hochgeladen) | Zugangsdaten werden geleakt wenn Sie auf GitHub pushen |
| **Compliance-Lucken** | Fehlende menschliche Aufsicht (EU AI Act Artikel 14), keine Audit-Logs, fehlende Autorisierungsprufungen | Sie brauchen diese Kontrollen gesetzlich bis August 2026 |

[Vollstandiger Erkennungskatalog →](https://docs.inkog.io/vulnerabilities)

## Unterstutzte Frameworks

**Code-first:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-code:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[Vollstandige CI/CD-Dokumentation →](https://docs.inkog.io/ci-cd/github-action)

## MCP-Server

Agenten-Code direkt aus Claude, ChatGPT oder Cursor scannen:

```bash
npx -y @inkog-io/mcp
```

7 Tools inklusive MCP-Server-Audit und Multi-Agenten-Topologie-Analyse. [MCP-Docs →](https://docs.inkog.io/integrations/mcp)

## Community

- [Dokumentation](https://docs.inkog.io) — CLI-Referenz, Erkennungsmuster, Integrationen
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — Fragen, Feedback, Feature-Anfragen
- [Issues](https://github.com/inkog-io/inkog/issues) — Bug-Reports und Feature-Anfragen
- [Beitragen](../../CONTRIBUTING.md) — PRs willkommen

## Lizenz

Apache 2.0 — Siehe [LICENSE](../../LICENSE)
