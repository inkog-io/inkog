<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">Trouvez les failles de securite dans vos agents IA.</h3>

<p align="center">
  Scannez les bugs logiques, l'injection de prompts, les protections manquantes et les lacunes de conformite — avant la mise en production.
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-Rejoindre-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

Les agents IA peuvent tomber dans des boucles infinies, epuiser votre budget API en quelques minutes, executer du code arbitraire a partir des saisies utilisateur, ou prendre des decisions a haut risque sans supervision humaine. La plupart de ces failles passent la revue de code car elles ressemblent a du code normal — le danger reside dans le comportement a l'execution.

Inkog scanne votre code d'agents de maniere statique et detecte ces problemes avant le deploiement. Une seule commande, compatible avec plus de 20 frameworks, cartographie les resultats vers le EU AI Act et l'OWASP LLM Top 10.

## Demarrage rapide

Aucune installation necessaire :

```bash
npx -y @inkog-io/cli scan .
```

Ou installez de maniere permanente :

| Methode | Commande |
|---------|----------|
| **Script d'installation** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **Binaire** | [Telecharger depuis Releases](https://github.com/inkog-io/inkog/releases) |

```bash
# Obtenez votre cle API gratuite sur https://app.inkog.io
export INKOG_API_KEY=sk_live_...

inkog .
```

## Ce que ca detecte

| Categorie | Exemples | Pourquoi c'est important |
|-----------|----------|--------------------------|
| **Boucles infinies** | L'agent se rappelle lui-meme sans condition de sortie, la sortie du LLM est renvoyee en entree sans limite | Votre agent tourne indefiniment et accumule les couts API |
| **Injection de prompts** | Les saisies utilisateur s'infiltrent dans le prompt systeme sans assainissement, des donnees contaminees atteignent les appels d'outils | Les attaquants peuvent detourner le comportement de l'agent |
| **Protections manquantes** | Pas d'approbation humaine pour les actions destructives, pas de limitation de debit sur les appels LLM, acces aux outils sans restriction | Une mauvaise decision et votre agent devient incontrole |
| **Secrets en dur** | Cles API, tokens et mots de passe dans le code source (detectes localement, jamais uploades) | Les identifiants fuient quand vous poussez sur GitHub |
| **Lacunes de conformite** | Absence de supervision humaine (EU AI Act Article 14), pas de journaux d'audit, pas de verification d'autorisation | Ces controles sont legalement requis d'ici aout 2026 |

[Catalogue complet des detections →](https://docs.inkog.io/vulnerabilities)

## Frameworks supportes

**Code-first :** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-code :** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[Documentation CI/CD complete →](https://docs.inkog.io/ci-cd/github-action)

## Serveur MCP

Scannez le code d'agents directement depuis Claude, ChatGPT ou Cursor :

```bash
npx -y @inkog-io/mcp
```

7 outils incluant l'audit de serveurs MCP et l'analyse de topologie multi-agents. [Docs MCP →](https://docs.inkog.io/integrations/mcp)

## Communaute

- [Documentation](https://docs.inkog.io) — Reference CLI, patterns de detection, integrations
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — Questions, retours, demandes de fonctionnalites
- [Issues](https://github.com/inkog-io/inkog/issues) — Rapports de bugs et demandes
- [Contribuer](../../CONTRIBUTING.md) — Les PRs sont les bienvenues

## Licence

Apache 2.0 — Voir [LICENSE](../../LICENSE)
