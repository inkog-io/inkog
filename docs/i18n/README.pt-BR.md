<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">Encontre falhas de seguranca em agentes de IA.</h3>

<p align="center">
  Escaneie bugs logicos, injecao de prompts, protecoes ausentes e lacunas de conformidade — antes de chegar a producao.
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-Participe-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

Agentes de IA podem entrar em loops infinitos, esgotar seu orcamento de API em minutos, executar codigo arbitrario a partir da entrada do usuario, ou tomar decisoes de alto risco sem supervisao humana. A maioria dessas falhas passa pela revisao de codigo porque parecem codigo normal — o perigo esta no comportamento em tempo de execucao.

Inkog escaneia seu codigo de agentes estaticamente e captura esses problemas antes do deploy. Um unico comando, funciona com mais de 20 frameworks, mapeia descobertas para a Lei de IA da UE e OWASP LLM Top 10.

## Inicio Rapido

Sem necessidade de instalacao:

```bash
npx -y @inkog-io/cli scan .
```

Ou instale permanentemente:

| Metodo | Comando |
|--------|---------|
| **Script de instalacao** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **Binario** | [Baixar dos Releases](https://github.com/inkog-io/inkog/releases) |

```bash
# Obtenha sua API key gratis em https://app.inkog.io
export INKOG_API_KEY=sk_live_...

inkog .
```

## O Que Detecta

| Categoria | Exemplos | Por que importa |
|-----------|----------|-----------------|
| **Loops infinitos** | Agente chama a si mesmo sem condicao de saida, saida do LLM retroalimentada como entrada sem limite | Seu agente roda para sempre e acumula custos de API |
| **Injecao de prompts** | Entrada do usuario flui para o prompt do sistema sem sanitizacao, dados contaminados chegam a chamadas de ferramentas | Atacantes podem sequestrar o comportamento do agente |
| **Protecoes ausentes** | Sem aprovacao humana para acoes destrutivas, sem limites de taxa em chamadas LLM, acesso a ferramentas sem restricao | Uma decisao ruim e seu agente fica fora de controle |
| **Segredos hardcoded** | Chaves API, tokens e senhas no codigo fonte (detectados localmente, nunca enviados) | Credenciais vazam quando voce faz push no GitHub |
| **Lacunas de conformidade** | Sem supervisao humana (Lei de IA da UE Artigo 14), sem logs de auditoria, sem verificacoes de autorizacao | Voce precisa legalmente desses controles ate agosto de 2026 |

[Catalogo completo de deteccoes →](https://docs.inkog.io/vulnerabilities)

## Frameworks Suportados

**Code-first:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-code:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[Documentacao completa de CI/CD →](https://docs.inkog.io/ci-cd/github-action)

## Servidor MCP

Escaneie codigo de agentes diretamente do Claude, ChatGPT ou Cursor:

```bash
npx -y @inkog-io/mcp
```

7 ferramentas incluindo auditoria de servidores MCP e analise de topologia multi-agente. [Docs MCP →](https://docs.inkog.io/integrations/mcp)

## Comunidade

- [Documentacao](https://docs.inkog.io) — Referencia CLI, padroes de deteccao, integracoes
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — Perguntas, feedback, pedidos de funcionalidades
- [Issues](https://github.com/inkog-io/inkog/issues) — Relatorios de bugs e pedidos
- [Contribuir](../../CONTRIBUTING.md) — PRs sao bem-vindos

## Licenca

Apache 2.0 — Ver [LICENSE](../../LICENSE)
