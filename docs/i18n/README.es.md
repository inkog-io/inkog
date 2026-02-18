<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">Encuentra vulnerabilidades de seguridad en agentes de IA.</h3>

<p align="center">
  Escanea errores lógicos, inyección de prompts, falta de protecciones y problemas de cumplimiento — antes de llegar a producción.
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-Únete-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

Los agentes de IA pueden caer en bucles infinitos, agotar tu presupuesto de API en minutos, ejecutar código arbitrario desde la entrada del usuario, o tomar decisiones de alto riesgo sin supervisión humana. La mayoría de estos fallos pasan la revisión de código porque parecen código normal — el peligro está en el comportamiento en tiempo de ejecución.

Inkog escanea tu código de agentes de forma estática y detecta estos problemas antes del despliegue. Un solo comando, funciona con más de 20 frameworks, mapea hallazgos a la Ley de IA de la UE y OWASP LLM Top 10.

## Inicio Rápido

Sin necesidad de instalar:

```bash
npx -y @inkog-io/cli scan .
```

O instala permanentemente:

| Método | Comando |
|--------|---------|
| **Script de instalación** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **Binario** | [Descargar desde Releases](https://github.com/inkog-io/inkog/releases) |

```bash
# Obtén tu API key gratis en https://app.inkog.io
export INKOG_API_KEY=sk_live_...

inkog .
```

## Qué Detecta

| Categoría | Ejemplos | Por qué importa |
|-----------|----------|-----------------|
| **Bucles infinitos** | Agente se llama a sí mismo sin condición de salida, salida del LLM retroalimentada como entrada sin límite | Tu agente ejecuta para siempre y acumula costos de API |
| **Inyección de prompts** | Entrada del usuario fluye al prompt del sistema sin sanitizar, datos contaminados llegan a llamadas de herramientas | Atacantes pueden secuestrar el comportamiento del agente |
| **Protecciones faltantes** | Sin aprobación humana para acciones destructivas, sin límites de tasa en llamadas LLM, acceso a herramientas sin restricción | Una mala decisión y tu agente se sale de control |
| **Secretos hardcodeados** | Claves API, tokens y contraseñas en código fuente (detectados localmente, nunca se suben) | Las credenciales se filtran al hacer push a GitHub |
| **Brechas de cumplimiento** | Sin supervisión humana (Ley de IA de la UE Artículo 14), sin logs de auditoría, sin verificaciones de autorización | Legalmente necesitas estos controles antes de agosto 2026 |

[Catálogo completo de detecciones →](https://docs.inkog.io/vulnerabilities)

## Frameworks Soportados

**Code-first:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**No-code:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[Documentación completa de CI/CD →](https://docs.inkog.io/ci-cd/github-action)

## Servidor MCP

Escanea código de agentes directamente desde Claude, ChatGPT o Cursor:

```bash
npx -y @inkog-io/mcp
```

7 herramientas incluyendo auditoría de servidores MCP y análisis de topología multi-agente. [Docs MCP →](https://docs.inkog.io/integrations/mcp)

## Comunidad

- [Documentación](https://docs.inkog.io) — Referencia CLI, patrones de detección, integraciones
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — Preguntas, feedback, solicitud de funciones
- [Issues](https://github.com/inkog-io/inkog/issues) — Reportes de bugs y solicitudes
- [Contribuir](../../CONTRIBUTING.md) — PRs bienvenidos

## Licencia

Apache 2.0 — Ver [LICENSE](../../LICENSE)
