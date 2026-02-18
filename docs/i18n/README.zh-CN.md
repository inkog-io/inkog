<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">发现 AI 智能体中的安全漏洞。</h3>

<p align="center">
  在部署前扫描逻辑缺陷、提示注入、缺失的安全防护和合规问题。
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-加入我们-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

AI 智能体可能会陷入无限循环、在几分钟内耗尽你的 API 预算、执行来自用户输入的任意代码，或者在没有人工监督的情况下做出高风险决策。这些缺陷大多能通过代码审查，因为它们看起来像正常代码——危险在于运行时行为。

Inkog 对你的智能体代码进行静态扫描，在部署前捕获这些问题。一条命令，支持 20+ 框架，将发现映射到欧盟 AI 法案和 OWASP LLM Top 10。

## 快速开始

无需安装：

```bash
npx -y @inkog-io/cli scan .
```

或永久安装：

| 方式 | 命令 |
|------|------|
| **安装脚本** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **二进制文件** | [从 Releases 下载](https://github.com/inkog-io/inkog/releases) |

```bash
# 在 https://app.inkog.io 获取免费 API Key
export INKOG_API_KEY=sk_live_...

inkog .
```

## 检测内容

| 类别 | 示例 | 为什么重要 |
|------|------|-----------|
| **无限循环** | 智能体无退出条件地重复调用自身，LLM 输出无上限地回馈为输入 | 智能体永远运行，API 费用飙升 |
| **提示注入** | 用户输入未经消毒流入系统提示，被污染的数据到达工具调用 | 攻击者可以劫持智能体行为 |
| **缺失防护** | 破坏性操作没有人工审批，LLM 调用没有速率限制，工具访问不受约束 | 一个错误决策，智能体就会失控 |
| **硬编码密钥** | 源代码中的 API 密钥、令牌和密码（本地检测，永远不会上传） | 推送到 GitHub 时凭证泄露 |
| **合规缺口** | 缺少人工监督（欧盟 AI 法案第14条）、无审计日志、缺少授权检查 | 2026年8月前你在法律上必须具备这些控制措施 |

[完整检测目录 →](https://docs.inkog.io/vulnerabilities)

## 支持的框架

**代码优先：** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**无代码：** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[完整 CI/CD 文档 →](https://docs.inkog.io/ci-cd/github-action)

## MCP 服务器

从 Claude、ChatGPT 或 Cursor 中直接扫描智能体代码：

```bash
npx -y @inkog-io/mcp
```

包含 7 个工具，涵盖 MCP 服务器审计和多智能体拓扑分析。[MCP 文档 →](https://docs.inkog.io/integrations/mcp)

## 社区

- [文档](https://docs.inkog.io) — CLI 参考、检测模式、集成
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — 提问、反馈、功能请求
- [Issues](https://github.com/inkog-io/inkog/issues) — Bug 报告和功能请求
- [贡献指南](../../CONTRIBUTING.md) — 欢迎提交 PR

## 许可证

Apache 2.0 — 查看 [LICENSE](../../LICENSE)
