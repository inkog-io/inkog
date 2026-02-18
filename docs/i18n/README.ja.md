<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">AIエージェントのセキュリティ脆弱性を発見。</h3>

<p align="center">
  ロジックバグ、プロンプトインジェクション、ガードレールの欠如、コンプライアンス違反を本番前にスキャン。
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-参加する-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

AIエージェントは無限ループに陥り、数分でAPI予算を使い果たし、ユーザー入力から任意のコードを実行し、人間の監視なしに重大な意思決定を行う可能性があります。これらの欠陥のほとんどは通常のコードに見えるため、コードレビューを通過してしまいます。危険なのはランタイムの動作です。

Inkogはエージェントコードを静的にスキャンし、デプロイ前にこれらの問題をキャッチします。1つのコマンドで20以上のフレームワークに対応し、検出結果をEU AI法およびOWASP LLM Top 10にマッピングします。

## クイックスタート

インストール不要：

```bash
npx -y @inkog-io/cli scan .
```

または永続インストール：

| 方法 | コマンド |
|------|---------|
| **インストールスクリプト** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **バイナリ** | [Releasesからダウンロード](https://github.com/inkog-io/inkog/releases) |

```bash
# https://app.inkog.io で無料APIキーを取得
export INKOG_API_KEY=sk_live_...

inkog .
```

## 検出内容

| カテゴリ | 例 | 重要な理由 |
|---------|-----|-----------|
| **無限ループ** | 終了条件なしでエージェントが自身を再呼び出し、LLM出力が上限なしに入力に戻される | エージェントが永遠に実行され、API費用が膨大に |
| **プロンプトインジェクション** | ユーザー入力がサニタイズされずにシステムプロンプトに流入、汚染データがツール呼び出しに到達 | 攻撃者がエージェントの動作を乗っ取る可能性 |
| **ガードレールの欠如** | 破壊的アクションに人間の承認なし、LLM呼び出しにレート制限なし、ツールアクセスが無制限 | 1つの判断ミスでエージェントが暴走 |
| **ハードコードされた秘密情報** | ソースコード内のAPIキー、トークン、パスワード（ローカルで検出、アップロードされません） | GitHubにプッシュすると認証情報が漏洩 |
| **コンプライアンスの欠如** | 人間の監視なし（EU AI法第14条）、監査ログなし、認可チェックなし | 2026年8月までにこれらの制御が法的に必要 |

[検出パターン全リスト →](https://docs.inkog.io/vulnerabilities)

## 対応フレームワーク

**コードファースト：** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**ノーコード：** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[CI/CDドキュメント →](https://docs.inkog.io/ci-cd/github-action)

## MCPサーバー

Claude、ChatGPT、Cursorから直接エージェントコードをスキャン：

```bash
npx -y @inkog-io/mcp
```

MCPサーバー監査やマルチエージェントトポロジー分析を含む7つのツール。[MCPドキュメント →](https://docs.inkog.io/integrations/mcp)

## コミュニティ

- [ドキュメント](https://docs.inkog.io) — CLIリファレンス、検出パターン、インテグレーション
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — 質問、フィードバック、機能リクエスト
- [Issues](https://github.com/inkog-io/inkog/issues) — バグレポートと機能リクエスト
- [コントリビューション](../../CONTRIBUTING.md) — PRを歓迎します

## ライセンス

Apache 2.0 — [LICENSE](../../LICENSE)を参照
