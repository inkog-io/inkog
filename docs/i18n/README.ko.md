<p align="center">
  <img src="../../logo.png" width="200" alt="Inkog">
</p>

<h3 align="center">AI 에이전트의 보안 취약점을 발견하세요.</h3>

<p align="center">
  로직 버그, 프롬프트 인젝션, 누락된 가드레일, 컴플라이언스 문제를 배포 전에 스캔합니다.
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
  <a href="https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw"><img src="https://img.shields.io/badge/Slack-참여하기-4A154B?logo=slack&logoColor=white" alt="Slack"></a>
</p>

---

AI 에이전트는 무한 루프에 빠지고, 몇 분 만에 API 예산을 소진하고, 사용자 입력으로부터 임의의 코드를 실행하고, 인간의 감독 없이 중요한 결정을 내릴 수 있습니다. 이러한 결함은 정상적인 코드처럼 보이기 때문에 대부분 코드 리뷰를 통과합니다 — 위험은 런타임 동작에 있습니다.

Inkog는 에이전트 코드를 정적으로 스캔하여 배포 전에 이러한 문제를 잡아냅니다. 하나의 명령어로 20개 이상의 프레임워크를 지원하며, 발견사항을 EU AI Act와 OWASP LLM Top 10에 매핑합니다.

## 빠른 시작

설치 불필요:

```bash
npx -y @inkog-io/cli scan .
```

또는 영구 설치:

| 방법 | 명령어 |
|------|--------|
| **설치 스크립트** | `curl -fsSL https://inkog.io/install.sh \| sh` |
| **Homebrew** | `brew tap inkog-io/inkog && brew install inkog` |
| **Go** | `go install github.com/inkog-io/inkog/cmd/inkog@latest` |
| **바이너리** | [Releases에서 다운로드](https://github.com/inkog-io/inkog/releases) |

```bash
# https://app.inkog.io 에서 무료 API 키 발급
export INKOG_API_KEY=sk_live_...

inkog .
```

## 탐지 항목

| 카테고리 | 예시 | 중요한 이유 |
|---------|------|-----------|
| **무한 루프** | 종료 조건 없이 에이전트가 자신을 재호출, LLM 출력이 제한 없이 입력으로 피드백 | 에이전트가 영원히 실행되고 API 비용 폭증 |
| **프롬프트 인젝션** | 사용자 입력이 새니타이즈 없이 시스템 프롬프트로 유입, 오염된 데이터가 도구 호출에 도달 | 공격자가 에이전트 동작을 탈취 가능 |
| **가드레일 누락** | 파괴적 작업에 인간 승인 없음, LLM 호출에 속도 제한 없음, 도구 접근 제한 없음 | 하나의 잘못된 판단으로 에이전트가 폭주 |
| **하드코딩된 시크릿** | 소스 코드의 API 키, 토큰, 비밀번호 (로컬에서 감지, 업로드되지 않음) | GitHub에 푸시하면 인증 정보 유출 |
| **컴플라이언스 격차** | 인간 감독 누락 (EU AI Act 14조), 감사 로깅 없음, 인가 확인 없음 | 2026년 8월까지 법적으로 이러한 통제가 필요 |

[전체 탐지 카탈로그 →](https://docs.inkog.io/vulnerabilities)

## 지원 프레임워크

**코드 우선:** LangChain · LangGraph · CrewAI · AutoGen · OpenAI Agents · Semantic Kernel · Azure AI Foundry · LlamaIndex · Haystack · DSPy · Phidata · Smolagents · PydanticAI · Google ADK

**노코드:** n8n · Flowise · Langflow · Dify · Microsoft Copilot Studio · Salesforce Agentforce

## GitHub Actions

```yaml
- uses: inkog-io/inkog@v1
  with:
    api-key: ${{ secrets.INKOG_API_KEY }}
    sarif-upload: true
```

[CI/CD 문서 →](https://docs.inkog.io/ci-cd/github-action)

## MCP 서버

Claude, ChatGPT, Cursor에서 직접 에이전트 코드를 스캔:

```bash
npx -y @inkog-io/mcp
```

MCP 서버 감사 및 멀티 에이전트 토폴로지 분석을 포함한 7가지 도구. [MCP 문서 →](https://docs.inkog.io/integrations/mcp)

## 커뮤니티

- [문서](https://docs.inkog.io) — CLI 레퍼런스, 탐지 패턴, 통합
- [Slack](https://join.slack.com/t/inkog-io/shared_invite/zt-3jrzztm28-cXyokCXO8KjKC6nBI0l4Gw) — 질문, 피드백, 기능 요청
- [Issues](https://github.com/inkog-io/inkog/issues) — 버그 리포트 및 기능 요청
- [기여하기](../../CONTRIBUTING.md) — PR을 환영합니다

## 라이선스

Apache 2.0 — [LICENSE](../../LICENSE) 참조
