# DepsGuard MCP

[![CI](https://github.com/Kim-Kyowon/depsguard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kim-Kyowon/depsguard-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/depsguard-mcp)](https://pypi.org/project/depsguard-mcp/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

**AI-Powered Dependency Vulnerability & Breaking Change Analyzer MCP**

의존성 패키지의 취약점을 [OSV.dev](https://osv.dev)에서 실시간 조회하고, AI가 내 코드의 실제 사용 패턴과 연결하여 **진짜 위험한 것만** 우선순위화합니다. 버전 업데이트 시 breaking change 영향 범위까지 분석하여 수정 코드를 제안합니다.

## 기존 도구와 차이점

| 도구 | 취약점 탐지 | 실제 영향 분석 | Breaking Change 분석 |
|---|---|---|---|
| `pip audit` / `npm audit` | ✅ | ❌ | ❌ |
| Dependabot / Renovate | ✅ | ❌ | ❌ |
| **DepsGuard MCP** | ✅ | ✅ AI 판단 | ✅ AI 판단 |

## 빠른 시작

```bash
pip install depsguard-mcp

# Claude Code에 MCP 등록
claude mcp add depsguard -- depsguard-mcp serve

# 환경 변수 (LLM 선택)
export DEPSGUARD_LLM_PROVIDER="anthropic"   # anthropic | openai | gemini | ollama
export ANTHROPIC_API_KEY="sk-..."

# 사내 프록시 환경
export DEPSGUARD_PROXY="http://proxy:8080"
```

## CLI 사용

```bash
# 취약점 스캔
depsguard scan ./requirements.txt
depsguard scan ./package.json

# 업그레이드 breaking change 분석
depsguard upgrade django --from 3.2.0 --to 4.2.0
```

## MCP 도구 목록

| 도구 | 설명 |
|---|---|
| `scan_dependencies` | 의존성 파일 스캔 + AI 실제 영향 분석 |
| `analyze_upgrade` | 버전 업그레이드 breaking change AI 분석 |
| `list_packages` | 의존성 파일 패키지 목록 파싱 |

## 지원 생태계

| 파일 | 생태계 |
|---|---|
| `requirements.txt`, `pyproject.toml` | Python / PyPI |
| `package.json` | Node.js / npm |

## 아키텍처

```
의존성 파일 파싱
      ↓
OSV.dev API (취약점 조회, 무료·Key 불필요)
      ↓
AST 코드 사용 패턴 분석
      ↓
LLM 실제 영향 판단 (anthropic / openai / gemini / ollama)
      ↓
MCP 도구 응답
```

## 라이선스

Apache 2.0
