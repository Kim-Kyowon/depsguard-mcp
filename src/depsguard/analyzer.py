from __future__ import annotations

import ast
import json
import os
from pathlib import Path

from litellm import acompletion

from depsguard.models import (
    BreakingChange,
    ImpactAnalysis,
    Package,
    UpgradeAnalysis,
    Vulnerability,
)

_PROVIDER = os.getenv("DEPSGUARD_LLM_PROVIDER", "anthropic")
_MODEL_MAP = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "gemini": "gemini/gemini-2.5-flash",
    "ollama": "ollama/llama3",
    "enterprise-gateway": os.getenv("DEPSGUARD_GATEWAY_MODEL", "gpt-4o"),
}


def _model() -> str:
    return _MODEL_MAP.get(_PROVIDER, "claude-sonnet-4-6")


def _collect_usages(package_name: str, project_root: str) -> list[dict]:
    """AST로 프로젝트 코드에서 패키지 사용 패턴 추출."""
    usages = []
    for py_file in Path(project_root).rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", "") or ""
                names = [alias.name for alias in node.names]
                if package_name.lower() in module.lower() or any(
                    package_name.lower() in n.lower() for n in names
                ):
                    usages.append({
                        "file": str(py_file),
                        "line": node.lineno,
                        "type": "import",
                        "detail": ast.unparse(node),
                    })
    return usages[:50]  # LLM 컨텍스트 제한


async def analyze_impact(
    package: Package,
    vuln: Vulnerability,
    project_root: str,
) -> ImpactAnalysis:
    usages = _collect_usages(package.name, project_root)
    usage_text = "\n".join(
        f"  {u['file']}:{u['line']} — {u['detail']}" for u in usages
    ) or "  (사용 패턴 없음)"

    prompt = f"""당신은 보안 전문가입니다. 아래 정보를 바탕으로
취약점이 이 프로젝트에 실제로 영향을 미치는지 판단하세요.

패키지: {package.name} {package.version}
취약점: {vuln.id} (CVSS: {vuln.cvss_score}, 심각도: {vuln.severity})
요약: {vuln.summary}

프로젝트 내 사용 패턴:
{usage_text}

다음 형식으로 JSON만 반환하세요 (다른 텍스트 없이):
{{
  "is_affected": true/false,
  "confidence": 0.0~1.0,
  "affected_files": ["파일경로", ...],
  "reason": "판단 이유 (한국어)",
  "recommendation": "권장 조치 (한국어)"
}}"""

    resp = await acompletion(
        model=_model(),
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    result = json.loads(resp.choices[0].message.content)

    return ImpactAnalysis(
        vuln_id=vuln.id,
        package=package,
        is_affected=result.get("is_affected", True),
        confidence=float(result.get("confidence", 0.5)),
        affected_files=result.get("affected_files", []),
        reason=result.get("reason", ""),
        recommendation=result.get("recommendation", ""),
    )


async def analyze_breaking_changes(
    package: Package,
    target_version: str,
    changelog: str,
    project_root: str,
) -> UpgradeAnalysis:
    usages = _collect_usages(package.name, project_root)
    usage_text = "\n".join(
        f"  {u['file']}:{u['line']} — {u['detail']}" for u in usages
    ) or "  (사용 패턴 없음)"

    prompt = f"""당신은 Python 전문가입니다. 패키지 업데이트 시 breaking change를 분석하세요.

패키지: {package.name} {package.version} → {target_version}

Changelog/마이그레이션 가이드:
{changelog[:3000]}

프로젝트 내 사용 패턴:
{usage_text}

다음 형식으로 JSON만 반환하세요:
{{
  "is_safe": true/false,
  "summary": "전체 요약 (한국어)",
  "breaking_changes": [
    {{
      "description": "변경 내용",
      "affected_files": ["파일경로"],
      "affected_lines": [줄번호],
      "suggested_fix": "수정 코드 또는 방법"
    }}
  ]
}}"""

    resp = await acompletion(
        model=_model(),
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    result = json.loads(resp.choices[0].message.content)

    return UpgradeAnalysis(
        package=package,
        target_version=target_version,
        is_safe=result.get("is_safe", False),
        summary=result.get("summary", ""),
        breaking_changes=[
            BreakingChange(**bc) for bc in result.get("breaking_changes", [])
        ],
    )
