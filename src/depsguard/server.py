from __future__ import annotations

from pathlib import Path

from fastmcp import FastMCP

from depsguard.analyzer import analyze_breaking_changes
from depsguard.models import Package, ScanReport
from depsguard.parsers import parse_dependency_file
from depsguard.scanner import scan

mcp = FastMCP(
    name="depsguard",
    instructions=(
        "DepsGuard는 의존성 취약점을 OSV.dev에서 실시간 조회하고, "
        "AI가 실제 코드 영향을 분석하여 진짜 위험한 것만 우선순위화합니다."
    ),
)


@mcp.tool()
async def scan_dependencies(
    dependency_file: str,
    project_root: str = ".",
    ai_analysis: bool = True,
) -> str:
    """의존성 파일을 스캔하여 취약점을 탐지하고 AI로 실제 영향을 분석합니다.

    Args:
        dependency_file: requirements.txt, package.json 등 경로
        project_root: 프로젝트 루트 디렉터리 (AI 영향 분석용 코드 탐색 기준)
        ai_analysis: True이면 CRITICAL/HIGH 취약점에 대해 AI 실제 영향 분석 수행
    """
    if not Path(dependency_file).exists():
        return f"오류: {dependency_file} 파일을 찾을 수 없습니다."

    report: ScanReport = await scan(dependency_file, project_root, ai_analysis)
    return _format_scan_report(report)


@mcp.tool()
async def analyze_upgrade(
    package_name: str,
    current_version: str,
    target_version: str,
    ecosystem: str = "PyPI",
    project_root: str = ".",
    changelog: str = "",
) -> str:
    """패키지 버전 업그레이드 시 breaking change를 AI가 분석하고 영향 파일·수정 방법을 제시합니다.

    Args:
        package_name: 패키지 이름 (예: requests, django)
        current_version: 현재 버전 (예: 2.28.0)
        target_version: 업그레이드 목표 버전 (예: 2.31.0)
        ecosystem: PyPI / npm / Go 등
        project_root: 프로젝트 루트 디렉터리
        changelog: changelog 또는 마이그레이션 가이드 텍스트 (없으면 AI가 일반 지식으로 분석)
    """
    pkg = Package(name=package_name, version=current_version, ecosystem=ecosystem)
    analysis = await analyze_breaking_changes(pkg, target_version, changelog, project_root)

    lines = [
        f"## {package_name} {current_version} → {target_version} 업그레이드 분석",
        f"**안전 여부:** {'✅ 안전' if analysis.is_safe else '⚠️ 수정 필요'}",
        f"**요약:** {analysis.summary}",
    ]

    if analysis.breaking_changes:
        lines.append("\n### Breaking Changes")
        for i, bc in enumerate(analysis.breaking_changes, 1):
            lines.append(f"\n**{i}. {bc.description}**")
            if bc.affected_files:
                lines.append(f"- 영향 파일: {', '.join(bc.affected_files)}")
            if bc.affected_lines:
                lines.append(f"- 영향 라인: {bc.affected_lines}")
            if bc.suggested_fix:
                lines.append(f"- 수정 방법:\n```\n{bc.suggested_fix}\n```")
    else:
        lines.append("\n✅ Breaking change 없음.")

    return "\n".join(lines)


@mcp.tool()
async def list_packages(dependency_file: str) -> str:
    """의존성 파일에서 패키지 목록을 파싱하여 반환합니다.

    Args:
        dependency_file: requirements.txt, package.json 등 경로
    """
    if not Path(dependency_file).exists():
        return f"오류: {dependency_file} 파일을 찾을 수 없습니다."

    packages = parse_dependency_file(dependency_file)
    lines = [f"## {dependency_file} — {len(packages)}개 패키지"]
    for pkg in packages:
        lines.append(f"- {pkg.name} {pkg.version} ({pkg.ecosystem})")
    return "\n".join(lines)


def _format_scan_report(report: ScanReport) -> str:
    lines = [
        f"## DepsGuard 스캔 결과: {report.scanned_file}",
        f"- 총 패키지: {len(report.packages)}개",
        f"- 취약점 있는 패키지: {len(report.vulnerabilities)}개",
        f"- CRITICAL: {report.critical_count}개 | HIGH: {report.high_count}개",
    ]

    if report.impact_analyses:
        lines.append(f"- AI 분석 결과 실제 영향: {report.affected_count}개\n")
        lines.append("### AI 영향 분석 결과")
        for ia in report.impact_analyses:
            status = "🔴 영향 있음" if ia.is_affected else "🟢 영향 없음"
            lines.append(
                f"\n**{ia.vuln_id}** ({ia.package.name} {ia.package.version})"
                f"\n- 상태: {status} (신뢰도: {ia.confidence:.0%})"
                f"\n- 이유: {ia.reason}"
                f"\n- 권장 조치: {ia.recommendation}"
            )
            if ia.affected_files:
                lines.append(f"- 영향 파일: {', '.join(ia.affected_files)}")

    if not report.vulnerabilities:
        lines.append("\n✅ 취약점 없음.")
    else:
        lines.append("\n### 발견된 취약점 전체 목록")
        for pkg_name, vulns in report.vulnerabilities.items():
            for v in vulns:
                lines.append(
                    f"- [{v.severity.value}] {v.id} ({pkg_name})"
                    f" — {v.summary[:80]}"
                    + (f" → 수정 버전: {v.fixed_version}" if v.fixed_version else "")
                )

    return "\n".join(lines)


def serve():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    serve()
