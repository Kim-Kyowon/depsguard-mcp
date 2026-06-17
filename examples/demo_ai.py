"""Gemini AI 실제 영향 분석 E2E 데모"""
import asyncio
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from depsguard.parsers import parse_dependency_file
from depsguard.db.osv import query_osv
from depsguard.analyzer import analyze_impact
from depsguard.models import Severity


async def main():
    base = os.path.dirname(__file__)

    print("=" * 60)
    print("DepsGuard MCP — Gemini AI 연동 E2E 데모")
    print("=" * 60)

    # 1단계: 파싱
    req_file = os.path.join(base, "requirements.txt")
    pkgs = parse_dependency_file(req_file)
    print(f"\n[1/3] 의존성 파싱: {len(pkgs)}개 패키지 발견")

    # 2단계: OSV.dev 취약점 조회 (Pillow — CRITICAL 포함)
    pillow_pkg = next(p for p in pkgs if p.name == "Pillow")
    vulns = await query_osv(pillow_pkg)
    high = [v for v in vulns if v.severity in (Severity.HIGH, Severity.CRITICAL)]
    print(f"[2/3] OSV.dev 조회: Pillow {pillow_pkg.version} → 총 {len(vulns)}개 취약점, HIGH/CRITICAL {len(high)}개")

    # 3단계: Gemini AI 실제 영향 분석
    if not high:
        print("HIGH 이상 취약점 없음")
        return

    target = high[0]
    print(f"\n[3/3] Gemini AI 분석 요청")
    print(f"  취약점: {target.id} ({target.severity.value})")
    print(f"  요약:   {target.summary}")
    print(f"  분석 중...", flush=True)

    project_root = os.path.join(base, "..")
    result = await analyze_impact(pillow_pkg, target, project_root)

    print("\n" + "=" * 60)
    print("AI 분석 결과")
    print("=" * 60)
    affected_str = "영향 있음" if result.is_affected else "영향 없음"
    print(f"실제 영향 여부 : {affected_str}")
    print(f"신뢰도        : {result.confidence:.0%}")
    print(f"판단 이유     : {result.reason}")
    print(f"권장 조치     : {result.recommendation}")
    if result.affected_files:
        print(f"영향 파일     : {', '.join(result.affected_files)}")


if __name__ == "__main__":
    asyncio.run(main())
