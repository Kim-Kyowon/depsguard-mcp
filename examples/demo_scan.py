"""OSV.dev 실제 API 연동 데모 스크립트"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from depsguard.parsers import parse_dependency_file
from depsguard.db.osv import query_osv
from depsguard.models import Severity


async def main():
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    print(f"[1/3] 의존성 파일 파싱: {req_file}")
    packages = parse_dependency_file(req_file)
    print(f"      → {len(packages)}개 패키지 발견\n")

    print("[2/3] OSV.dev 취약점 조회 중...")
    results = {}
    for pkg in packages:
        try:
            vulns = await query_osv(pkg)
            results[pkg.name] = (pkg, vulns)
            status = f"{len(vulns)}개 취약점" if vulns else "이상 없음"
            print(f"      {pkg.name} {pkg.version} → {status}")
        except Exception as e:
            print(f"      {pkg.name} {pkg.version} → 오류: {e}")
            results[pkg.name] = (pkg, [])

    print("\n[3/3] 결과 요약")
    print("=" * 60)
    for pkg_name, (pkg, vulns) in results.items():
        if not vulns:
            print(f"✅ {pkg_name} {pkg.version} — 취약점 없음")
            continue
        for v in vulns:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.severity.value, "⚪")
            fixed = f" (수정버전: {v.fixed_version})" if v.fixed_version else ""
            print(f"{icon} [{v.severity.value}] {v.id}")
            print(f"   패키지: {pkg_name} {pkg.version}{fixed}")
            print(f"   요약:   {v.summary[:100]}")
            if v.references:
                print(f"   참고:   {v.references[0]}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
