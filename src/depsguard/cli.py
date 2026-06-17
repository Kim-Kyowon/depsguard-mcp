from __future__ import annotations
import asyncio
import argparse
import sys
from depsguard.scanner import scan
from depsguard.analyzer import analyze_breaking_changes
from depsguard.models import Package


def main():
    parser = argparse.ArgumentParser(prog="depsguard", description="AI-Powered Dependency Vulnerability Analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="의존성 파일 취약점 스캔")
    p_scan.add_argument("file", help="requirements.txt / package.json 경로")
    p_scan.add_argument("--root", default=".", help="프로젝트 루트 (기본값: 현재 디렉터리)")
    p_scan.add_argument("--no-ai", action="store_true", help="AI 영향 분석 건너뜀")

    p_upgrade = sub.add_parser("upgrade", help="업그레이드 breaking change 분석")
    p_upgrade.add_argument("package", help="패키지 이름")
    p_upgrade.add_argument("--from", dest="from_ver", required=True, help="현재 버전")
    p_upgrade.add_argument("--to", dest="to_ver", required=True, help="목표 버전")
    p_upgrade.add_argument("--root", default=".", help="프로젝트 루트")
    p_upgrade.add_argument("--ecosystem", default="PyPI")

    args = parser.parse_args()

    if args.command == "scan":
        report = asyncio.run(scan(args.file, args.root, ai_analysis=not args.no_ai))
        _print_report(report)
    elif args.command == "upgrade":
        pkg = Package(name=args.package, version=args.from_ver, ecosystem=args.ecosystem)
        result = asyncio.run(analyze_breaking_changes(pkg, args.to_ver, "", args.root))
        print(f"\n{args.package} {args.from_ver} → {args.to_ver}")
        print(f"안전 여부: {'✅ 안전' if result.is_safe else '⚠️ 수정 필요'}")
        print(f"요약: {result.summary}")
        for bc in result.breaking_changes:
            print(f"\n  - {bc.description}")
            if bc.suggested_fix:
                print(f"    수정: {bc.suggested_fix}")


def _print_report(report):
    print(f"\n스캔 완료: {report.scanned_file}")
    print(f"패키지 {len(report.packages)}개 | 취약점 {len(report.vulnerabilities)}개 | "
          f"CRITICAL {report.critical_count} | HIGH {report.high_count}")
    if report.impact_analyses:
        affected = [ia for ia in report.impact_analyses if ia.is_affected]
        print(f"AI 실제 영향 분석: {len(affected)}개 실제 위험\n")
        for ia in affected:
            print(f"  [{ia.vuln_id}] {ia.package.name} — {ia.reason}")
            print(f"  → {ia.recommendation}\n")
    if not report.vulnerabilities:
        print("✅ 취약점 없음.")
