from __future__ import annotations

import asyncio

from depsguard.analyzer import analyze_impact
from depsguard.db import query_osv
from depsguard.models import ScanReport, Severity
from depsguard.parsers import parse_dependency_file


async def scan(dependency_file: str, project_root: str, ai_analysis: bool = True) -> ScanReport:
    packages = parse_dependency_file(dependency_file)

    vuln_map: dict[str, list] = {}
    tasks = [query_osv(pkg) for pkg in packages]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for pkg, result in zip(packages, results):
        if isinstance(result, Exception):
            continue
        if result:
            vuln_map[pkg.name] = result

    report = ScanReport(
        scanned_file=dependency_file,
        packages=packages,
        vulnerabilities=vuln_map,
    )

    for sev in [Severity.CRITICAL, Severity.HIGH]:
        for pkg_name, vulns in vuln_map.items():
            for v in vulns:
                if v.severity == Severity.CRITICAL:
                    report.critical_count += 1
                elif v.severity == Severity.HIGH:
                    report.high_count += 1

    if ai_analysis and vuln_map:
        impact_tasks = []
        for pkg in packages:
            for vuln in vuln_map.get(pkg.name, []):
                if vuln.severity in (Severity.CRITICAL, Severity.HIGH):
                    impact_tasks.append(analyze_impact(pkg, vuln, project_root))

        if impact_tasks:
            impact_results = await asyncio.gather(*impact_tasks, return_exceptions=True)
            report.impact_analyses = [r for r in impact_results if not isinstance(r, Exception)]
            report.affected_count = sum(1 for r in report.impact_analyses if r.is_affected)

    return report
