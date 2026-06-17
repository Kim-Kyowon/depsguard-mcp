from __future__ import annotations

from depsguard.http import make_client
from depsguard.models import Package, Severity, Vulnerability

OSV_API = "https://api.osv.dev/v1/query"


async def query_osv(package: Package) -> list[Vulnerability]:
    payload = {
        "version": package.version,
        "package": {"name": package.name, "ecosystem": package.ecosystem},
    }
    async with make_client() as client:
        resp = await client.post(OSV_API, json=payload)
        resp.raise_for_status()
        data = resp.json()

    return [_parse_vuln(v) for v in data.get("vulns", [])]


_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,   # GitHub Advisory uses "MODERATE"
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_vuln(raw: dict) -> Vulnerability:
    db_specific = raw.get("database_specific", {})

    # 심각도: database_specific.severity(문자열) 우선, 없으면 UNKNOWN
    sev_str = (db_specific.get("severity") or "").upper()
    severity = _SEVERITY_MAP.get(sev_str, Severity.UNKNOWN)

    # CWE: database_specific.cwe_ids
    cwes = db_specific.get("cwe_ids") or []

    # 수정 버전: affected[].ranges[].events[].fixed
    fixed = None
    for affected in raw.get("affected", []):
        for rng in affected.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    fixed = evt["fixed"]
                    break
            if fixed:
                break
        if fixed:
            break

    return Vulnerability(
        id=raw.get("id", "UNKNOWN"),
        summary=raw.get("summary", "No summary available"),
        severity=severity,
        cvss_score=None,    # 벡터 문자열이므로 NVD 보완 시 채움
        cwe=cwes,
        fixed_version=fixed,
        references=[r.get("url", "") for r in raw.get("references", [])],
    )


def _severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
