from __future__ import annotations

import os

from depsguard.http import make_client

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def query_nvd(cve_id: str) -> dict | None:
    """CVSS 점수·CWE 상세 보완용 — NVD는 보조 소스로만 사용."""
    params = {"cveId": cve_id}
    headers = {}
    if api_key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key

    async with make_client() as client:
        try:
            resp = await client.get(NVD_API, params=params, headers=headers)
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            return items[0] if items else None
        except Exception:
            return None


async def enrich_cvss(cve_id: str) -> tuple[float | None, list[str]]:
    """CVE ID로 CVSS 점수와 CWE 목록을 반환."""
    data = await query_nvd(cve_id)
    if not data:
        return None, []

    cve = data.get("cve", {})
    score = None
    for metric_group in cve.get("metrics", {}).values():
        for m in metric_group:
            score = m.get("cvssData", {}).get("baseScore")
            if score:
                break

    cwes = [
        w.get("description", [{}])[0].get("value", "")
        for w in cve.get("weaknesses", [])
    ]
    return score, [c for c in cwes if c]
