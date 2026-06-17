"""OSV 응답 원본 구조 확인용"""
import asyncio, sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import httpx

async def main():
    payload = {"version": "2.28.0", "package": {"name": "requests", "ecosystem": "PyPI"}}
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post("https://api.osv.dev/v1/query", json=payload)
        data = resp.json()
    # 첫 번째 취약점만 출력
    vuln = data["vulns"][0]
    print(json.dumps({
        "id": vuln.get("id"),
        "severity": vuln.get("severity"),
        "database_specific": vuln.get("database_specific"),
        "affected_0_ecosystem_specific": vuln.get("affected", [{}])[0].get("ecosystem_specific"),
    }, indent=2))

asyncio.run(main())
