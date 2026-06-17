import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from depsguard.db.osv import query_osv, _severity_from_score
from depsguard.models import Package, Severity

MOCK_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "CVE-2023-32681",
            "summary": "Requests forwards proxy-authorization header to destination servers",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
            "references": [{"url": "https://example.com/advisory"}],
        }
    ]
}


@pytest.mark.asyncio
async def test_query_osv_returns_vulns():
    pkg = Package(name="requests", version="2.28.0", ecosystem="PyPI")

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()                              # json()은 동기 메서드
        mock_resp.json.return_value = MOCK_OSV_RESPONSE
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        vulns = await query_osv(pkg)

    assert len(vulns) == 1
    assert vulns[0].id == "CVE-2023-32681"
    assert vulns[0].fixed_version == "2.31.0"


@pytest.mark.asyncio
async def test_query_osv_empty():
    pkg = Package(name="safe-package", version="1.0.0", ecosystem="PyPI")

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        vulns = await query_osv(pkg)

    assert vulns == []


def test_severity_from_score():
    assert _severity_from_score(9.5) == Severity.CRITICAL
    assert _severity_from_score(7.5) == Severity.HIGH
    assert _severity_from_score(5.0) == Severity.MEDIUM
    assert _severity_from_score(2.0) == Severity.LOW
    assert _severity_from_score(None) == Severity.UNKNOWN
