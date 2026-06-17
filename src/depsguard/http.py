from __future__ import annotations
import os
import httpx


def _proxy_url() -> str | None:
    """환경변수 우선순위: DEPSGUARD_PROXY > HTTPS_PROXY > HTTP_PROXY"""
    return (
        os.getenv("DEPSGUARD_PROXY")
        or os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
    )


def make_client(timeout: int = 15) -> httpx.AsyncClient:
    """프록시 설정을 자동 반영한 httpx AsyncClient를 반환합니다."""
    proxy = _proxy_url()
    if proxy:
        return httpx.AsyncClient(
            timeout=timeout,
            mounts={
                "https://": httpx.AsyncHTTPTransport(proxy=proxy),
                "http://": httpx.AsyncHTTPTransport(proxy=proxy),
            },
        )
    return httpx.AsyncClient(timeout=timeout)
