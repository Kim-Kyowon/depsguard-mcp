from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

from depsguard.models import Package


def parse_requirements(path: Path) -> list[Package]:
    packages = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
            version = _extract_version(str(req.specifier))
            if version:
                packages.append(Package(name=req.name, version=version, ecosystem="PyPI"))
        except Exception:
            continue
    return packages


def parse_pyproject(path: Path) -> list[Package]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = []
    deps: list[str] = (
        data.get("project", {}).get("dependencies", [])
        or data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    )
    if isinstance(deps, dict):
        deps = [f"{k}>={v}" if isinstance(v, str) and v != "*" else k for k, v in deps.items()]
    for dep in deps:
        try:
            req = Requirement(dep)
            version = _extract_version(str(req.specifier))
            if version:
                packages.append(Package(name=req.name, version=version, ecosystem="PyPI"))
        except Exception:
            continue
    return packages


def _extract_version(specifier: str) -> str | None:
    m = re.search(r"==([^\s,]+)", specifier)
    if m:
        return m.group(1)
    m = re.search(r">=([^\s,]+)", specifier)
    if m:
        return m.group(1)
    return None
