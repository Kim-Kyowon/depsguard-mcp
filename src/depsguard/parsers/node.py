from __future__ import annotations

import json
import re
from pathlib import Path

from depsguard.models import Package


def parse_package_json(path: Path) -> list[Package]:
    data = json.loads(path.read_text(encoding="utf-8"))
    packages = []
    all_deps: dict[str, str] = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
    }
    for name, version_spec in all_deps.items():
        version = _clean_version(version_spec)
        if version:
            packages.append(Package(name=name, version=version, ecosystem="npm"))
    return packages


def _clean_version(spec: str) -> str | None:
    cleaned = re.sub(r"[^0-9.]", "", spec.split(" ")[0])
    return cleaned if cleaned else None
