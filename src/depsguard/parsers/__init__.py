from pathlib import Path

from depsguard.models import Package
from depsguard.parsers.node import parse_package_json
from depsguard.parsers.python import parse_pyproject, parse_requirements


def parse_dependency_file(filepath: str) -> list[Package]:
    path = Path(filepath)
    name = path.name.lower()

    if name == "requirements.txt":
        return parse_requirements(path)
    elif name == "pyproject.toml":
        return parse_pyproject(path)
    elif name == "package.json":
        return parse_package_json(path)
    else:
        raise ValueError(f"지원하지 않는 파일 형식: {name}")
