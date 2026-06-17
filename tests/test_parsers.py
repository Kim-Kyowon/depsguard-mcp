from pathlib import Path
import pytest
from depsguard.parsers.python import parse_requirements, parse_pyproject
from depsguard.parsers.node import parse_package_json


@pytest.fixture
def tmp_req(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.28.0\ndjango>=3.2.0\n# comment\nflask==2.3.1\n")
    return f


@pytest.fixture
def tmp_pkg_json(tmp_path):
    f = tmp_path / "package.json"
    f.write_text('{"dependencies": {"axios": "^1.4.0", "react": "^18.2.0"}}')
    return f


def test_parse_requirements(tmp_req):
    pkgs = parse_requirements(tmp_req)
    names = [p.name for p in pkgs]
    assert "requests" in names
    assert "flask" in names
    assert all(p.ecosystem == "PyPI" for p in pkgs)
    req = next(p for p in pkgs if p.name == "requests")
    assert req.version == "2.28.0"


def test_parse_package_json(tmp_pkg_json):
    pkgs = parse_package_json(tmp_pkg_json)
    names = [p.name for p in pkgs]
    assert "axios" in names
    assert "react" in names
    assert all(p.ecosystem == "npm" for p in pkgs)


def test_parse_requirements_skips_comments(tmp_req):
    pkgs = parse_requirements(tmp_req)
    assert all(p.name != "comment" for p in pkgs)
