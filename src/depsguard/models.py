from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Package(BaseModel):
    name: str
    version: str
    ecosystem: str  # PyPI, npm, Go, Maven


class Vulnerability(BaseModel):
    id: str                          # CVE-2023-XXXX or GHSA-XXXX
    summary: str
    severity: Severity
    cvss_score: float | None = None
    cwe: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    references: list[str] = Field(default_factory=list)


class ImpactAnalysis(BaseModel):
    vuln_id: str
    package: Package
    is_affected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    affected_files: list[str] = Field(default_factory=list)
    reason: str
    recommendation: str


class BreakingChange(BaseModel):
    description: str
    affected_files: list[str]
    affected_lines: list[int] = Field(default_factory=list)
    suggested_fix: str | None = None


class UpgradeAnalysis(BaseModel):
    package: Package
    target_version: str
    breaking_changes: list[BreakingChange]
    is_safe: bool
    summary: str


class ScanReport(BaseModel):
    scanned_file: str
    packages: list[Package]
    vulnerabilities: dict[str, list[Vulnerability]] = Field(default_factory=dict)
    impact_analyses: list[ImpactAnalysis] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    affected_count: int = 0
