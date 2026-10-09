# src/sentinels/schemas/finding.py
from pydantic import BaseModel, Field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class Finding(BaseModel):
    """
    A strict data structure representing a single security vulnerability.
    When this is passed to an MAF agent as a result_schema, the LLM is 
    forced to output data that exactly matches this structure.
    """
    title: str = Field(..., description="A concise title for the vulnerability, e.g., 'SQL Injection in User Login'.")
    severity: Severity = Field(..., description="The severity rating of the vulnerability.")
    confidence: Confidence = Field(..., description="The agent's confidence that this is a real, exploitable vulnerability and not a false positive.")
    cwe: str = Field(..., description="The CWE identifier, e.g., 'CWE-89'.")
    file: str = Field(..., description="The file path where the vulnerability was found.")
    line_start: int = Field(..., description="The starting line number of the vulnerable code.")
    line_end: int = Field(..., description="The ending line number of the vulnerable code.")
    evidence: str = Field(..., description="The exact code snippet that is vulnerable.")
    description: str = Field(..., description="A detailed explanation of why this code is vulnerable.")
    remediation: str = Field(..., description="Specific instructions on how to fix the vulnerability.")
    patch: str | None = Field(default=None, description="Unified git diff showing the exact before and after code fix.")
    owasp: str | None = Field(default=None, description="OWASP Top 10 category mapping, e.g. 'A03:2021-Injection'.")
    cve: str | None = Field(default=None, description="CVE identifier if applicable, e.g. 'CVE-2023-32681'.")
    package_name: str | None = Field(default=None, description="Affected third-party package name for SCA findings.")
    fixed_version: str | None = Field(default=None, description="Remediated package version for SCA findings.")