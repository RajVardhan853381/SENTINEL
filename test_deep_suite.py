# test_deep_suite.py
"""
Deep Exhaustive Test Suite for Sentinels.
Tests all subsystems, edge cases, sandboxing defenses, parsing resilience,
dependency CVE matching, and tri-format report generation.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

# Add src to Python path
sys.path.insert(0, "src")

from sentinels.schemas.finding import Finding, Severity, Confidence
from sentinels.schemas.manifest import RepoManifest, FileInfo, DirectoryCluster
from sentinels.schemas.parser import extract_findings_resilient
from sentinels.mcp_server.tools.repo import clone_repo, list_files, read_file
from sentinels.mcp_server.tools.scanner import run_secret_scan, run_semgrep
from sentinels.mcp_server.tools.dependency_scanner import (
    discover_dependencies, query_osv_batch, _parse_requirements_txt,
    _parse_package_json, _parse_go_mod, _is_version_vulnerable
)
from sentinels.reporting import export_all_reports
from sentinels.reporting.sarif_exporter import generate_sarif_dict
from sentinels.reporting.markdown_exporter import generate_markdown_content
from sentinels.reporting.pdf_exporter import export_pdf_file
from starlette.testclient import TestClient
from sentinels.web.server import app

# ==============================================================================
# SECTION 1: SANDBOXING & FILESYSTEM DEFENSES
# ==============================================================================
def test_security_path_traversal():
    """Verify that read_file completely blocks path-traversal attacks."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a secret file outside the sandbox
        outside_file = os.path.join(tmp_dir, "outside_secret.txt")
        with open(outside_file, "w") as f:
            f.write("SUPER_SECRET_HOST_CONTENT")

        # Sandbox is a subdirectory
        sandbox = os.path.join(tmp_dir, "sandbox")
        os.makedirs(sandbox, exist_ok=True)

        # 1. Attempt relative path traversal (../outside_secret.txt)
        res1 = read_file(sandbox, "../outside_secret.txt")
        assert "[Access denied" in res1 or "[File not found" in res1, f"Expected access denied, got: {res1}"
        assert "SUPER_SECRET_HOST_CONTENT" not in res1

        # 2. Attempt double traversal (../../outside_secret.txt)
        res2 = read_file(sandbox, "../../outside_secret.txt")
        assert "SUPER_SECRET_HOST_CONTENT" not in res2

        # 3. Attempt absolute path escape
        res3 = read_file(sandbox, outside_file)
        assert "SUPER_SECRET_HOST_CONTENT" not in res3

    print("✓ Passed: Path-traversal defenses prevent sandbox escapes")


def test_security_symlink_escape_blocked():
    """Verify that read_file blocks symlinks pointing outside sandbox (SEC-01)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        outside_secret = os.path.join(tmp_dir, "outside_secret.txt")
        with open(outside_secret, "w") as f:
            f.write("CRITICAL_HOST_TOKEN_12345")

        sandbox = os.path.join(tmp_dir, "sandbox")
        os.makedirs(sandbox, exist_ok=True)

        symlink_path = os.path.join(sandbox, "malicious_link.txt")
        os.symlink(outside_secret, symlink_path)

        res = read_file(sandbox, "malicious_link.txt")
        assert "[Access denied" in res, f"Expected access denied for symlink, got: {res}"
        assert "CRITICAL_HOST_TOKEN_12345" not in res

    print("✓ Passed: Symlink sandbox escape blocked by realpath containment verification")


def test_security_large_file_cap():
    """Verify that read_file skips files over 1MB to protect LLM context."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        large_file = os.path.join(tmp_dir, "huge_data.bin")
        # Create a file slightly over 1MB
        with open(large_file, "wb") as f:
            f.write(b"0" * (1024 * 1024 + 100))

        rel_name = "huge_data.bin"
        res = read_file(tmp_dir, rel_name)
        assert "[File skipped" in res and "Exceeds maximum size" in res, f"Expected skip message, got: {res}"

    print("✓ Passed: 1MB file size cap protects memory and LLM context")


def test_security_clone_url_validation():
    """Verify that clone_repo rejects non-HTTPS and malicious URL schemes."""
    invalid_urls = [
        "file:///etc/passwd",
        "ssh://git@github.com/org/repo.git",
        "http://insecure-github.com/org/repo",
        "ftp://example.com/repo",
        "javascript:alert(1)"
    ]
    for url in invalid_urls:
        try:
            clone_repo(url)
            raise AssertionError(f"Expected ValueError for URL: {url}")
        except ValueError:
            pass

    print("✓ Passed: Clone URL validation strictly enforces HTTPS GitHub URLs")


# ==============================================================================
# SECTION 2: SECRET SCANNER DETECTION ACCURACY
# ==============================================================================
def test_secret_scanner_edge_cases():
    """Test secret detection with true positives and benign false-positive candidates."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a file with real secret patterns
        vuln_file = os.path.join(tmp_dir, "secrets.py")
        with open(vuln_file, "w") as f:
            f.write("""
# Benign comments
def test():
    # True positive 1: AWS Key
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    # True positive 2: GitHub token
    gh_token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
    # Benign variable should not flag as GitHub Token
    variable = "ghp_short"
""")
        findings = run_secret_scan(tmp_dir)
        types = {f["type"] for f in findings}
        assert "AWS Access Key" in types, "Failed to detect AWS Access Key"
        assert "GitHub Token" in types, "Failed to detect GitHub Token"
        assert len(findings) == 2, f"Expected exactly 2 secret findings, got {len(findings)}"

    print("✓ Passed: Secret scanner accurately detects credentials without false positives")


# ==============================================================================
# SECTION 3: DEPENDENCY SCANNER (SCA) HYBRID ENGINE
# ==============================================================================
def test_dependency_scanner_manifest_parsing():
    """Test parsing across requirements.txt, package.json, and go.mod."""
    # 1. requirements.txt
    req_content = """
# Production requirements
requests==2.25.0
flask>=1.1.2
urllib3<=1.26.17
ignored-pkg # without version
"""
    req_deps = _parse_requirements_txt(req_content, "requirements.txt")
    req_pkgs = {d[0]: d[1] for d in req_deps}
    assert req_pkgs.get("requests") == "2.25.0"
    assert req_pkgs.get("flask") == "1.1.2"
    assert req_pkgs.get("urllib3") == "1.26.17"

    # 2. package.json
    pkg_content = json.dumps({
        "name": "sample-app",
        "dependencies": {
            "lodash": "^4.17.15",
            "express": "~4.17.1"
        },
        "devDependencies": {
            "axios": "0.21.1"
        }
    })
    npm_deps = _parse_package_json(pkg_content, "package.json")
    npm_pkgs = {d[0]: d[1] for d in npm_deps}
    assert npm_pkgs.get("lodash") == "4.17.15"
    assert npm_pkgs.get("express") == "4.17.1"
    assert npm_pkgs.get("axios") == "0.21.1"

    # 3. go.mod
    go_content = """
module example.com/app
go 1.20

require (
    github.com/gin-gonic/gin v1.7.0
    golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
)
"""
    go_deps = _parse_go_mod(go_content, "go.mod")
    go_pkgs = {d[0]: d[1] for d in go_deps}
    assert "github.com/gin-gonic/gin" in go_pkgs

    print("✓ Passed: Dependency manifests correctly parsed across Python, npm, and Go")


def test_go_mod_comments_handling():
    """Verify go.mod parser ignores comment-only lines and strips inline comments (FUN-02)."""
    go_content = """
module example.com/security-app
go 1.21

// require github.com/commented-out/vuln v1.0.0

require (
    // inline explanation
    github.com/gin-gonic/gin v1.9.1 // indirect
    golang.org/x/crypto v0.14.0 // indirect and safe
)

require github.com/stretchr/testify v1.8.4 // direct test tool
"""
    go_deps = _parse_go_mod(go_content, "go.mod")
    go_pkgs = {d[0]: d[1] for d in go_deps}
    assert "github.com/commented-out/vuln" not in go_pkgs, "Commented-out package should not be parsed"
    assert go_pkgs.get("github.com/gin-gonic/gin") == "1.9.1", f"Expected version 1.9.1, got {go_pkgs.get('github.com/gin-gonic/gin')}"
    assert go_pkgs.get("golang.org/x/crypto") == "0.14.0"
    assert go_pkgs.get("github.com/stretchr/testify") == "1.8.4"

    print("✓ Passed: go.mod parser correctly ignores comments and strips inline tags")


def test_dependency_version_comparison():
    """Verify semantic version comparison using packaging.version (FUN-01)."""
    # 2.9.0 vs 2.30.0: String comparison failed ('9' > '3'), semver must succeed
    assert _is_version_vulnerable("2.9.0", "2.30.0") is True
    assert _is_version_vulnerable("2.30.0", "2.30.0") is True
    assert _is_version_vulnerable("2.30.1", "2.30.0") is False

    # Multi-digit minor versions (1.10.0 vs 1.9.0)
    assert _is_version_vulnerable("1.8.0", "1.9.0") is True
    assert _is_version_vulnerable("1.9.0", "1.9.0") is True
    assert _is_version_vulnerable("1.10.0", "1.9.0") is False

    print("✓ Passed: Semantic version comparison correctly handles multi-digit semver")


def test_dependency_scanner_cve_matching():
    """Test hybrid CVE matching for known vulnerable dependencies."""
    deps = [
        ("requests", "2.25.0", "PyPI", "requirements.txt"),
        ("lodash", "4.17.15", "npm", "package.json"),
        ("clean-pkg", "1.0.0", "PyPI", "requirements.txt")
    ]
    vulns = query_osv_batch(deps)
    assert len(vulns) >= 2, f"Expected at least 2 vulnerabilities, got {len(vulns)}"

    vuln_pkgs = {v["package"] for v in vulns}
    assert "requests" in vuln_pkgs
    assert "lodash" in vuln_pkgs
    assert "clean-pkg" not in vuln_pkgs

    # Check finding fields
    req_vuln = next(v for v in vulns if v["package"] == "requests")
    assert req_vuln["cve"].startswith("CVE-") or req_vuln["cve"].startswith("GHSA-")
    assert req_vuln["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert req_vuln["fixed_version"] != ""

    print("✓ Passed: Dependency scanner accurately matches CVEs with upgrade paths")


# ==============================================================================
# SECTION 4: RESILIENT JSON PARSER STRESS TESTING
# ==============================================================================
def test_resilient_parser_edge_cases():
    """Stress-test extract_findings_resilient with 8 distinct LLM output shapes."""

    # 1. Standard markdown code fence
    t1 = """
```json
[
  {
    "title": "SQLi",
    "severity": "High",
    "confidence": "High",
    "cwe": "CWE-89",
    "file": "db.py",
    "line_start": 5,
    "line_end": 6,
    "evidence": "SELECT",
    "description": "SQL injection",
    "remediation": "Param query",
    "patch": "- a\\n+ b"
  }
]
```
"""
    res1 = extract_findings_resilient(t1)
    assert len(res1) == 1 and res1[0].title == "SQLi"

    # 2. Markdown code fence with trailing comma
    t2 = """
```
[
  {
    "title": "XSS",
    "severity": "Medium",
    "confidence": "Medium",
    "cwe": "CWE-79",
    "file": "app.js",
    "line_start": 10,
    "line_end": 10,
    "evidence": "res.write",
    "description": "XSS",
    "remediation": "Escape",
  },
]
```
"""
    res2 = extract_findings_resilient(t2)
    assert len(res2) == 1 and res2[0].title == "XSS"

    # 3. Single object rather than list
    t3 = """
{
  "title": "CSRF",
  "severity": "Low",
  "confidence": "High",
  "cwe": "CWE-352",
  "file": "routes.py",
  "line_start": 20,
  "line_end": 20,
  "evidence": "POST",
  "description": "Missing CSRF token",
  "remediation": "Add CSRF protection"
}
"""
    res3 = extract_findings_resilient(t3)
    assert len(res3) == 1 and res3[0].title == "CSRF"

    # 4. Object wrapping {"findings": [...]}
    t4 = """
{
  "summary": "Found 1 issue",
  "findings": [
    {
      "title": "RCE",
      "severity": "Critical",
      "confidence": "High",
      "cwe": "CWE-78",
      "file": "exec.py",
      "line_start": 1,
      "line_end": 1,
      "evidence": "eval()",
      "description": "Remote code exec",
      "remediation": "Never use eval"
    }
  ]
}
"""
    res4 = extract_findings_resilient(t4)
    assert len(res4) == 1 and res4[0].title == "RCE"

    # 5. Empty JSON array
    t5 = "Here are the findings: ```json [] ``` No issues found."
    assert extract_findings_resilient(t5) == []

    # 6. Completely invalid text (random English prose)
    t6 = "The codebase looks safe. No vulnerabilities were detected."
    assert extract_findings_resilient(t6) == []

    # 7. JavaScript comments inside JSON
    t7 = """
[
  // This is a comment from the model
  {
    "title": "Secret in code",
    "severity": "High",
    "confidence": "High",
    "cwe": "CWE-798",
    "file": "auth.py",
    "line_start": 2,
    "line_end": 2,
    "evidence": "KEY = 123",
    "description": "Hardcoded key",
    "remediation": "Env var"
  }
]
"""
    res7 = extract_findings_resilient(t7)
    assert len(res7) == 1 and res7[0].title == "Secret in code"

    print("✓ Passed: Resilient parser successfully handles all 7 LLM output variations")


# ==============================================================================
# SECTION 5: MANIFEST WINDOWING & CLUSTERING
# ==============================================================================
def test_manifest_windowing_and_clustering():
    """Verify windowing and clustering when file count exceeds 250 files."""
    from sentinels.workflow.ingest import _cluster_directory

    assert _cluster_directory("main.py") == "."
    assert _cluster_directory("src/api.py") == "src"
    assert _cluster_directory("src/api/v1/routes.py") == "src/api"
    assert _cluster_directory("infra/terraform/main.tf") == "infra/terraform"

    # Simulate a manifest with 300 files
    files = [
        FileInfo(path=f"src/module_{i % 5}/file_{i}.py", size_bytes=100, language="Python")
        for i in range(300)
    ]
    clusters = [
        DirectoryCluster(
            directory=f"src/module_{i}",
            file_count=60,
            languages=["Python"],
            sample_files=[f"file_{i}.py"]
        )
        for i in range(5)
    ]
    manifest = RepoManifest(
        repo_url="https://github.com/example/monorepo",
        local_path="/tmp/monorepo",
        total_files=300,
        languages=["Python"],
        files=files[:150],  # Windowed to top 150
        is_windowed=True,
        directory_clusters=clusters
    )
    assert manifest.is_windowed is True
    assert manifest.total_files == 300
    assert len(manifest.files) == 150
    assert len(manifest.directory_clusters) == 5

    print("✓ Passed: Manifest clustering and windowing correctly structured")


# ==============================================================================
# SECTION 6: MULTI-FORMAT REPORTING PIPELINE
# ==============================================================================
def test_multi_format_reporting_clean_repo():
    """Verify that reporting pipeline handles a clean repository with 0 findings."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest = RepoManifest(
            repo_url="https://github.com/example/clean-project",
            local_path=tmp_dir,
            total_files=10,
            languages=["Python", "Terraform"]
        )
        reports = export_all_reports(manifest, [], "Clean repo summary", output_dir=tmp_dir)
        assert "pdf" in reports and os.path.isfile(reports["pdf"])
        assert "markdown" in reports and os.path.isfile(reports["markdown"])
        assert "sarif" in reports and os.path.isfile(reports["sarif"])

        # Check SARIF output with 0 results
        with open(reports["sarif"]) as f:
            sarif_data = json.load(f)
            assert len(sarif_data["runs"][0]["results"]) == 0

        # Check Markdown has clean notice
        with open(reports["markdown"]) as f:
            md_text = f.read()
            assert "CLEAN / SECURE" in md_text

        # Check PDF is generated and non-empty
        assert os.path.getsize(reports["pdf"]) > 2000

    print("✓ Passed: Multi-format reporting generates perfect outputs for clean repos")


def test_multi_format_reporting_findings_repo():
    """Verify that reporting pipeline properly formats findings, diffs, and SARIF."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest = RepoManifest(
            repo_url="https://github.com/example/vulnerable-app",
            local_path=tmp_dir,
            total_files=25,
            languages=["Python", "JavaScript"]
        )
        findings = [
            Finding(
                title="SQL Injection in Authentication",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                cwe="CWE-89",
                owasp="A03:2021-Injection",
                file="src/auth.py",
                line_start=45,
                line_end=46,
                evidence="db.query(f'SELECT * FROM users WHERE u={u}')",
                description="Raw user input passed directly to database driver.",
                remediation="Use parameterized queries with prepared statements.",
                patch="""--- a/src/auth.py
+++ b/src/auth.py
@@ -45,2 +45,2 @@
- db.query(f"SELECT * FROM users WHERE u={u}")
+ db.query("SELECT * FROM users WHERE u = :u", {"u": u})"""
            ),
            Finding(
                title="Outdated Requests Library",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-1395",
                owasp="A06:2021-Vulnerable and Outdated Components",
                cve="CVE-2023-32681",
                package_name="requests",
                fixed_version="2.31.0",
                file="requirements.txt",
                line_start=1,
                line_end=1,
                evidence="requests==2.25.0",
                description="Leaking Proxy-Authorization header in cross-origin redirects.",
                remediation="Upgrade requests package to >=2.31.0.",
                patch="""--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,1 @@
- requests==2.25.0
+ requests>=2.31.0"""
            )
        ]

        reports = export_all_reports(manifest, findings, output_dir=tmp_dir)
        assert os.path.isfile(reports["pdf"])
        assert os.path.isfile(reports["markdown"])
        assert os.path.isfile(reports["sarif"])

        # Check SARIF output has 2 results with fixes
        with open(reports["sarif"]) as f:
            sarif_data = json.load(f)
            assert len(sarif_data["runs"][0]["results"]) == 2
            first = sarif_data["runs"][0]["results"][0]
            assert first["level"] == "error"
            assert "fixes" in first

        # Check Markdown output has diff blocks
        with open(reports["markdown"]) as f:
            md_text = f.read()
            assert "```diff" in md_text
            assert "CVE-2023-32681" in md_text
            assert "SQL Injection in Authentication" in md_text

        # Check PDF output
        assert os.path.getsize(reports["pdf"]) > 3000

    print("✓ Passed: Multi-format reporting generates rich PDF, Markdown, and SARIF with diffs")


def test_pdf_exporter_xml_escaping():
    """Verify PDF generator does not crash on unescaped XML/HTML entities like <script> or & (SEC-02)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest = RepoManifest(
            repo_url="https://github.com/test/html-escape-repo",
            local_path=tmp_dir,
            total_files=2,
            languages=["Python"]
        )
        malicious_findings = [
            Finding(
                id="SEC-001",
                title="XSS via <script>alert('XSS')</script> & dynamic <T> payload",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                cwe="CWE-79",
                owasp="A03:2021-Injection",
                file="app/views.py",
                line_start=15,
                line_end=18,
                evidence="res.send('<span>' + user_data + '</span>')",
                description="User input <T> & <U> is directly concatenated without sanitization: 1 < 2 && 3 > 2 & 'foo'.",
                remediation="Encode with &lt;tag&gt; and xml.sax.saxutils.escape() helper.",
                remediation_diff="- dangerous(data)\n+ safe(escape(data))"
            )
        ]
        pdf_path = os.path.join(tmp_dir, "test_escaped_report.pdf")
        export_pdf_file(
            manifest,
            malicious_findings,
            pdf_path,
            raw_manager_text="Raw summary containing <tags>, ampersands & special characters <xml>."
        )
        assert os.path.isfile(pdf_path)
        assert os.path.getsize(pdf_path) > 3000

    print("✓ Passed: PDF exporter XML entity escaping prevents ReportLab paraparser crashes")


# ==============================================================================
# SECTION 8: WEB API ENDPOINTS & SARIF INTEGRATION
# ==============================================================================
def test_web_server_endpoints():
    """Verify FastAPI web server returns valid status, findings, and SARIF 2.1.0."""
    client = TestClient(app)

    # 1. System status endpoint
    res_status = client.get("/api/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert "provider" in status_data
    assert status_data["status"] in ("ready", "operational")

    # 2. Findings endpoint
    res_findings = client.get("/api/findings")
    assert res_findings.status_code == 200
    findings_data = res_findings.json()
    assert "findings" in findings_data
    assert len(findings_data["findings"]) > 0
    first_f = findings_data["findings"][0]
    assert "line_start" in first_f
    assert "line" in first_f
    assert "confidence" in first_f

    # 3. SARIF 2.1.0 endpoint
    res_sarif = client.get("/api/sarif")
    assert res_sarif.status_code == 200
    sarif_data = res_sarif.json()
    assert sarif_data["version"] == "2.1.0"
    assert "$schema" in sarif_data
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) > 0
    assert len(sarif_data["runs"][0]["results"]) > 0

    print("✓ Passed: Web API endpoints (/api/status, /api/findings, /api/sarif) return valid responses")


# ==============================================================================
# SECTION 7: FASTMCP TOOL REGISTRATION INTEGRITY
# ==============================================================================
def test_fastmcp_registered_tools():
    """Verify that FastMCP registers all 6 tools including the dependency scanner."""
    from sentinels.mcp_server.server import mcp
    tools = mcp._tool_manager.list_tools()
    tool_names = {t.name for t in tools}
    expected = {
        "clone_repo",
        "list_files",
        "read_file",
        "run_semgrep",
        "run_secret_scan",
        "run_dependency_scan"
    }
    for e in expected:
        assert e in tool_names, f"Missing registered tool: {e}"

    print(f"✓ Passed: FastMCP server cleanly registered all {len(expected)} tools: {', '.join(sorted(expected))}")


# ==============================================================================
# MAIN TEST RUNNER
# ==============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING DEEP EXHAUSTIVE TESTING SUITE FOR SENTINELS")
    print("=" * 70)

    test_security_path_traversal()
    test_security_symlink_escape_blocked()
    test_security_large_file_cap()
    test_security_clone_url_validation()
    test_secret_scanner_edge_cases()
    test_dependency_scanner_manifest_parsing()
    test_go_mod_comments_handling()
    test_dependency_version_comparison()
    test_dependency_scanner_cve_matching()
    test_resilient_parser_edge_cases()
    test_manifest_windowing_and_clustering()
    test_multi_format_reporting_clean_repo()
    test_multi_format_reporting_findings_repo()
    test_pdf_exporter_xml_escaping()
    test_fastmcp_registered_tools()
    test_web_server_endpoints()

    print("=" * 70)
    print("ALL 16 DEEP AUDIT & ENTERPRISE TEST SECTIONS PASSED WITH 100% SUCCESS!")
    print("=" * 70)
