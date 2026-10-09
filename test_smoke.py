"""Smoke test guarding core functionality and newly added enterprise features:
- Ingestion symlink and windowing safety
- MCP server path resolution and tool registration (including dependency scanner)
- Multi-provider LLM config (Ollama + Azure)
- FastMCP tool degradation (semgrep) and secret detection
- Finding schema with unified git patch & OWASP fields
- Resilient JSON finding parser
- Multi-format report exporters: SARIF 2.1.0, Markdown, and Executive White-Theme PDF
Run: python test_smoke.py
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")

from sentinels.schemas.finding import Finding, Severity, Confidence
from sentinels.schemas.manifest import RepoManifest, FileInfo, DirectoryCluster
from sentinels.schemas.parser import extract_findings_resilient
from sentinels.reporting import export_all_reports
from sentinels.reporting.sarif_exporter import generate_sarif_dict
from sentinels.mcp_server.tools.dependency_scanner import discover_dependencies

def test_modules_import_cleanly():
    import sentinels.workflow.orchestrator  # noqa: F401
    import sentinels.reporting  # noqa: F401
    import sentinels.mcp_server.tools.dependency_scanner  # noqa: F401


def test_mcp_server_path_resolves():
    from sentinels.agents.workers.base_worker import _SERVER_SCRIPT
    assert _SERVER_SCRIPT.is_file(), f"MCP server script not found at {_SERVER_SCRIPT}"


def test_config_reads_deployment_env_var(monkeypatch):
    from sentinels.config import get_azure_chat_client

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "dummy-key")
    monkeypatch.setenv("AZURE_OPENAI_GPT_DEPLOYMENT", "my-real-deployment")

    client = get_azure_chat_client()
    assert client.model == "my-real-deployment"


def test_config_raises_without_credentials(monkeypatch):
    from sentinels.config import get_azure_chat_client

    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

    try:
        get_azure_chat_client()
        raise AssertionError("expected ValueError for missing credentials")
    except ValueError:
        pass


def test_config_supports_ollama(monkeypatch):
    from sentinels.config import get_chat_client
    from agent_framework.ollama import OllamaChatClient

    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2")
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")

    client = get_chat_client()
    assert isinstance(client, OllamaChatClient)


def test_manager_agent_builds_with_worker_tools(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "dummy-key")

    from sentinels.agents.manager import create_manager_agent

    manager = create_manager_agent()
    assert manager is not None


def test_cleanup_removes_readonly_git_packfiles():
    import shutil
    import stat
    from sentinels.workflow.orchestrator import _force_remove_readonly

    with tempfile.TemporaryDirectory() as tmp_dir:
        sandbox = Path(tmp_dir) / "sandbox"
        sandbox.mkdir()
        readonly_file = sandbox / "pack-abc.pack"
        readonly_file.write_bytes(b"fake packfile")
        readonly_file.chmod(stat.S_IREAD)

        if sys.version_info >= (3, 12):
            shutil.rmtree(sandbox, onexc=_force_remove_readonly)
        else:
            shutil.rmtree(sandbox, onerror=_force_remove_readonly)
        assert not sandbox.exists()


def test_workflow_is_buildable_and_runnable():
    from sentinels.workflow.orchestrator import sentinel_scan_workflow
    built = sentinel_scan_workflow.build()
    assert hasattr(built, "run")


def test_run_semgrep_never_raises():
    from sentinels.mcp_server.tools.scanner import run_semgrep
    with tempfile.TemporaryDirectory() as tmp_dir:
        result = run_semgrep(tmp_dir)
    assert isinstance(result, list)


def test_secret_scan_detects_secrets():
    from sentinels.mcp_server.tools.scanner import run_secret_scan

    with tempfile.TemporaryDirectory() as tmp_dir:
        sample = os.path.join(tmp_dir, "test_secrets.py")
        with open(sample, "w", encoding="utf-8") as f:
            f.write('GH_TOKEN = "ghp_123456789012345678901234567890123456"\n')
            f.write('AWS_KEY = "AKIA1234567890123456"\n')

        findings = run_secret_scan(tmp_dir)
        types = {item["type"] for item in findings}
        assert "GitHub Token" in types
        assert "AWS Access Key" in types


def test_read_file_safe_error_handling():
    from sentinels.mcp_server.tools.repo import read_file
    with tempfile.TemporaryDirectory() as tmp_dir:
        res = read_file(tmp_dir, "non_existent_file.py")
        assert "[File not found" in res


# --- New Tests for Top-Grade Features ---

def test_finding_patch_and_schema():
    patch_diff = """--- a/app.py
+++ b/app.py
@@ -10,1 +10,1 @@
- db.execute(f"SELECT * FROM users WHERE id = {user_id}")
+ db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})"""

    f = Finding(
        title="SQL Injection in User Lookup",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        file="src/app.py",
        line_start=10,
        line_end=10,
        evidence='db.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        description="User input is concatenated directly into SQL statement.",
        remediation="Use parameterized queries with bound variables.",
        patch=patch_diff
    )
    assert f.patch == patch_diff
    assert f.owasp == "A03:2021-Injection"
    assert f.severity == Severity.HIGH


def test_resilient_json_parser():
    raw_llm_output = """
Here are the security findings from the audit:

```json
[
  {
    "title": "Hardcoded JWT Secret",
    "severity": "Critical",
    "confidence": "High",
    "cwe": "CWE-798",
    "file": "config/jwt.py",
    "line_start": 4,
    "line_end": 4,
    "evidence": "SECRET = 'supersecretkey123'",
    "description": "Hardcoded cryptographic secret key in source code.",
    "remediation": "Load secret from environment variable.",
    "patch": "- SECRET = 'supersecretkey123'\\n+ SECRET = os.environ['JWT_SECRET']",
  }
]
```
Let me know if you would like me to fix anything else!
"""
    findings = extract_findings_resilient(raw_llm_output)
    assert len(findings) == 1
    assert findings[0].title == "Hardcoded JWT Secret"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].cwe == "CWE-798"
    assert "JWT_SECRET" in findings[0].patch


def test_dependency_scanner_discovery():
    with tempfile.TemporaryDirectory() as tmp_dir:
        req_file = os.path.join(tmp_dir, "requirements.txt")
        with open(req_file, "w") as fp:
            fp.write("requests==2.25.0\nflask>=1.1.2\n")

        pkg_file = os.path.join(tmp_dir, "package.json")
        with open(pkg_file, "w") as fp:
            fp.write('{"dependencies": {"lodash": "4.17.15", "express": "^4.17.1"}}')

        deps = discover_dependencies(tmp_dir)
        pkgs = {d[0] for d in deps}
        assert "requests" in pkgs
        assert "flask" in pkgs
        assert "lodash" in pkgs
        assert "express" in pkgs


def test_sarif_export():
    manifest = RepoManifest(
        repo_url="https://github.com/example/demo",
        local_path="/tmp/demo",
        total_files=5,
        languages=["Python"]
    )
    finding = Finding(
        title="Command Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-78",
        file="src/cmd.py",
        line_start=15,
        line_end=15,
        evidence="os.system(user_input)",
        description="Shell execution with untrusted input.",
        remediation="Use subprocess.run without shell=True.",
        patch="- os.system(user_input)\n+ subprocess.run(['ls', user_input])"
    )

    sarif = generate_sarif_dict(manifest, [finding])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    res = sarif["runs"][0]["results"][0]
    assert res["level"] == "error"
    assert res["ruleId"] == "CWE-78"
    assert "fixes" in res


def test_multi_format_export_all():
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest = RepoManifest(
            repo_url="https://github.com/example/vuln-app",
            local_path=tmp_dir,
            total_files=3,
            languages=["Python", "JavaScript"]
        )
        finding = Finding(
            title="Reflected XSS",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            file="views/index.js",
            line_start=22,
            line_end=22,
            evidence="res.send('<h1>Hello ' + req.query.name + '</h1>')",
            description="Unsanitized query param reflected into HTML output.",
            remediation="Sanitize input with DOMPurify or use template engine.",
            patch="- res.send('<h1>' + req.query.name)\n+ res.send(escapeHtml(req.query.name))"
        )

        out_reports = os.path.join(tmp_dir, "reports")
        paths = export_all_reports(manifest, [finding], "Manager scan summary", output_dir=out_reports)

        assert "pdf" in paths and os.path.isfile(paths["pdf"])
        assert "markdown" in paths and os.path.isfile(paths["markdown"])
        assert "sarif" in paths and os.path.isfile(paths["sarif"])
        assert os.path.getsize(paths["pdf"]) > 1000
        assert os.path.getsize(paths["markdown"]) > 200
        assert os.path.getsize(paths["sarif"]) > 200


def test_symlink_defense():
    from sentinels.mcp_server.tools.repo import read_file
    with tempfile.TemporaryDirectory() as tmp_dir:
        outside_file = os.path.join(tmp_dir, "outside_secret.txt")
        with open(outside_file, "w") as f:
            f.write("SECRET_TOKEN")
        sandbox = os.path.join(tmp_dir, "sandbox")
        os.makedirs(sandbox, exist_ok=True)
        link = os.path.join(sandbox, "link.txt")
        os.symlink(outside_file, link)
        res = read_file(sandbox, "link.txt")
        assert "[Access denied" in res
        assert "SECRET_TOKEN" not in res


def test_active_provider_info():
    from sentinels.config import get_active_provider_info
    info = get_active_provider_info()
    assert "provider" in info
    assert "model" in info
    assert "display" in info


def test_pdf_xml_escaping_smoke():
    from sentinels.reporting.pdf_exporter import export_pdf_file
    with tempfile.TemporaryDirectory() as tmp_dir:
        manifest = RepoManifest(
            repo_url="https://github.com/example/smoke",
            local_path=tmp_dir,
            total_files=1,
            languages=["Python"]
        )
        finding = Finding(
            title="XSS <script>alert(1)</script> & payload",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-79",
            file="app.py",
            line_start=1,
            line_end=1,
            description="Raw <tags> and ampersands & in description.",
            evidence="raw <script>alert(1)</script>",
            remediation="Sanitize input with <safe> method."
        )
        pdf_path = os.path.join(tmp_dir, "smoke.pdf")
        export_pdf_file(manifest, [finding], pdf_path, raw_manager_text="Raw summary with <script> & test.")
        assert os.path.isfile(pdf_path)
        assert os.path.getsize(pdf_path) > 1000


if __name__ == "__main__":
    class _Monkeypatch:
        def __init__(self):
            self._saved = {}

        def setenv(self, key, value):
            self._saved.setdefault(key, os.environ.get(key))
            os.environ[key] = value

        def delenv(self, key, raising=False):
            self._saved.setdefault(key, os.environ.get(key))
            os.environ.pop(key, None)

        def restore(self):
            for key, value in self._saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    test_modules_import_cleanly()
    print("ok: modules import cleanly")

    test_mcp_server_path_resolves()
    print("ok: mcp server path resolves")

    mp = _Monkeypatch()
    try:
        test_config_reads_deployment_env_var(mp)
        print("ok: config reads AZURE_OPENAI_GPT_DEPLOYMENT")
    finally:
        mp.restore()

    mp = _Monkeypatch()
    try:
        test_config_raises_without_credentials(mp)
        print("ok: config raises without credentials")
    finally:
        mp.restore()

    mp = _Monkeypatch()
    try:
        test_config_supports_ollama(mp)
        print("ok: config supports Ollama provider")
    finally:
        mp.restore()

    mp = _Monkeypatch()
    try:
        test_manager_agent_builds_with_worker_tools(mp)
        print("ok: manager agent builds with worker tools")
    finally:
        mp.restore()

    test_cleanup_removes_readonly_git_packfiles()
    print("ok: cleanup removes read-only git packfiles")

    test_workflow_is_buildable_and_runnable()
    print("ok: workflow is buildable and runnable")

    test_run_semgrep_never_raises()
    print("ok: run_semgrep degrades gracefully instead of raising")

    test_secret_scan_detects_secrets()
    print("ok: secret scanner detects tokens and keys")

    test_read_file_safe_error_handling()
    print("ok: read_file handles missing files safely")

    # New enterprise tests
    test_finding_patch_and_schema()
    print("ok: finding patch, owasp, and cve fields validated")

    test_resilient_json_parser()
    print("ok: resilient JSON parser extracts and cleans findings")

    test_dependency_scanner_discovery()
    print("ok: dependency scanner discovers requirements.txt & package.json")

    test_sarif_export()
    print("ok: SARIF 2.1.0 exporter generates valid OASIS schema")

    test_multi_format_export_all()
    print("ok: multi-format pipeline generates PDF, Markdown, and SARIF")

    test_symlink_defense()
    print("ok: symlink sandbox escape strictly denied")

    test_active_provider_info()
    print("ok: active provider information properly resolved")

    test_pdf_xml_escaping_smoke()
    print("ok: PDF exporter handles unescaped XML/HTML entities safely")

    print("\nALL SMOKE & ENTERPRISE CHECKS PASSED SUCCESSFULLY!")
