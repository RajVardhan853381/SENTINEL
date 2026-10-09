# src/sentinels/schemas/parser.py
"""
Resilient JSON Parser and Pydantic Validator for LLM Security Findings.
Guarantees clean extraction of structured `Finding` objects even when models
wrap responses in conversational text, markdown code blocks, or minor JSON syntax errors.
"""
import json
import re
from typing import List, Any, Dict
from sentinels.schemas.finding import Finding, Severity, Confidence

def _clean_json_syntax(text: str) -> str:
    """Repairs common minor JSON syntax errors made by LLMs."""
    # Remove single-line JS-style comments // ...
    text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    # Remove trailing commas in arrays/objects: [1, 2, ] -> [1, 2]
    text = re.sub(r",\s*([\]}])", r"\1", text)
    return text.strip()

def _extract_json_candidate(text: str) -> str | None:
    """Finds the most plausible JSON substring within arbitrary LLM text."""
    text = text.strip()
    # 1. Look for ```json ... ``` blocks
    fenced_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fenced_match:
        return fenced_match.group(1).strip()

    # 2. Look for balanced [ ... ] brackets
    start_bracket = text.find("[")
    end_bracket = text.rfind("]")
    if start_bracket != -1 and end_bracket > start_bracket:
        return text[start_bracket : end_bracket + 1].strip()

    # 3. Look for balanced { ... } brackets (single finding object)
    start_brace = text.find("{")
    end_brace = text.rfind("}")
    if start_brace != -1 and end_brace > start_brace:
        return text[start_brace : end_brace + 1].strip()

    return None

def _normalize_finding_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures required fields have plausible defaults if slightly malformed."""
    d = dict(item)
    # Normalize severity string
    sev_raw = str(d.get("severity", "Medium")).strip().capitalize()
    valid_sevs = {s.value: s for s in Severity}
    d["severity"] = valid_sevs.get(sev_raw, Severity.MEDIUM)

    # Normalize confidence string
    conf_raw = str(d.get("confidence", "Medium")).strip().capitalize()
    valid_confs = {c.value: c for c in Confidence}
    d["confidence"] = valid_confs.get(conf_raw, Confidence.MEDIUM)

    # Ensure strings and integers are present
    d["title"] = str(d.get("title", "Unspecified Security Finding"))
    d["cwe"] = str(d.get("cwe", "CWE-Unknown"))
    d["file"] = str(d.get("file", "unknown_file"))
    
    raw_start = d.get("line_start") if d.get("line_start") is not None else (d.get("line") or 1)
    try:
        d["line_start"] = int(raw_start)
    except (ValueError, TypeError):
        d["line_start"] = 1

    raw_end = d.get("line_end") if d.get("line_end") is not None else (d.get("line") or d["line_start"])
    try:
        d["line_end"] = int(raw_end)
    except (ValueError, TypeError):
        d["line_end"] = d["line_start"]

    d["evidence"] = str(d.get("evidence", ""))
    d["description"] = str(d.get("description", ""))
    d["remediation"] = str(d.get("remediation", ""))
    
    # Optional fields
    if "patch" in d and d["patch"]:
        d["patch"] = str(d["patch"])
    if "owasp" in d and d["owasp"]:
        d["owasp"] = str(d["owasp"])
    if "cve" in d and d["cve"]:
        d["cve"] = str(d["cve"])
    if "package_name" in d and d["package_name"]:
        d["package_name"] = str(d["package_name"])
    if "fixed_version" in d and d["fixed_version"]:
        d["fixed_version"] = str(d["fixed_version"])

    return d

def extract_findings_resilient(raw_text: str) -> List[Finding]:
    """
    Extracts and validates a list of `Finding` models from arbitrary LLM text.
    Returns an empty list `[]` if no valid findings are present.
    """
    if not raw_text or not raw_text.strip():
        return []

    candidate = _extract_json_candidate(raw_text)
    if not candidate:
        return []

    cleaned = _clean_json_syntax(candidate)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: try raw candidate before cleaning
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            return []

    if isinstance(data, dict):
        # Could be {"findings": [...]} or a single finding {...}
        if "findings" in data and isinstance(data["findings"], list):
            items = data["findings"]
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        return []

    findings: List[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            norm_item = _normalize_finding_dict(item)
            finding = Finding.model_validate(norm_item)
            findings.append(finding)
        except Exception:
            continue

    return findings
