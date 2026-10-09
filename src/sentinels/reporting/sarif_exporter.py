# src/sentinels/reporting/sarif_exporter.py
"""
OASIS SARIF 2.1.0 Exporter for Sentinels.
Converts structured Finding objects into standard SARIF JSON format,
enabling native integration with GitHub Security Tab, GitLab, and VS Code.
"""
import json
from pathlib import Path
from typing import List
from sentinels.schemas.finding import Finding, Severity
from sentinels.schemas.manifest import RepoManifest

def _severity_to_sarif_level(severity: Severity) -> str:
    """Maps Sentinels Severity to SARIF level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    else:
        return "note"

def generate_sarif_dict(manifest: RepoManifest, findings: List[Finding]) -> dict:
    """Generates a complete SARIF 2.1.0 structure from scan results."""
    rules_dict = {}
    sarif_results = []

    for f in findings:
        rule_id = f.cwe if f.cwe and f.cwe != "CWE-Unknown" else "SENTINEL-SEC-01"
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html" if rule_id.startswith("CWE-") else "https://github.com/org/sentinels",
                "properties": {
                    "tags": ["security", "verified-by-ai"] + ([f.owasp] if f.owasp else [])
                }
            }

        res_item = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.severity),
            "message": {
                "text": f"{f.title}\n\nEvidence: {f.evidence}\n\nRemediation: {f.remediation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": max(1, f.line_start),
                            "endLine": max(1, f.line_end)
                        }
                    }
                }
            ]
        }

        # Embed Git diff patch if available
        if f.patch:
            res_item["fixes"] = [
                {
                    "description": {"text": "AI-Verified Unified Patch"},
                    "fileChanges": [
                        {
                            "artifactLocation": {"uri": f.file.replace("\\", "/")},
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": max(1, f.line_start),
                                        "endLine": max(1, f.line_end)
                                    },
                                    "insertedContent": {"text": f.patch}
                                }
                            ]
                        }
                    ]
                }
            ]

        sarif_results.append(res_item)

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinels",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/org/sentinels",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": []
                    }
                ],
                "results": sarif_results
            }
        ]
    }
    return sarif_data

def export_sarif_file(manifest: RepoManifest, findings: List[Finding], output_path: str) -> str:
    """Exports findings as a SARIF JSON file and returns the file path."""
    sarif_data = generate_sarif_dict(manifest, findings)
    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
    return str(dest.resolve())
