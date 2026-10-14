from __future__ import annotations


def compute_risk_status(findings) -> str:
    if not findings:
        return "No known matches found in the data sources checked at this time."
    severities = [finding.severity.lower() for finding in findings]
    if any(item in severities for item in ["critical", "high"]):
        return "Action required"
    if any(item == "medium" for item in severities):
        return "Monitor"
    return "Low risk"
