from __future__ import annotations

import math


def prioritize_finding(
    severity: str | None,
    cvss_score: float | None,
    match_status: str | None,
    is_kev: bool,
) -> dict[str, str]:
    status = (match_status or "potential").strip().lower()
    if status in {"not_applicable", "not_affected"}:
        return {
            "priority": "NOT PRIORITIZED",
            "reason": (
                "Stored product/version evidence currently excludes this finding; "
                "reassess if device evidence changes."
            ),
        }

    score = (
        float(cvss_score)
        if isinstance(cvss_score, (int, float))
        and not isinstance(cvss_score, bool)
        and math.isfinite(cvss_score)
        and 0 <= cvss_score <= 10
        else None
    )
    severity_name = severity.strip().upper() if isinstance(severity, str) else ""
    if severity_name not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        severity_name = (
            "CRITICAL" if score is not None and score >= 9.0
            else "HIGH" if score is not None and score >= 7.0
            else "MEDIUM" if score is not None and score >= 4.0
            else "LOW" if score is not None
            else ""
        )

    evaluated = status == "affected"
    applicability = (
        "evaluated affected match" if evaluated else "unresolved applicability"
    )
    if is_kev:
        return {
            "priority": "CRITICAL" if evaluated else "HIGH",
            "reason": (
                f"CISA KEV lists this CVE and the device has {applicability}; "
                "prioritize remediation or applicability review."
            ),
        }

    if not severity_name:
        return {
            "priority": "REVIEW",
            "reason": (
                f"Severity data is unavailable and applicability is {applicability}; "
                "missing data is not evidence of low risk."
            ),
        }

    if evaluated:
        priority = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }[severity_name]
        reason = (
            f"{severity_name} vulnerability severity with an evaluated affected "
            "version match."
        )
    else:
        priority = {
            "CRITICAL": "HIGH",
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "LOW",
        }[severity_name]
        reason = (
            f"{severity_name} vulnerability severity, but applicability is "
            "unresolved; confirm device evidence before treating it as affected."
        )
    return {"priority": priority, "reason": reason}
