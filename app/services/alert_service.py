from __future__ import annotations


from app.extensions import db
from app.models.alert import SecurityAlert
from app.models.finding import Finding


def _dedupe_key(device_id: int, cve_id: str | None, severity: str, source: str) -> str:
    return f"{device_id}:{cve_id or 'manual'}:{severity}:{source}"


def create_or_update_alert(
    *,
    device_id: int,
    cve_id: str | None,
    severity: str,
    title: str,
    summary: str,
    source: str = "scan",
    alert_type: str = "cve",
    commit: bool = True,
) -> SecurityAlert:
    key = _dedupe_key(device_id, cve_id, severity, source)
    alert = SecurityAlert.query.filter_by(dedupe_key=key).first()
    if alert is None:
        alert = SecurityAlert(
            device_id=device_id,
            cve_id=cve_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            summary=summary,
            source=source,
            dedupe_key=key,
        )
        db.session.add(alert)
    else:
        alert.title = title
        alert.summary = summary
        alert.severity = severity
        alert.status = "open"
        alert.acknowledged_at = None
    if commit:
        db.session.commit()
    return alert


def create_alerts_from_findings(
    device_id: int,
    findings: list[Finding],
    *,
    commit: bool = True,
) -> list[SecurityAlert]:
    alerts: list[SecurityAlert] = []
    for finding in findings:
        score = finding.score or 0.0
        severity = (finding.severity or "medium").upper()
        title = f"{finding.cve_id} requires review" if finding.cve_id else "New assessment finding"
        summary = finding.summary or (
            "Evidence-based CVE review flagged this device for follow-up. "
            "This record is not proof of exploitation by itself."
        )
        if finding.component_name:
            summary = (
                f"{summary} Component: {finding.component_name} "
                f"({finding.component_version or 'unknown version'})."
            )
        alert = create_or_update_alert(
            device_id=device_id,
            cve_id=finding.cve_id,
            severity=severity,
            title=title,
            summary=summary,
            source="scan",
            alert_type="cve",
            commit=False,
        )
        if isinstance(score, (int, float)) and score > 0:
            alert.summary = f"{alert.summary} CVSS score: {score}."
        alerts.append(alert)
    if commit:
        db.session.commit()
    return alerts


def list_active_alerts(device_id: int | None = None) -> list[SecurityAlert]:
    query = SecurityAlert.query.filter(SecurityAlert.status != "resolved")
    if device_id is not None:
        query = query.filter_by(device_id=device_id)
    return query.order_by(SecurityAlert.created_at.desc()).all()
