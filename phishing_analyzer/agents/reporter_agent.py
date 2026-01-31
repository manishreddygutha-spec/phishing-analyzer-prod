def build_json_report(
    email_out,
    header_out,
    content_out,
    domain_out,
    url_out,
    attachment_out,
    risk_out,
):
    """
    Build a stable, machine-readable JSON report.
    Backward-compatible with tests.
    """

    confidence = risk_out.get("confidence", "Low")

    return {
        "from": email_out.from_email,
        "domain": email_out.from_domain,
        "risk": {
            "score": risk_out["score"],
            "severity": risk_out["severity"],
            "action": risk_out["action"],
            "confidence": confidence,
        },
        "findings": {
            "headers": header_out.indicators,
            "content": content_out.indicators,
            "urls": {
                "indicators": url_out.indicators,
                "virustotal": url_out.vt_status,
            },
            "attachments": {
                "indicators": attachment_out.indicators,
                "virustotal": attachment_out.vt_status,
            },
            "domain": {
                "age_days": domain_out.age_days,
                "virustotal": domain_out.vt_status,
            },
        },
    }
