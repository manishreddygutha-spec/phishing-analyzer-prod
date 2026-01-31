from phishing_analyzer.agents.ingestion import EmailIngestionAgent
from phishing_analyzer.agents.content_agent import ContentAnalyzerAgent
from phishing_analyzer.agents.domain_agent import DomainAgent
from phishing_analyzer.agents.url_agent import URLAnalyzerAgent
from phishing_analyzer.agents.attachment_agent import AttachmentAnalyzerAgent
from phishing_analyzer.agents.risk_agent import RiskAgent, RiskConfig
from phishing_analyzer.agents.reporter_agent import build_json_report
from phishing_analyzer.tools.url_tool import URLTool
from phishing_analyzer.tools.attachment_tool import AttachmentTool
from phishing_analyzer.tools.virustotal_tool import VirusTotalTool


def phishing_flow(eml_path: str, demo_mode: bool = False):
    """
    Orchestrates full phishing analysis pipeline.

    demo_mode:
      - False → production-safe conservative thresholds
      - True  → aggressive thresholds for demo / visualization
    """

    # -----------------------------
    # Ingest email
    # -----------------------------
    email_out = EmailIngestionAgent().parse(eml_path)

    # -----------------------------
    # Run analyzers
    # -----------------------------
    content_out = ContentAnalyzerAgent().run(email_out)

    domain_out = DomainAgent().run(
        whois_tool=None,
        vt_tool=VirusTotalTool(),
        domain=email_out.from_domain,
        recent_days=30,
    )

    url_out = URLAnalyzerAgent().run(
        email_out.urls,
        URLTool(),
        VirusTotalTool(),
    )

    attachment_out = AttachmentAnalyzerAgent().run(
        email_out.attachments,
        AttachmentTool(),
        VirusTotalTool(),
    )

    # -----------------------------
    # Risk configuration
    # -----------------------------
    if demo_mode:
        # Aggressive demo thresholds (visual clarity)
        risk_cfg = RiskConfig(
            quarantine_threshold=40,
            flag_threshold=20,
        )
    else:
        # Production-safe defaults
        risk_cfg = RiskConfig()

    risk_out = RiskAgent().run(
        header=content_out,   # headers folded into content agent in this design
        content=content_out,
        domain=domain_out,
        url=url_out,
        attachment=attachment_out,
        config=risk_cfg,
    )

    # -----------------------------
    # Build reports
    # -----------------------------
    report_json = build_json_report(
        email_out,
        content_out,
        content_out,
        domain_out,
        url_out,
        attachment_out,
        risk_out,
    )

    return {
        "report_json": report_json,
    }
