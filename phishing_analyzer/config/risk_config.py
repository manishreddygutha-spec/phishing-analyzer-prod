from dataclasses import dataclass

@dataclass
class RiskConfig:
    w_header: float = 0.20
    w_content: float = 0.20
    w_domain: float = 0.15
    w_auth: float = 0.15
    w_url: float = 0.10
    w_attachment: float = 0.10

    block_threshold: int = 85
    quarantine_threshold: int = 70
    flag_threshold: int = 50

    recent_domain_days: int = 30
