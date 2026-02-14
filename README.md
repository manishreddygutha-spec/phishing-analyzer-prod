# 🛡️ Production-Ready Multi-Agent AI Phishing Detection System

[![Title](images/title.png)](images/title.png)

Phishing emails remain one of the most common and damaging cybersecurity threats faced by organizations today. Security teams must analyze suspicious emails quickly while ensuring legitimate communication is not incorrectly blocked. This requires detection systems that are accurate, reliable, and transparent.

This project presents a production-ready multi-agent AI phishing detection system designed to simulate real-world enterprise email security workflows. The system analyzes raw .eml email files using a coordinated set of specialized agents that perform header analysis, content inspection, domain intelligence, attachment scanning, and structured risk scoring.

Unlike experimental prototypes, this production-focused implementation emphasizes reliability, monitoring, resilience, and maintainability. It demonstrates how agentic AI systems can be deployed with proper guardrails, logging, testing, and failure handling to meet professional software standards.

The goal of this project is to demonstrate how agentic AI systems can be deployed safely in production environments with clear decision logic, monitoring, and built-in safety guardrails.
---
## 🌍 Real-World Cybersecurity Impact

This system demonstrates how multi-agent AI can improve phishing detection in real-world security environments. It enables security teams to automatically analyze suspicious emails, reduce manual investigation time, and generate structured phishing risk scores with recommended actions.

The architecture reflects how modern Security Operations Centers (SOC) combine automated detection, structured validation, and monitoring to prevent phishing attacks safely while maintaining operational efficiency.

---
## 🏗 Production-Oriented Design

This production version focuses on reliability and maintainability rather than experimentation. The system includes structured logging, guardrails, testing, and graceful fallback mechanisms to ensure predictable behavior even when external tools fail.

Each agent performs a clearly defined task and contributes to a deterministic final risk score, making the system easier to audit, debug, and extend. The modular architecture allows independent updates and supports deployment in real-world security workflows.

---

## ✨ Key Highlights

- 📧 Analyze raw `.eml` email files  
- 🤖 Multi-Agent architecture (Header, Content, URL, Domain, Attachment)  
- 🔗 SOC-style **cross-agent correlation**  
- 📊 Deterministic **risk scoring (0–100)**  
- 🚨 Final actions: **Allow / Flag / Quarantine**  
- 🧪 Demo mode with phishing samples  
- 🧠 Real credential-phishing detection  
- 🖥️ Interactive **Streamlit UI**  
- 🧪 70%+ test coverage with pytest  

---

## 🧠 System Architecture

The system processes emails using **independent detection agents**, then correlates their findings using SOC-style logic.

[![Architecture](images/architecture.png)](images/architecture.png)

---

## 📂 Project Structure

```text
phishing-analyzer-prod/
│
├── __init__.py
├── logging_config.py            # Centralized production logging configuration
├── health.py                    # System health check & monitoring utility
│
├── app/
│   └── app.py                   # Streamlit UI for interactive phishing analysis
│
├── phishing_analyzer/
│   ├── agents/                  # Core multi-agent detection system
│   │   ├── ingestion.py         # Email ingestion agent
│   │   ├── header_agent.py      # Header analysis agent
│   │   ├── content_agent.py     # Email content analysis agent
│   │   ├── url_agent.py         # URL analysis agent
│   │   ├── domain_agent.py      # Domain intelligence agent
│   │   ├── attachment_agent.py  # Attachment analysis agent
│   │   ├── risk_agent.py        # Risk scoring & decision agent
│   │   └── reporter_agent.py    # Final report generation agent
│   │
│   ├── orchestration/
│   │   └── prefect_flow.py      # Prefect workflow orchestration
│   │
│   ├── tools/                   # External analysis tools
│   │   ├── url_tool.py
│   │   ├── attachment_tool.py
│   │   └── virustotal_tool.py
│   │
│   ├── config/
│   │   └── risk_config.py       # Risk scoring configuration
│   │
│   ├── safety/
│   │   └── guardrails.py        # Input validation & safety guardrails
│   │
│   └── utils/
│       ├── error_handler.py     # Standardized error handling wrapper
│       └── resilience.py        # Retry, timeout & resilience utilities
│
├── samples/                     # Sample phishing & legitimate emails
│   ├── dhl_delivery_failure_phish.eml
│   ├── microsoft_password_reset_phish.eml
│   ├── Updates to how privacy settings work on Play.eml
│   └── Help shape Advent of Cyber 2026.eml
│
├── images/
│   ├── architecture.png
│   └── title.png
│
├── tests/                       # Testing suite
│   └── unit/                    # Unit tests for agents & tools
│
├── .env                         # Environment variables (not committed)
├── requirements.txt
├── pyproject.toml
└── README.md

```

---

## 🔁 Analysis Flow

1. Raw `.eml` email is ingested
2. Email is parsed into structured components
3. Each agent analyzes its own signal independently
4. Agents return **risk scores + indicators**
5. Risk Agent applies **cross-agent correlation**
6. Final decision is produced:
   - Score
   - Severity
   - Action
   - Confidence

No agent can directly allow or block an email on its own.
---

## 🧩 Agents Overview

### 📥 Ingestion Agent
- Parses `.eml` files
- Extracts:
  - Email body
  - URLs
  - Attachments
  - Sender & domain

---

### 🧾 Header Agent
- Detects:
  - Brand impersonation
  - Sender spoofing indicators
- Adds risk for suspicious headers

---

### 🧠 Content Agent
- Detects **credential phishing**
- Looks for:
  - Password reset language
  - Urgency & coercion
  - Brand impersonation keywords
- Assigns **real, non-zero phishing risk**

---

### 🔗 URL Agent
- Detects:
  - Malformed / obfuscated URLs
  - URL shorteners
  - Suspicious URL keywords
- Works even without VirusTotal
- Adds meaningful risk in demo mode

---

### 🌐 Domain Agent
- Checks:
  - Domain age (WHOIS)
  - Recently registered domains
- **Correlation triggers even when domain age is unknown**
- Optional VirusTotal reputation lookup

---

### 📎 Attachment Agent
- Flags risky attachment types
- Optional hash-based VirusTotal lookup

---

### ⚠️ Risk Agent (Core Intelligence)

- Aggregates all agent risks
- Applies **SOC-style correlation**, for example:
  - Content phishing + URL → boosted risk
  - Content phishing + attachment → boosted risk
- Produces:
  - Final score
  - Severity
  - Action
  - Confidence

---

## 📊 Risk Thresholds

| Score Range | Severity | Action     |
|------------|----------|------------|
| 0–49       | Info     | Allow      |
| 50–69      | Medium   | Flag       |
| 70–100     | High     | Quarantine |

---
## ⚙️ Prerequisites

- Python 3.11+
- pip package manager
- Internet connection (for DNS & WHOIS lookups)
- Optional: CrewAI for explanation agent

---

## 🧪 Demo Mode vs Real-World Mode

### Demo Mode (Default)
- VirusTotal optional
- Uses heuristic and structural analysis
- Safe for classrooms, demos, GitHub, interviews
- Still produces **real phishing decisions**

### Real-World Mode
- Enable VirusTotal via `VT_API_KEY`
- Adds reputation-based confirmation
- Same scoring and correlation logic
- No logic changes required
---


## 🧪 Sample Output (High-Risk Phishing)

### 📄 `dhl_delivery_failure_phish.eml`

```json
{
  "from": "DHL Express <noreply@dhl-track-support.com>",
  "domain": "dhl-track-support.com",
  "risk": {
    "score": 90,
    "severity": "High",
    "action": "Quarantine",
    "confidence": "High"
  },
  "findings": {
    "headers": [
      "Brand impersonation detected: dhl"
    ],
    "content": [
      "Brand impersonation detected: dhl"
    ],
    "urls": {
      "indicators": [
        "Malformed URL detected"
      ],
      "virustotal": "not_configured"
    },
    "attachments": {
      "indicators": [],
      "virustotal": "not_configured"
    },
    "domain": {
      "age_days": null,
      "virustotal": "enabled"
    }
  }
}
``````
---

## 🐍 Python Virtual Environment Setup

### 1️⃣ Create virtual environment

```bash
python -m venv venv
```

### 2️⃣ Activate virtual environment

#### Windows

```bash
venv\Scripts\activate
```

#### macOS / Linux

```bash
source venv/bin/activate
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Application

```bash
streamlit run app/app.py
```

Upload a .eml file and view the phishing analysis.
---

## 🧪 Testing Strategy

This project includes a comprehensive testing suite to ensure production reliability and safe multi-agent behavior.

### Unit Tests
Validate individual agents and tools:
- Email ingestion agent
- Header and content analysis agents
- URL and domain intelligence agents
- Attachment analysis
- Risk scoring and reporting

### Integration-Level Testing
Several tests simulate real workflow paths across multiple components:
- Domain + VirusTotal lookup flows
- URL analysis pipelines
- Agent-to-tool interactions
- Error and fallback scenarios

These tests ensure agents and tools work together correctly under realistic conditions.

### End-to-End Workflow Validation
The system can be tested end-to-end using provided `.eml` samples through:
- Streamlit UI
- Prefect orchestration flow

```bash
pytest --cov=phishing_analyzer
```
✔ Minimum 70% test coverage enforced

The testing suite ensures stability, reliability, and safe production-style behavior.
---
## 🧰 Troubleshooting

**CrewAI explanation not generated**  
→ CrewAI not installed. Install or run deterministic mode.

**DNS/WHOIS lookup failure**  
→ Check internet connectivity.

**Timeout during execution**  
→ Retry execution; timeout handling is built-in.

**Dependency errors**  
```bash
pip install -r requirements.txt
pip install -e .
```
---
## 🛠 Resilience & Reliability

The system is designed to fail safely:

- Retry logic with exponential backoff for external tools
- Timeouts to prevent stuck workflows
- Graceful degradation when VirusTotal is unavailable
- No silent failures — errors are logged and surfaced
- Deterministic behavior even when signals are missing

This ensures consistent behavior in real SOC environments.
---
## 🛡 Error Handling

The system includes structured error handling to ensure stable execution across all agents and external tool integrations.

- Graceful fallback when optional external services fail
- Safe handling of malformed email inputs or invalid URLs
- Timeout-aware execution to prevent stalled workflows
- Structured logging of errors for debugging and traceability
- Continued processing wherever possible to avoid full pipeline failure

These mechanisms ensure the system behaves predictably and avoids silent failures in production-like environments. 

---

## 📋 Logging & Observability

- Centralized logging configuration
- Clear logs for agent decisions and external tool failures
- Structured logging for debugging, traceability, and auditing
- Prevents silent workflow failures
- Built-in system health check for runtime readiness verification

---

## 🔒 Security & Safety Guardrails

- `.eml` files are parsed safely (no execution)
- Attachments are never opened or executed
- External API calls are isolated and optional
- Input validation and sanitization enforced
- No destructive actions performed on user systems

This project includes built-in safety mechanisms to ensure robustness, secure handling of untrusted email content, and fail-safe behavior under errors.

### 🧹 Input Sanitization & Content Safety
All user-supplied and email-derived text is sanitized before analysis or UI rendering:

- Removes embedded <script> and <style> blocks
- Strips all remaining HTML tags
- Decodes HTML entities
- Normalizes whitespace

This prevents:

- XSS risks in the Streamlit UI
- Malicious HTML or JavaScript execution
- Parser confusion from malformed markup

---

## 🧱 Graceful Degradation

The system is designed to continue operating even when optional components fail:
- VirusTotal unavailable → system falls back to heuristic analysis
- WHOIS lookup fails → correlation still triggers
- Individual agent failure → overall pipeline continues
No single failure causes the system to crash or silently skip analysis, ensuring consistent behavior in production-like environments.

---

## 🔎 Deterministic & Auditable Decisions

- No opaque ML decisions in the core pipeline
- Every risk increase is traceable to:
  - A specific agent
  - A specific indicator
  - Or an explicit correlation rule
- Final decisions are explainable and auditable

---

## ⚠️ Known Limitations

- Rule-based and heuristic driven (no ML model yet)
- Free VirusTotal API limits apply
- No attachment sandbox execution
- Designed for analysis and decisioning, not auto-remediation
---

## 🚀 Future Enhancements

- ML-based phishing classifier
- Attachment sandboxing
- SIEM / SOAR integration
- Batch email ingestion

---
## 🛠 Maintenance & Support Status

This project is an actively maintained production-style prototype developed as part of the ReadyTensor Agentic AI in Production program.

Maintenance scope:
- Compatible with Python 3.11+
- Regular dependency and security updates when required
- Modular architecture allows easy extension and updates

Support:
This repository is maintained for educational and production experimentation purposes.  
Issues and improvements can be reported via GitHub Issues.

---
## 📜 License

This project is released under the MIT License.

You are free to use, modify, and distribute this software for educational and commercial purposes with proper attribution.

---
## 🏁 Conclusion

This project demonstrates how a production-ready multi-agent AI system can be designed for real-world phishing detection using deterministic analysis, structured risk scoring, and modular orchestration. By combining reliability-focused engineering practices such as guardrails, logging, testing, and resilience mechanisms, the system reflects how modern security tools are built for safe and predictable operation.

The architecture highlights how agentic AI can be deployed responsibly in cybersecurity environments, supporting faster and more consistent decision-making while maintaining transparency and control. This implementation serves as a practical foundation for building scalable and trustworthy AI-driven security solutions.
