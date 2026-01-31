# ==============================
# Streamlit App – Phishing Analyzer
# ==============================

from dotenv import load_dotenv
load_dotenv()  # ✅ Load VT_API_KEY

import os
import tempfile
import streamlit as st

from phishing_analyzer.orchestration.prefect_flow import phishing_flow
import phishing_analyzer.logging_config
# ------------------------------
# MUST be first Streamlit call
# ------------------------------
st.set_page_config(
    page_title="Phishing Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ------------------------------
# Session State Defaults
# ------------------------------
for k, v in {
    "analysis_done": False,
    "last_result": None,
    "uploaded_file": None,
    "demo_mode": True,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ------------------------------
# Sidebar
# ------------------------------
st.sidebar.title("⚙️ Configuration")

vt_loaded = bool(os.getenv("VT_API_KEY"))
st.sidebar.write(
    f"VirusTotal API key loaded: {'YES' if vt_loaded else 'NO'}"
)

st.sidebar.checkbox(
    "Demo Mode (use sample emails)",
    key="demo_mode",
)

st.sidebar.markdown("---")
st.sidebar.info("Close browser tab + stop terminal to exit.")

# ------------------------------
# Header
# ------------------------------
st.title("📧 Phishing Email Analyzer")
st.caption("Static + reputation-based phishing detection")

# ------------------------------
# Reset Helper
# ------------------------------
def reset_app():
    for k in ["analysis_done", "last_result", "uploaded_file"]:
        st.session_state[k] = None
    st.session_state.analysis_done = False
    st.experimental_rerun()

# ------------------------------
# Upload / Select Email
# ------------------------------
if not st.session_state.analysis_done:

    st.subheader("📤 Select an email (.eml)")

    uploaded = st.file_uploader(
        "Upload an email file",
        type=["eml"],
        key="eml_uploader",
    )

    if uploaded:
        st.session_state.uploaded_file = uploaded

    if st.button(
        "🔍 Analyze Email",
        disabled=st.session_state.uploaded_file is None,
        key="analyze_button",
    ):
        with st.spinner("Analyzing email..."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                tmp.write(st.session_state.uploaded_file.read())
                eml_path = tmp.name

            flow_result = phishing_flow(eml_path)

            try:
                os.unlink(eml_path)
            except Exception:
                pass

            st.session_state.last_result = flow_result
            st.session_state.analysis_done = True
            st.experimental_rerun()

# ------------------------------
# Results View
# ------------------------------
else:
    raw_result = st.session_state.last_result

    # ✅ SAFE extraction of actual report
    if isinstance(raw_result, dict) and "report_json" in raw_result:
        result = raw_result["report_json"]
    else:
        result = raw_result

    st.success("✅ Analysis complete")

    # ------------------------------
    # Sender Info
    # ------------------------------
    st.subheader("🧾 Sender Information")

    from_email = result.get("from_email") or result.get("from") or "Unknown"
    from_domain = result.get("from_domain") or result.get("domain") or "Unknown"

    st.write(f"**From:** {from_email}")
    st.write(f"**Sender Domain:** {from_domain}")

    # ------------------------------
    # Risk Summary (SAFE)
    # ------------------------------
    risk = result.get("risk", {})

    cols = st.columns(3)
    cols[0].metric("Risk Score", f"{risk.get('score', 0)} / 100")
    cols[1].metric("Severity", risk.get("severity", "Unknown"))
    cols[2].metric("Recommended Action", risk.get("action", "Unknown"))

    # ------------------------------
    # Verdict Explanation
    # ------------------------------
    st.subheader("✅ Final Verdict")

    if risk.get("action") == "Allow":
        st.write(
            "This email appears **legitimate** based on:\n\n"
            "- Trusted sender domain\n"
            "- No malicious URLs or attachments\n"
            "- No phishing content detected"
        )
    else:
        st.warning("This email shows **risk indicators**.")

    # ------------------------------
    # Findings
    # ------------------------------
    findings = result.get("findings", {})

    with st.expander("🔐 Headers"):
        st.write(findings.get("headers") or "No header anomalies detected.")

    with st.expander("🔗 URLs"):
        urls = findings.get("urls", {})
        st.write(urls.get("indicators") or "No suspicious URLs detected.")
        st.write(f"VirusTotal (URLs): {urls.get('virustotal', 'N/A')}")

    with st.expander("📎 Attachments"):
        atts = findings.get("attachments", {})
        st.write(atts.get("indicators") or "No attachments detected.")
        st.write(f"VirusTotal (Attachments): {atts.get('virustotal', 'N/A')}")

    with st.expander("🌐 Domain Reputation"):
        dom = findings.get("domain", {})
        age = dom.get("age_days")
        st.write(f"Domain age: {age} days" if age is not None else "Domain age: Unknown")
        st.write(f"VirusTotal (Domain): {dom.get('virustotal', 'N/A')}")

    # ------------------------------
    # Raw JSON
    # ------------------------------
    with st.expander("🧾 Raw JSON Report"):
        st.json(result)

    # ------------------------------
    # Analyze Another Email
    # ------------------------------
    st.markdown("---")
    if st.button("🔁 Analyze another email", key="analyze_another"):
        reset_app()
