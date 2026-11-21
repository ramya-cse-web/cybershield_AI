import re
from urllib.parse import urlparse
import streamlit as st

st.set_page_config(page_title="CyberShield AI Agent", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main {background:#f7fafc}
.hero {background:#10283d;color:white;padding:24px;border-radius:14px}
.small {color:#526273}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ CyberShield – AI Cybersecurity Agent</h1><p>Defensive security awareness • Threat review • Safe next steps</p></div>', unsafe_allow_html=True)
st.caption("Educational demo. This tool checks text patterns only; it does not confirm whether a website, email, or device is safe.")

tab1, tab2, tab3 = st.tabs(["🔗 URL Checker", "✉️ Message Checker", "📋 Log Review"])

def result(level, title, reasons, advice):
    color = {"High":"#b42318", "Medium":"#b54708", "Low":"#067647"}.get(level, "#344054")
    st.markdown(f"### <span style='color:{color}'>{level} risk: {title}</span>", unsafe_allow_html=True)
    if reasons:
        st.write("**Indicators found**")
        for x in reasons: st.write("• " + x)
    st.write("**Recommended next steps**")
    for x in advice: st.write("• " + x)

with tab1:
    st.subheader("Suspicious URL review")
    url = st.text_input("Paste a URL (do not open it)", placeholder="https://example.com")
    if st.button("Analyse URL", key="url"):
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            raw = url.strip()
            candidate = raw if "://" in raw else "https://" + raw
            p = urlparse(candidate)
            host = (p.hostname or "").lower()
            reasons=[]
            if not host: reasons.append("The address could not be parsed.")
            if p.scheme != "https": reasons.append("The URL does not use HTTPS.")
            if re.search(r'\\d{1,3}(?:\\.\\d{1,3}){3}', host): reasons.append("The host is an IP address rather than a familiar domain.")
            if "xn--" in host: reasons.append("The domain contains punycode, which can disguise lookalike characters.")
            if len(raw) > 100: reasons.append("The URL is unusually long.")
            if "@" in p.netloc: reasons.append("The URL contains an @ sign in its network location.")
            if any(k in raw.lower() for k in ["login", "verify", "password", "secure", "wallet"]):
                reasons.append("The URL contains words commonly used in account-verification lures.")
            level = "High" if len(reasons)>=3 else "Medium" if reasons else "Low"
            result(level, "Review required" if reasons else "No obvious pattern detected", reasons,
                   ["Do not enter passwords or payment details from an unexpected link.",
                    "Open the organisation's official app or type its known address yourself.",
                    "A low-risk result is not proof that the site is safe."])

with tab2:
    st.subheader("Email / message review")
    msg = st.text_area("Paste message text (remove private details first)", height=180)
    if st.button("Analyse Message", key="msg"):
        if not msg.strip():
            st.warning("Paste a message first.")
        else:
            t=msg.lower(); reasons=[]
            patterns = [
                (r"urgent|immediately|act now|within 24 hours", "Uses urgency or pressure."),
                (r"password|otp|one.?time password|verification code", "Requests or mentions sensitive login codes."),
                (r"bank|account|payment|refund|prize|lottery", "Mentions money or account access."),
                (r"click here|open the link|download attachment", "Encourages clicking a link or opening an attachment."),
                (r"gift card|crypto|bitcoin", "Mentions payment methods often abused in scams.")
            ]
            for pat, label in patterns:
                if re.search(pat,t): reasons.append(label)
            level = "High" if len(reasons)>=3 else "Medium" if reasons else "Low"
            result(level, "Possible phishing indicators" if reasons else "No common indicators detected", reasons,
                   ["Verify the sender using a separate trusted contact method.",
                    "Never share passwords, OTPs, or recovery codes.",
                    "Do not open unexpected attachments or links."])

with tab3:
    st.subheader("Basic system-log review")
    logs = st.text_area("Paste selected log lines (remove IPs/usernames if sensitive)", height=180,
                        placeholder="Failed login for user...\nLogin failed...")
    if st.button("Review Logs", key="logs"):
        if not logs.strip():
            st.warning("Paste log lines first.")
        else:
            lines=logs.splitlines()
            failed=sum(bool(re.search(r"fail|denied|invalid password|authentication error",x,re.I)) for x in lines)
            unusual=sum(bool(re.search(r"unknown|unexpected|outside|unusual|blocked",x,re.I)) for x in lines)
            reasons=[]
            if failed>=5: reasons.append(f"{failed} lines contain failed/denied authentication wording.")
            elif failed: reasons.append(f"{failed} line(s) contain failed/denied authentication wording.")
            if unusual: reasons.append(f"{unusual} line(s) contain unusual/unknown/blocked wording.")
            level="High" if failed>=5 else "Medium" if reasons else "Low"
            result(level, "Log review summary", reasons,
                   ["Check whether the events match an approved user activity.",
                    "Ask an administrator to review repeated failures and timestamps.",
                    "Preserve relevant logs according to your organisation's policy."])

st.divider()
st.markdown("**Project modules:** Input Management • Pre-processing • URL & Phishing Analysis • Log Monitoring • Risk Explanation • Report Guidance")
st.caption("CyberShield is a student decision-support demo. Results are heuristic and must be verified by a qualified administrator.")
