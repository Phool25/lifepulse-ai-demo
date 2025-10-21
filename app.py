import streamlit as st
import pandas as pd
import shortuuid
import hashlib
from datetime import datetime, timedelta

# =========================
# BRANDING / THEME
# =========================
BRAND_NAME = "LifePulse AI"
# Change this to your hosted logo image if you want:
LOGO_URL = "https://raw.githubusercontent.com/enchantedlabs/assets/main/lifepulse_logo_blue.png"  # fallback works even if it 404s
PRIMARY = "#2563eb"   # blue
ACCENT = "#10b981"    # green
DANGER = "#ef4444"    # red
MUTED = "#6b7280"     # gray

st.set_page_config(page_title=f"{BRAND_NAME} – Demo", layout="wide")

# Minimal CSS polish
st.markdown(f"""
<style>
/* top banner */
.banner {{
  width: 100%;
  padding: 18px 22px;
  border-radius: 14px;
  background: linear-gradient(90deg, {PRIMARY} 0%, #60a5fa 100%);
  color: white;
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 14px;
}}
.banner img {{
  width: 38px; height: 38px; object-fit: contain; filter: drop-shadow(0 1px 2px rgba(0,0,0,.25));
}}
.banner h1 {{
  font-size: 22px; line-height: 1.2; margin: 0;
}}
.sub {{
  font-size: 13px; opacity: 0.95; margin-top: 2px;
}}
.card {{
  border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; background: #fff;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}}
.metric {{
  font-size: 13px; color: {MUTED}; margin-bottom: 6px;
}}
.metric strong {{
  font-size: 18px; color: #111827;
}}
.badge {{
  display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 600;
  border: 1px solid #e5e7eb; color: #111827; background:#f9fafb;
}}
.badge.green {{ border-color: {ACCENT}; color: {ACCENT}; }}
.badge.amber {{ border-color: #f59e0b; color: #b45309; }}
.badge.red   {{ border-color: {DANGER}; color: {DANGER}; }}
.small {{ color: {MUTED}; font-size: 12px; }}
</style>
""", unsafe_allow_html=True)

st.markdown(
    f"""
<div class="banner">
  <img src="{LOGO_URL}" onerror="this.style.display='none'"/>
  <div>
    <h1>{BRAND_NAME} – Digital Health Passport</h1>
    <div class="sub">Early Detection • Digital Records • Remote Access • Safe Prescriptions</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# =========================
# IN-MEMORY DEMO "DB"
# =========================
if "users" not in st.session_state:
    st.session_state["users"] = {}  # email -> {name, role, password_hash, cnic, dob, subscribed}
if "patients" not in st.session_state:
    st.session_state["patients"] = {}  # token -> {name, cnic, dob, report(df), alerts, metrics, risk_label}
if "doctor_notes" not in st.session_state:
    st.session_state["doctor_notes"] = {}  # token -> list of notes
if "prescriptions" not in st.session_state:
    st.session_state["prescriptions"] = {}  # token -> {"meds":[...], "code": "RXCODE"}
if "audit" not in st.session_state:
    st.session_state["audit"] = []  # list of events
if "chat_history" not in st.session_state:
    st.session_state["chat_history"] = {}  # user_email -> list of (role,msg,time)
if "sos_outbox" not in st.session_state:
    st.session_state["sos_outbox"] = []  # simulated emergency notifications

# =========================
# HELPERS
# =========================
def hash_password(pw: str) -> str:
    import hashlib as _h
    return _h.sha256(pw.encode()).hexdigest()

def create_user(email, name, password, role="patient", cnic="", dob=""):
    st.session_state["users"][email] = {
        "name": name, "role": role, "password_hash": hash_password(password),
        "cnic": cnic, "dob": dob, "subscribed": False
    }

def check_login(email, password):
    u = st.session_state["users"].get(email)
    if not u: return False
    return u["password_hash"] == hash_password(password)

def gen_token():
    return shortuuid.uuid()[:8]

def log_event(actor, action, target="", extra=""):
    st.session_state["audit"].append({
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "actor": actor or "anonymous", "action": action, "target": target, "extra": extra
    })

# ------------------ Simple AI Simulation ------------------
def analyze_report(df: pd.DataFrame):
    alerts = []
    metrics = {"glucose": None, "chol": None, "hgb": None, "wbc": None}
    for _, row in df.iterrows():
        test = str(row["Test"]).strip()
        val = float(row["Result"])
        if test.lower().startswith("glucose"):
            metrics["glucose"] = val
            if val >= 126:
                alerts.append("⚠️ High glucose → Possible Diabetes Risk")
        if test.lower().startswith("chol"):
            metrics["chol"] = val
            if val >= 200:
                alerts.append("⚠️ High cholesterol → Cardiovascular risk")
        if test.lower().startswith("hemoglobin") or test.lower().startswith("hgb"):
            metrics["hgb"] = val
            if val < 11:
                alerts.append("⚠️ Low hemoglobin → Possible Anemia Risk")
        if test.lower().startswith("wbc"):
            metrics["wbc"] = val
            if val > 20000:
                alerts.append("🚨 Abnormal WBC → Early malignant process possible (Cancer risk). Urgent referral.")
    if not alerts:
        alerts.append("✅ Report looks normal. No critical risks found (demo).")
    score = sum([1 for a in alerts if "⚠️" in a or "🚨" in a])
    label = "Low" if score == 0 else ("Moderate" if score == 1 else "High")
    return alerts, metrics, label

def fake_ai_chat(message):
    m = message.lower()
    if "cancer" in m or "wbc" in m:
        return "High WBC can be serious. This demo flagged a cancer risk pattern — please consult a specialist urgently."
    if "diabetes" in m or "sugar" in m or "glucose" in m:
        return "Elevated glucose suggests diabetes risk. Track fasting levels and consult your physician."
    if "hello" in m or "hi" in m:
        return "Hello! I'm your LifePulse AI demo assistant. You can upload a report or ask about your lab tests."
    return "Demo reply: In production, this will connect to Gemini/GPT/Claude/Llama for detailed, secure answers."

def fire_sos(patient_name, patient_token, reason, notify_to="Patient + Emergency Contact"):
    """Simulate SOS: push a record into outbox and show urgent alert."""
    msg = {
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "patient": patient_name,
        "token": patient_token,
        "reason": reason,
        "notified": notify_to,
        "status": "SENT (demo)"
    }
    st.session_state["sos_outbox"].append(msg)
    st.error(f"🚨 EMERGENCY ALERT — {patient_name}: {reason}\n\nSimulated notification sent to: {notify_to}")
    log_event("system", "sos_alert", target=patient_token, extra=reason)

# =========================
# PRELOAD DEMO PATIENTS
# =========================
def preload_demo():
    if "demo_loaded" in st.session_state: return
    create_user("demo@lifepulse.test", "Demo Patient", "demo123", role="patient", cnic="12345-6789012-3", dob="1985-01-01")

    def make_df(glu, chol, hgb, wbc):
        return pd.DataFrame([
            {"Test":"Glucose","Result":glu,"Unit":"mg/dL","Reference_Range":"70-110"},
            {"Test":"Cholesterol","Result":chol,"Unit":"mg/dL","Reference_Range":"<200"},
            {"Test":"Hemoglobin","Result":hgb,"Unit":"g/dL","Reference_Range":"13-17"},
            {"Test":"WBC","Result":wbc,"Unit":"cells/µL","Reference_Range":"4000-11000"},
        ])

    demo_set = [
        ("Ali Khan",   "demo-cnic", "1990-01-01", make_df(95, 170, 14.5, 6000)),    # healthy
        ("Sara Ahmed", "demo-cnic", "1988-02-10", make_df(155, 220, 13.2, 7200)),   # diabetes risk
        ("Fatima Noor","demo-cnic", "1995-10-05", make_df(98, 180, 9.5, 6500)),     # anemia risk
        ("Bilal Hussain","demo-cnic","1970-07-21", make_df(102, 185, 13.8, 28000)), # cancer risk
    ]

    for name, cnic, dob, df in demo_set:
        token = gen_token()
        alerts, metrics, label = analyze_report(df)
        st.session_state["patients"][token] = {
            "name": name, "cnic": cnic, "dob": dob, "report": df,
            "alerts": alerts, "metrics": metrics, "risk_label": label
        }
        # auto-create a prescription "code" equal to token (simple)
        st.session_state["prescriptions"][token] = {
            "meds":[{"name":"Metformin","dose":"500mg","qty":30}],
            "code": token
        }
        # auto SOS for high risk cancer-like pattern
        if any("🚨" in a for a in alerts):
            fire_sos(name, token, "Cancer risk pattern flagged (WBC)")

    st.session_state["demo_loaded"] = True

preload_demo()

# =========================
# SIDEBAR: NAV + AUTH
# =========================
st.sidebar.title("Navigation")
if "current_user" in st.session_state:
    user_email = st.session_state["current_user"]
    u = st.session_state["users"][user_email]
    st.sidebar.write(f"Signed in: **{u['name']}** ({u['role']})")
else:
    user_email = None
    st.sidebar.write("Not signed in")

page = st.sidebar.radio(
    "Menu",
    ["Home","Patient Dashboard","Upload Report","Doctor Portal","Pharmacy","Chat AI","Admin / Audit"]
)

st.sidebar.markdown("---")
st.sidebar.subheader("Account")
if "current_user" not in st.session_state:
    auth_mode = st.sidebar.selectbox("Choose", ["Login","Signup"])
    if auth_mode == "Signup":
        su_name = st.sidebar.text_input("Full name")
        su_email = st.sidebar.text_input("Email")
        su_pw = st.sidebar.text_input("Password", type="password")
        su_cnic = st.sidebar.text_input("National ID (CNIC/SSN)")
        su_role = st.sidebar.selectbox("Role", ["patient","doctor","pharmacy"])
        if st.sidebar.button("Create Account"):
            if su_email and su_name and su_pw:
                if su_email in st.session_state["users"]:
                    st.sidebar.error("Account already exists.")
                else:
                    create_user(su_email, su_name, su_pw, role=su_role, cnic=su_cnic)
                    st.sidebar.success("Account created. Please Login.")
            else:
                st.sidebar.error("Fill name, email, password.")
    else:
        li_email = st.sidebar.text_input("Email")
        li_pw = st.sidebar.text_input("Password", type="password")
        if st.sidebar.button("Login"):
            if check_login(li_email, li_pw):
                st.session_state["current_user"] = li_email
                st.sidebar.success("Logged in")
                log_event(li_email, "login")
            else:
                st.sidebar.error("Invalid credentials.")
else:
    if st.sidebar.button("Logout"):
        log_event(st.session_state["current_user"], "logout")
        del st.session_state["current_user"]
        st.experimental_rerun()

# =========================
# PAGES
# =========================

def risk_badge(label):
    if label == "Low": return '<span class="badge green">Low</span>'
    if label == "Moderate": return '<span class="badge amber">Moderate</span>'
    return '<span class="badge red">High</span>'

# Home
if page == "Home":
    col1, col2, col3 = st.columns([1,1,1])
    with col1:
        st.markdown('<div class="card"><div class="metric">Upload Reports</div><strong>AI Early Detection</strong><br><span class="small">CSV/PDF analysis (demo)</span></div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="card"><div class="metric">Remote</div><strong>Doctor Portal</strong><br><span class="small">Read-only with notes</span></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="card"><div class="metric">Paperless</div><strong>Pharmacy</strong><br><span class="small">Digital code redemption</span></div>', unsafe_allow_html=True)
    st.info("Demo patients loaded: Ali (Healthy), Sara (Diabetes risk), Fatima (Anemia), Bilal (Cancer risk). Cancer risk triggers **SOS alert** automatically.")

# Patient Dashboard
elif page == "Patient Dashboard":
    if not user_email or st.session_state["users"][user_email]["role"] != "patient":
        st.warning("Please login as a patient.")
    else:
        u = st.session_state["users"][user_email]
        st.subheader(f"Patient Dashboard — {u['name']}")
        st.caption(f"ID: {u.get('cnic','-')}  •  DOB: {u.get('dob','-')}")

        rows = []
        for token, p in st.session_state["patients"].items():
            rows.append({
                "token": token,
                "patient": p["name"],
                "risk": p.get("risk_label","-")
            })
        df = pd.DataFrame(rows)
        if df.empty:
            st.info("No records yet.")
        else:
            # pretty table with risk badge
            df_show = df.copy()
            df_show["risk"] = df_show["risk"].apply(lambda x: risk_badge(x))
            st.markdown(df_show.to_html(escape=False, index=False), unsafe_allow_html=True)

# Upload Report
elif page == "Upload Report":
    if not user_email or st.session_state["users"][user_email]["role"] != "patient":
        st.warning("Please login as a patient to upload.")
    else:
        st.subheader("Upload Report (CSV)")
        st.caption("Tip: use the provided sample CSVs (Ali / Sara / Fatima / Bilal) for best demo.")
        patient_name = st.text_input("Patient name")
        uploaded = st.file_uploader("Upload lab report CSV", type=["csv"])
        if st.button("Analyze & Save"):
            if not uploaded or not patient_name:
                st.error("Provide patient name and select a CSV file.")
            else:
                df = pd.read_csv(uploaded)
                alerts, metrics, label = analyze_report(df)
                token = gen_token()
                u = st.session_state["users"][user_email]
                st.session_state["patients"][token] = {
                    "name": patient_name, "cnic": u.get("cnic","-"), "dob": u.get("dob","-"),
                    "report": df, "alerts": alerts, "metrics": metrics, "risk_label": label
                }
                st.session_state["prescriptions"][token] = {
                    "meds":[{"name":"Metformin","dose":"500mg","qty":30}],
                    "code": token
                }
                log_event(user_email, "upload_report", target=token)

                st.success(f"Report saved • Patient token: {token}")
                st.write("**AI Early Detection**")
                for a in alerts:
                    if "🚨" in a:
                        fire_sos(patient_name, token, a)
                    elif "⚠️" in a:
                        st.warning(a)
                    else:
                        st.success(a)

# Doctor Portal
elif page == "Doctor Portal":
    st.subheader("Doctor Portal (Read-only)")
    if not user_email or st.session_state["users"][user_email]["role"] != "doctor":
        st.info("Login as a doctor to continue.")
    else:
        doc = st.session_state["users"][user_email]["name"]
        token = st.text_input("Enter patient token")
        if st.button("View"):
            if token in st.session_state["patients"]:
                p = st.session_state["patients"][token]
                st.markdown(f"**Patient:** {p['name']} • **Token:** `{token}`")
                st.caption(f"CNIC: {p.get('cnic','-')} • DOB: {p.get('dob','-')}")
                st.dataframe(p["report"])
                st.markdown("**AI Alerts** (read-only)")
                for a in p["alerts"]:
                    if "🚨" in a: st.error(a)
                    elif "⚠️" in a: st.warning(a)
                    else: st.success(a)
                note = st.text_area("Doctor clinical notes (your own opinion)")
                if st.button("Save Note"):
                    st.session_state["doctor_notes"].setdefault(token, []).append(
                        {"doctor":doc, "note":note, "time":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
                    )
                    log_event(user_email, "doctor_note", target=token)
                    st.success("Note saved.")
                st.markdown("**Previous Notes**")
                for n in st.session_state["doctor_notes"].get(token, []):
                    st.write(f"- **{n['doctor']}** ({n['time']}): {n['note']}")
            else:
                st.error("Token not found.")

# Pharmacy
elif page == "Pharmacy":
    st.subheader("Pharmacy — Redeem Digital Prescription")
    if not user_email or st.session_state["users"][user_email]["role"] != "pharmacy":
        st.info("Login as pharmacy to continue.")
    else:
        code = st.text_input("Enter prescription code (token)")
        if st.button("Lookup"):
            if code in st.session_state["prescriptions"]:
                pres = st.session_state["prescriptions"][code]
                st.table(pd.DataFrame(pres["meds"]))
                # Simple interaction hint
                meds = " ".join([m["name"] for m in pres["meds"]]).lower()
                if "metformin" in meds and "iron" in meds:
                    st.warning("⚠️ Interaction: Iron may reduce absorption of Metformin. Separate doses by 2 hours.")
                log_event(user_email, "redeem_prescription", target=code)
            else:
                st.error("Prescription not found.")

# Chat AI
elif page == "Chat AI":
    st.subheader("Chat with LifePulse AI (Demo)")
    if not user_email:
        st.info("Login to chat.")
    else:
        hist = st.session_state["chat_history"].get(user_email, [])
        for who, msg, t in hist:
            st.write(f"**{who}** ({t}): {msg}")
        q = st.text_input("Ask something about your health or reports")
        if st.button("Send"):
            if q.strip():
                reply = fake_ai_chat(q)
                st.session_state["chat_history"].setdefault(user_email, []).append(("You", q, datetime.utcnow().strftime("%H:%M:%S")))
                st.session_state["chat_history"][user_email].append(("LifePulse AI", reply, datetime.utcnow().strftime("%H:%M:%S")))
                log_event(user_email, "chat_ai", extra=q)
                st.experimental_rerun()

# Admin / Audit
elif page == "Admin / Audit":
    st.subheader("Admin / Audit (Demo)")
    st.write("**Access Log (latest first)**")
    df = pd.DataFrame(st.session_state["audit"][::-1])
    if df.empty:
        st.info("No events yet.")
    else:
        st.dataframe(df, use_container_width=True)

    st.markdown("### SOS Outbox (Simulated)")
    sos_df = pd.DataFrame(st.session_state["sos_outbox"][::-1])
    if sos_df.empty:
        st.caption("No emergency notifications sent yet.")
    else:
        st.dataframe(sos_df, use_container_width=True)

st.markdown("---")
st.caption("Prototype demo — not for clinical use. Future: secure AI wrappers (Gemini/GPT/Claude/Llama), FHIR/HIS/LIS, NADRA ID.")
