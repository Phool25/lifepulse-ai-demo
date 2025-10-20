import streamlit as st
import pandas as pd
import shortuuid
import hashlib
from datetime import datetime, timedelta

st.set_page_config(page_title="LifePulse AI - Demo", layout="wide")

# ------------------ In-memory "DB" (demo only) ------------------
if "users" not in st.session_state:
    st.session_state["users"] = {}  # email -> {name, role, subscribed(bool)}
if "records" not in st.session_state:
    st.session_state["records"] = {}  # patient_email -> list of records
if "shares" not in st.session_state:
    st.session_state["shares"] = {}  # token -> {patient_email, scope, expires_at, active}
if "audit" not in st.session_state:
    st.session_state["audit"] = []  # list of access events
if "doctor_messages" not in st.session_state:
    st.session_state["doctor_messages"] = {}  # patient_email -> list of messages
if "prescriptions" not in st.session_state:
    st.session_state["prescriptions"] = {}  # presc_id -> {patient_email, meds, code}

# ------------------ Helpers ------------------
def create_user(email, name, role="patient"):
    st.session_state["users"][email] = {"name": name, "role": role, "subscribed": False}
    if email not in st.session_state["records"]:
        st.session_state["records"][email] = []

def gen_token():
    return shortuuid.uuid()

def hash_token(t):
    return hashlib.sha256(t.encode()).hexdigest()

def log_access(actor, action, patient_email, extra=""):
    st.session_state["audit"].append({
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "actor": actor,
        "action": action,
        "patient": patient_email,
        "extra": extra
    })

def fake_ai_analysis(file_name):
    # Dummy logic - in real app replace with OCR + ML
    return {
        "Glucose": "160 mg/dL (High)",
        "Cholesterol": "220 mg/dL (Borderline)",
        "AI_Conclusion": "Possible pre-diabetes / diabetes risk. Recommend clinical check-up."
    }

def create_prescription(patient_email, meds_list):
    pid = shortuuid.uuid()[:8]
    code = shortuuid.ShortUUID().random(length=10)
    st.session_state["prescriptions"][pid] = {"patient": patient_email, "meds": meds_list, "code": code}
    return pid, code

# ------------------ UI ------------------
st.title("💙 LifePulse AI (Demo)")
st.caption("Your lifetime health companion — demo (no real diagnoses)")

menu = st.sidebar.selectbox("Menu", ["Home / Login", "Patient Dashboard", "Upload Report", "Share & Privacy", "Doctor Portal", "Pharmacy", "Admin / Audit"])

# --- Home / Login ---
if menu == "Home / Login":
    st.header("Login / Create Account (Demo)")
    col1, col2 = st.columns(2)
    with col1:
        email = st.text_input("Email")
        name = st.text_input("Full name")
        role = st.selectbox("Role", ["patient", "doctor", "pharmacy"])
        if st.button("Create / Login"):
            if email.strip() == "" or name.strip() == "":
                st.error("Please provide both name and email.")
            else:
                if email not in st.session_state["users"]:
                    create_user(email, name, role=role)
                    st.success(f"Account created for {name} as {role}.")
                else:
                    st.success(f"Welcome back, {st.session_state['users'][email]['name']} ({st.session_state['users'][email]['role']})")
                st.session_state["current_user"] = email
    with col2:
        if "current_user" in st.session_state:
            cu = st.session_state["current_user"]
            u = st.session_state["users"].get(cu, {})
            st.info(f"Signed in as: {cu}\nName: {u.get('name')}\nRole: {u.get('role')}\nSubscribed: {u.get('subscribed')}")

# --- Patient Dashboard ---
elif menu == "Patient Dashboard":
    if "current_user" not in st.session_state or st.session_state["users"].get(st.session_state["current_user"], {}).get("role") != "patient":
        st.warning("Please login as a patient to view this page.")
    else:
        user = st.session_state["current_user"]
        st.header("Patient Dashboard")
        st.subheader(f"Welcome, {st.session_state['users'][user]['name']}")
        # summary metrics (demo)
        recent = st.session_state["records"].get(user, [])[-3:]
        col1, col2, col3 = st.columns(3)
        col1.metric("Last Glucose", recent[-1]["ai"].get("Glucose") if recent else "N/A")
        col2.metric("Last Cholesterol", recent[-1]["ai"].get("Cholesterol") if recent else "N/A")
        col3.metric("Health Note", recent[-1]["ai"].get("AI_Conclusion") if recent else "N/A")
        st.markdown("### Lifetime Records")
        df = pd.DataFrame([{"Date": r["date"], "Report": r["file_name"], "AI_Result": r["ai"].get("AI_Conclusion")} for r in st.session_state["records"].get(user, [])])
        st.table(df if not df.empty else pd.DataFrame([{"Date":"-","Report":"No records","AI_Result":"-"}]))
        st.markdown("---")
        st.subheader("Subscription")
        if not st.session_state["users"][user]["subscribed"]:
            st.info("You are currently NOT subscribed. Subscribe to consult doctors.")
            if st.button("Subscribe (Demo)"):
                st.session_state["users"][user]["subscribed"] = True
                st.success("Subscribed (demo). You can now request doctor consults.")
        else:
            st.success("Subscribed. You can request direct doctor consults.")

# --- Upload Report ---
elif menu == "Upload Report":
    if "current_user" not in st.session_state or st.session_state["users"].get(st.session_state["current_user"], {}).get("role") != "patient":
        st.warning("Please login as patient to upload reports.")
    else:
        user = st.session_state["current_user"]
        st.header("Upload Report")
        uploaded = st.file_uploader("Upload a lab report (PDF/JPG/PNG)", type=["pdf","png","jpg","jpeg"])
        notes = st.text_area("Optional notes for this report")
        if st.button("Process & Save"):
            if uploaded is None:
                st.error("Please upload a file first.")
            else:
                ai = fake_ai_analysis(uploaded.name)
                rec = {"id": shortuuid.uuid(), "file_name": uploaded.name, "date": datetime.utcnow().strftime("%Y-%m-%d"), "notes": notes, "ai": ai}
                st.session_state["records"].setdefault(user, []).append(rec)
                log_access(user, "upload_report", user, uploaded.name)
                st.success("Report saved and analyzed by AI (demo).")
                st.subheader("AI Analysis")
                st.write(ai)
                if st.button("Create demo prescription from AI result"):
                    meds = [{"name":"Metformin", "dose":"500mg", "qty":30}]
                    pid, code = create_prescription(user, meds)
                    log_access(user, "create_prescription", user, pid)
                    st.success(f"Prescription created. ID: {pid}, Pharmacy Code: {code}")

# --- Share & Privacy ---
elif menu == "Share & Privacy":
    if "current_user" not in st.session_state or st.session_state["users"].get(st.session_state["current_user"], {}).get("role") != "patient":
        st.warning("Please login as patient to manage shares.")
    else:
        user = st.session_state["current_user"]
        st.header("Share & Privacy (Read-only sharing)")
        scope = st.multiselect("Select scope to share", ["labs","imaging","notes"], default=["labs","notes"])
        days = st.number_input("Access for (days, 0 = no expiry)", min_value=0, value=7)
        if st.button("Create Share Link / Token"):
            token = gen_token()
            expires = None if days==0 else (datetime.utcnow()+timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S UTC")
            st.session_state["shares"][token] = {"patient": user, "scope": scope, "expires": expires, "active": True}
            log_access(user, "create_share", user, token)
            st.success(f"Share token created. Token: {token}")
        st.subheader("Active Shares")
        rows = []
        for t, s in st.session_state["shares"].items():
            if s["patient"]==user:
                rows.append({"token":t, "scope":",".join(s["scope"]), "expires": s["expires"], "active":s["active"]})
        st.table(pd.DataFrame(rows))

# --- Doctor Portal ---
elif menu == "Doctor Portal":
    st.header("Doctor Portal (Read-only patient access)")
    doc_email = st.text_input("Doctor Email")
    token = st.text_input("Patient Share Token (or patient email)")
    if st.button("View Patient Records"):
        patient = None
        if token in st.session_state["shares"] and st.session_state["shares"][token]["active"]:
            patient = st.session_state["shares"][token]["patient"]
        elif token in st.session_state["users"] and st.session_state["users"][token]["role"]=="patient":
            patient = token
        if patient is None:
            st.error("No active share found.")
        else:
            st.success(f"Access granted to patient: {patient} (READ-ONLY)")
            log_access(doc_email, "view_patient", patient, token)
            df = pd.DataFrame([{"Date": r["date"], "Report": r["file_name"], "AI_Result": r["ai"].get("AI_Conclusion")} for r in st.session_state["records"].get(patient, [])])
            st.table(df if not df.empty else pd.DataFrame([{"Date":"-","Report":"No records","AI_Result":"-"}]))
            st.subheader("Doctor Clinical Notes")
            note = st.text_area("Your clinical opinion")
            if st.button("Save Doctor Note"):
                st.session_state["doctor_messages"].setdefault(patient, []).append({"doctor":doc_email, "note":note, "time":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")})
                log_access(doc_email, "write_doctor_note", patient, "")
                st.success("Doctor note saved.")
            st.subheader("Existing Doctor Notes")
            notes = st.session_state["doctor_messages"].get(patient, [])
            for n in notes:
                st.write(f"- **{n['doctor']}** ({n['time']}): {n['note']}")

# --- Pharmacy ---
elif menu == "Pharmacy":
    st.header("Pharmacy - Redeem Prescription by Code (Demo)")
    code = st.text_input("Enter Prescription Code")
    if st.button("Lookup Code"):
        found = None
        for pid, p in st.session_state["prescriptions"].items():
            if p["code"]==code:
                found = (pid, p)
                break
        if not found:
            st.error("No prescription found.")
        else:
            pid, p = found
            st.success(f"Prescription {pid} for patient {p['patient']} found.")
            st.table(pd.DataFrame(p["meds"]))
            log_access("pharmacy_user", "redeem_prescription", p["patient"], pid)

# --- Admin / Audit ---
elif menu == "Admin / Audit":
    st.header("Admin / Audit (Demo)")
    df = pd.DataFrame(st.session_state["audit"][::-1])
    st.table(df if not df.empty else pd.DataFrame([{"time":"-","actor":"-","action":"-","patient":"-","extra":"-"}]))
    st.subheader("All Shares")
    sh = []
    for t,s in st.session_state["shares"].items():
        sh.append({"token":t,"patient":s["patient"],"scope":",".join(s["scope"]), "expires":s["expires"], "active":s["active"]})
    st.table(pd.DataFrame(sh if sh else [{"token":"-"}]))
