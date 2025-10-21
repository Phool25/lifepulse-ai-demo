import streamlit as st
import pandas as pd
import shortuuid

# ------------------------------
# Dummy in-memory storage
# ------------------------------
patients = {}
doctor_notes = {}
prescriptions = {}

# ------------------------------
# Utility: Analyze Report (AI Simulation)
# ------------------------------
def analyze_report(df):
    results = []
    alerts = []
    
    for _, row in df.iterrows():
        test = row['Test']
        value = float(row['Result'])
        ref = row['Reference_Range']
        
        if test == "Glucose" and value > 125:
            alerts.append("⚠️ High glucose detected → Possible Diabetes Risk")
        if test == "Hemoglobin" and value < 11:
            alerts.append("⚠️ Low hemoglobin → Possible Anemia Risk")
        if test == "WBC" and value > 20000:
            alerts.append("🚨 Abnormal WBC count → Possible Cancer Risk (Early Detection Alert!)")
    
    if not alerts:
        alerts.append("✅ Report looks normal. No critical risks found.")
    return alerts

# ------------------------------
# Streamlit App
# ------------------------------
st.set_page_config(page_title="LifePulse AI", layout="wide")

st.title("💙 LifePulse AI – Digital Health Passport")
st.caption("Early Detection • Digitized Records • Remote Diagnostics • Safe Prescriptions")

menu = st.sidebar.radio("Navigation", ["Home", "Upload Report", "Doctor Portal", "Pharmacy", "Analytics"])

# ------------------------------
# HOME
# ------------------------------
if menu == "Home":
    st.header("Welcome to LifePulse AI")
    st.write("Upload your medical reports, let AI analyze them for **early disease detection**, and securely share with doctors or pharmacies.")
    st.info("Demo patients available: Ali (Healthy), Sara (Diabetes Risk), Fatima (Anemia), Bilal (Cancer Risk)")

# ------------------------------
# UPLOAD REPORT
# ------------------------------
elif menu == "Upload Report":
    st.header("📤 Upload Patient Report")
    name = st.text_input("Patient Name")
    uploaded = st.file_uploader("Upload CSV Report", type=["csv"])
    
    if uploaded and name:
        df = pd.read_csv(uploaded)
        st.write("### Uploaded Report")
        st.dataframe(df)
        
        alerts = analyze_report(df)
        st.subheader("AI Early Detection Results")
        for a in alerts:
            if "Cancer" in a:
                st.error(a)
            elif "Diabetes" in a or "Anemia" in a:
                st.warning(a)
            else:
                st.success(a)
        
        token = shortuuid.uuid()[:8]
        patients[token] = {"name": name, "report": df, "alerts": alerts}
        st.success(f"✅ Patient record saved. Share this token with doctor: `{token}`")
        
        # Generate dummy prescription
        prescriptions[token] = ["Metformin", "Iron Supplements", "Vitamin D"]

# ------------------------------
# DOCTOR PORTAL
# ------------------------------
elif menu == "Doctor Portal":
    st.header("👨‍⚕️ Doctor Portal")
    token = st.text_input("Enter Patient Token")
    
    if token in patients:
        patient = patients[token]
        st.write(f"### Patient: {patient['name']}")
        st.dataframe(patient["report"])
        st.write("### AI Alerts (Read-only)")
        for a in patient["alerts"]:
            st.info(a)
        
        notes = st.text_area("Doctor Notes", doctor_notes.get(token, ""))
        if st.button("Save Notes"):
            doctor_notes[token] = notes
            st.success("Notes saved (only doctor view).")

# ------------------------------
# PHARMACY
# ------------------------------
elif menu == "Pharmacy":
    st.header("💊 Pharmacy Access")
    token = st.text_input("Enter Prescription Code")
    
    if token in prescriptions:
        st.write("### Prescribed Medicines")
        for med in prescriptions[token]:
            st.write(f"- {med}")
        
        # Drug interaction demo
        if "Metformin" in prescriptions[token] and "Iron Supplements" in prescriptions[token]:
            st.warning("⚠️ AI Check: Take Iron supplements 2 hours apart from Metformin to avoid absorption issues.")

# ------------------------------
# ANALYTICS
# ------------------------------
elif menu == "Analytics":
    st.header("📊 Health Analytics")
    if patients:
        for token, data in patients.items():
            st.subheader(f"Patient: {data['name']}")
            st.line_chart(data['report'].set_index("Test")["Result"])
            st.write("AI Summary:")
            for a in data["alerts"]:
                st.write("- " + a)
    else:
        st.info("No patient reports uploaded yet.")

st.sidebar.markdown("---")
st.sidebar.caption("Prototype Demo • AI Wrappers (Gemini, Claude, GPT, Llama) integration planned via APIs/SDKs")
