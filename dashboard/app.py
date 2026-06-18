import streamlit as st
import requests
import pandas as pd

API_URL = "https://ai-db-idps-77hv.onrender.com"

st.set_page_config(layout="wide")
st.title("🛡️ AI-DB-IDPS Dashboard")

# ─────────────────────────────
# INPUT SECTION
# ─────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    user = st.text_input("User", "alice")

with col2:
    ip = st.text_input("IP", "192.168.1.10")

with col3:
    query = st.text_input("Query", "SELECT * FROM users")

if st.button("Analyze"):

    try:
        res = requests.post(
            f"{API_URL}/query",
            json={"user": user, "ip": ip, "query": query},
            timeout=10,
        )
        data = res.json()
    except Exception as e:
        st.error(f"❌ API connection failed: {e}")
        data = None

    

    st.subheader("🔍 Result")

    if data["status"] == "allowed":
        st.success("✅ ALLOWED")
    else:
        st.error("🚨 BLOCKED")

    st.write("Score:", data["anomaly_score"])

    st.subheader("🧠 Explanation")
    if isinstance(data["explanation"], list):
        for r in data["explanation"]:
            st.write(f"- {r}")
    else:
        st.write(data["explanation"])

# ─────────────────────────────
# LOGS
# ─────────────────────────────
st.divider()
st.subheader("📜 Query Logs")

try:
    res = requests.get(f"{API_URL}/logs", timeout=10)
    logs = res.json().get("logs", [])
except:
    logs = []
df = pd.DataFrame(logs)

if not df.empty:
    st.dataframe(df)

    st.subheader("📊 Stats")
    st.metric("Total", len(df))
    st.metric("Blocked", len(df[df["decision"] == "blocked"]))
else:
    st.write("No logs yet")


