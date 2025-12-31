import streamlit as st
import json
import pandas as pd
import requests
import datetime
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ================= PATH SETUP =================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(REPORT_DIR, exist_ok=True)

# ================= PAGE CONFIG =================
st.set_page_config(page_title="Advanced CTI Dashboard", layout="wide")

st.title("🛡️ Advanced Cyber Threat Intelligence Dashboard")
st.caption("Live investigation + historical CTI correlation + MITRE + PDF reporting")

# ================= SIDEBAR =================
st.sidebar.header("🔎 Analyst Controls")

search_ip = st.sidebar.text_input(
    "Filter by IP (optional)",
    placeholder="e.g. 46.151.182.230"
)

min_ips = st.sidebar.slider(
    "Minimum IPs in correlation group",
    2, 10, 2
)

view_option = st.sidebar.selectbox(
    "Select View",
    ["None", "Correlation", "MITRE ATT&CK", "Both"]
)

apply_btn = st.sidebar.button("Apply Analysis")

# ================= LIVE IP LOOKUP =================
st.subheader("🔍 Live IP Lookup (Real‑Time)")

live_ip = st.text_input(
    "Enter any IP address",
    placeholder="e.g. 8.8.8.8"
)

if st.button("Lookup Live IP"):
    if not live_ip:
        st.warning("Please enter an IP address.")
    else:
        try:
            r = requests.get(f"https://ipinfo.io/{live_ip}/json", timeout=10)
            st.json(r.json())
        except:
            st.error("Live IP lookup failed")

# ================= LOAD DATA =================
with open(os.path.join(DATA_DIR, "correlated_iocs.json")) as f:
    correlated = json.load(f)

with open(os.path.join(DATA_DIR, "mitre_mapped_iocs.json")) as f:
    mitre_data = json.load(f)

# ================= HELPERS =================
def normalize_key(key):
    return key.replace('"', "").replace("'", "").strip().lower()

# ================= DEFAULT VIEW =================
if not apply_btn or view_option == "None":
    st.info(
        "👈 Use the sidebar to run CTI analysis.\n\n"
        "- Filter by IP (optional)\n"
        "- Choose correlation size\n"
        "- Select view\n"
        "- Click Apply Analysis"
    )
    st.stop()

# ================= FILTER CORRELATION =================
filtered_groups = []

for group in correlated:
    if len(group["related_ips"]) < min_ips:
        continue
    if search_ip and search_ip not in group["related_ips"]:
        continue
    filtered_groups.append(group)

# ================= CORRELATION VIEW =================
if view_option in ["Correlation", "Both"]:
    st.subheader("📌 Correlated Threat Groups")

    if not filtered_groups:
        st.warning("No correlation groups match your filters.")
    else:
        for group in filtered_groups:
            st.markdown(f"### 🔗 Correlation Key: `{group['correlation_key']}`")
            st.code("\n".join(group["related_ips"]))

# ================= MITRE VIEW =================
mitre_matches = []

if view_option in ["MITRE ATT&CK", "Both"]:
    st.subheader("🎯 MITRE ATT&CK Mapping")

    valid_keys = {normalize_key(g["correlation_key"]) for g in filtered_groups}

    for entry in mitre_data:
        if normalize_key(entry["correlation_key"]) in valid_keys:
            mitre_matches.append(entry)
            st.markdown(f"### 🔍 Correlation Key: `{entry['correlation_key']}`")
            st.table(pd.DataFrame(entry["mitre_mapping"]))

    if not mitre_matches:
        st.warning("No MITRE mappings available.")

# ================= PDF EXPORT =================
st.subheader("📄 Reporting")

if st.button("Export Filtered Report (PDF)"):
    if not filtered_groups:
        st.error("No data available to export.")
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_tag = search_ip if search_ip else "all"
        filename = f"CTI_Report_{ip_tag}_{ts}.pdf"
        filepath = os.path.join(REPORT_DIR, filename)

        st.write("📄 Writing PDF to:", filepath)

        c = canvas.Canvas(filepath, pagesize=A4)
        width, height = A4
        y = height - 40

        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "Advanced Cyber Threat Intelligence Report")
        y -= 25

        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Generated: {datetime.datetime.now()}")
        y -= 30

        for group in filtered_groups:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(40, y, f"Correlation Key: {group['correlation_key']}")
            y -= 18

            c.setFont("Helvetica", 10)
            for ip in group["related_ips"]:
                c.drawString(60, y, f"- {ip}")
                y -= 14
                if y < 60:
                    c.showPage()
                    y = height - 40

            for entry in mitre_matches:
                if normalize_key(entry["correlation_key"]) == normalize_key(group["correlation_key"]):
                    c.setFont("Helvetica-Oblique", 10)
                    c.drawString(60, y, "MITRE ATT&CK Techniques:")
                    y -= 14
                    c.setFont("Helvetica", 9)
                    for m in entry["mitre_mapping"]:
                        c.drawString(80, y, f"{m['technique_id']} - {m['technique']}")
                        y -= 12
                        if y < 60:
                            c.showPage()
                            y = height - 40

            y -= 20

        c.save()

        st.success("✅ PDF report generated successfully")
        st.info(f"📍 Saved at: {filepath}")

        with open(filepath, "rb") as pdf:
            st.download_button(
                "⬇️ Download PDF Report",
                pdf,
                file_name=filename,
                mime="application/pdf"
            )

st.divider()
st.success("Dashboard fully operational — live + historical CTI ready")
