import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx

st.set_page_config(page_title="SupplyGuard Security Dashboard", layout="wide")

st.title("🛡 SupplyGuard Security Dashboard")

# ==========================================================
# Load CLI Results
# ==========================================================

if not os.path.exists("last_scan.json"):
    st.error("No scan results found. Run CLI with --dashboard flag.")
    st.stop()

with open("last_scan.json") as f:
    data = json.load(f)

dependencies = data["dependencies"]
secrets = data["secrets"]
cloud_findings = data["cloud_findings"]
risk = data["risk"]

st.success("Loaded results from CLI scan.")

# ==========================================================
# Risk Overview
# ==========================================================

st.markdown("## 🚨 Risk Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Risk Level", risk["risk_level"])
col2.metric("Risk Score", risk["project_score"])
col3.metric("Dependencies", risk["total_dependencies"])
col4.metric("Secrets Found", len(secrets))

st.markdown("---")

st.markdown("## 📊 Dependency Graph")

if os.path.exists("dependency_graph.png"):
    st.image("dependency_graph.png", width="stretch")
else:
    st.warning("Dependency graph not found.")

st.markdown("## 🔥 Risk Heatmap")

if os.path.exists("risk_heatmap.png"):
    st.image("risk_heatmap.png", width="stretch")
else:
    st.warning("Risk heatmap not found.")
# ==========================================================
# Explain Section
# ==========================================================

st.markdown("## 🔍 Explain Engine")

highest_dep = max(
    dependencies,
    key=lambda x: float(x.get("highest_cvss", 0)),
    default=None
)

if highest_dep:
    st.warning("🚨 Highest Risk Dependency")
    st.write(f"Dependency: {highest_dep['name']}")
    st.write(f"CVSS: {highest_dep.get('highest_cvss', 0)}")
    st.write(f"Severity: {highest_dep.get('severity', 'NONE')}")
    st.write(f"CVE Count: {highest_dep.get('cve_count', 0)}")

    st.info("💡 Suggestion: Upgrade to latest secure version.")

if not risk.get("build_allowed", True):
    st.error("❌ BUILD BLOCKED")
else:
    st.success("✅ BUILD ALLOWED")

st.markdown("---")

# ==========================================================
# Dependency Table
# ==========================================================

st.markdown("## 📦 Top Risky Dependencies")

sorted_deps = sorted(
    dependencies,
    key=lambda x: float(x.get("highest_cvss", 0)),
    reverse=True
)

df = pd.DataFrame([{
    "Dependency": d["name"],
    "CVSS": float(d.get("highest_cvss", 0)),
    "Severity": d.get("severity", "NONE"),
    "CVE Count": d.get("cve_count", 0)
} for d in sorted_deps[:20]])

st.dataframe(df, width="stretch")

st.markdown("---")

# ==========================================================
# Secrets Section
# ==========================================================

st.markdown("## 🔐 Secrets Detection")

if secrets:
    st.error(f"{len(secrets)} potential secrets detected")
else:
    st.success("No secrets detected")

st.markdown("---")

# ==========================================================
# Cloud Findings
# ==========================================================

st.markdown("## ☁ Cloud Findings")

if cloud_findings:
    for finding in cloud_findings:
        severity = finding.get("severity", "HIGH")
        icon = "🔴" if severity == "CRITICAL" else "🟠"
        st.markdown(f"{icon} {finding['issue']}")
        st.markdown(f"➡ {finding['remediation']}")
        st.markdown("---")
else:
    st.success("No cloud misconfigurations detected")

st.markdown("### 🚀 SupplyGuard Multi-Cloud Security Engine")