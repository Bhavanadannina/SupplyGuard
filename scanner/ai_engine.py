import os
import json

# Optional OpenAI import
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


# ==========================================================
# ENTRY POINT (SAFE HYBRID MODE)
# ==========================================================

def generate_ai_report(scan_data):

    api_key = os.getenv("OPENAI_API_KEY")

    # If OpenAI not installed or key missing → fallback immediately
    if not OPENAI_AVAILABLE or not api_key:
        print("\n🧠 Using Offline AI Engine (No API Key Detected)...")
        return generate_local_report(scan_data)

    print("\n🤖 Attempting OpenAI AI Engine...")

    try:
        return generate_openai_report(scan_data, api_key)

    except Exception as e:
        print("\n⚠ OpenAI AI Engine failed.")
        print(f"Reason: {str(e)}")
        print("🔁 Switching to Offline AI Engine...\n")
        return generate_local_report(scan_data)


# ==========================================================
# REAL OPENAI ENGINE
# ==========================================================

def generate_openai_report(scan_data, api_key):

    client = OpenAI(api_key=api_key)

    prompt = f"""
You are a senior cybersecurity architect.

Analyze the following project scan results and generate:

1. Executive Summary
2. Root Cause Analysis
3. Risk Amplification Explanation
4. Prioritized Remediation Plan (sorted by severity and impact)

Scan Data:
{json.dumps(scan_data, indent=2)}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
    )

    print("\n🤖 AI SECURITY REPORT (OpenAI)")
    print("================================================")
    print(response.choices[0].message.content)
    print("================================================\n")


# ==========================================================
# OFFLINE FALLBACK ENGINE
# ==========================================================

def generate_local_report(scan_data):

    dependencies = scan_data.get("dependencies", [])
    secrets = scan_data.get("secrets", [])
    cloud = scan_data.get("cloud_findings", [])
    risk = scan_data.get("risk", {})

    risk_level = risk.get("risk_level", "UNKNOWN")
    score = risk.get("project_score", 0)

    print("\n🧠 OFFLINE AI SECURITY ANALYSIS")
    print("================================================")

    print("\n📊 Executive Summary")
    print(f"Risk Level: {risk_level}")
    print(f"Risk Score: {score}")

    critical_deps = [
        d for d in dependencies
        if float(d.get("highest_cvss", 0)) >= 9
    ]

    print("\n🧠 Root Cause Analysis")

    if critical_deps:
        print(f"- {len(critical_deps)} critical dependency vulnerabilities detected.")

    if secrets:
        print(f"- {len(secrets)} hardcoded secrets increase exploitability risk.")

    if cloud:
        print(f"- {len(cloud)} cloud misconfigurations expand attack surface.")

    if not (critical_deps or secrets or cloud):
        print("- No major systemic weaknesses detected.")

    # ------------------------------
    # Prioritized Remediation
    # ------------------------------

    remediation = []

    for dep in critical_deps:
        remediation.append((
            100,
            f"Upgrade critical dependency '{dep['name']}' (CVSS {dep.get('highest_cvss')})"
        ))

    for c in cloud:
        severity = c.get("severity", "HIGH")
        weight = 90 if severity == "CRITICAL" else 70
        remediation.append((weight, c.get("issue")))

    if secrets:
        remediation.append((80, "Remove hardcoded secrets and rotate exposed credentials."))

    remediation.sort(reverse=True)

    print("\n🚨 Prioritized Remediation Plan")

    if remediation:
        for idx, (_, action) in enumerate(remediation, 1):
            print(f"{idx}. {action}")
    else:
        print("No urgent remediation required.")

    print("================================================\n")