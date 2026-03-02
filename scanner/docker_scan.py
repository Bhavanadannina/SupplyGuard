import os
import re


def scan_dockerfile(project_path):

    print("[*] Running Dockerfile security checks...")

    dockerfile_path = None

    for root, dirs, files in os.walk(project_path):
        if "Dockerfile" in files:
            dockerfile_path = os.path.join(root, "Dockerfile")
            break

    if not dockerfile_path:
        print("[!] No Dockerfile found")
        return []

    print(f"[*] Found Dockerfile at: {dockerfile_path}")

    findings = []

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read().lower()

    # Rule 1: latest tag
    if re.search(r"from\s+.*:latest", content):
        findings.append("Using 'latest' tag in base image")

    # Rule 2: running as root (no USER instruction)
    if "user " not in content:
        findings.append("Container runs as root (no USER instruction found)")

    # Rule 3: ADD instead of COPY
    if re.search(r"^\s*add\s+", content, re.MULTILINE):
        findings.append("Using ADD instead of COPY")

    # Rule 4: Exposing privileged ports
    if re.search(r"expose\s+22", content):
        findings.append("Exposing SSH port 22")

    # Rule 5: No HEALTHCHECK
    if "healthcheck" not in content:
        findings.append("No HEALTHCHECK instruction found")

    if findings:
        print(f"[!] Found {len(findings)} Docker misconfigurations")
    else:
        print("[+] No Docker misconfigurations detected")

    return findings