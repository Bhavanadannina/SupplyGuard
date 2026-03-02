import sys
import os
import shutil
import subprocess
import tempfile
import venv
import json

from scanner.dependency_scan import scan_dependencies
from scanner.sbom import generate_sbom
from scanner.systemic_risk import compute_project_risk
from scanner.explain_engine import explain_risk
from scanner.secret_scanner import scan_secrets
from scanner.docker_scan import scan_dockerfile
from scanner.iac_scan import scan_yaml_iac, scan_docker_compose
from scanner.java_dependency_scan import scan_java_dependencies
from scanner.cloud_scan import scan_aws_environment
# from scanner.azure_scan import scan_azure_environment
from scanner.ai_engine import generate_ai_report
from scanner.sbom_integrity import generate_sbom_hash, verify_sbom_integrity



# ==========================================================
# Helper: Detect Git URL
# ==========================================================

def is_git_url(path):
    return path.startswith("http://") or path.startswith("https://")


# ==========================================================
# AWS AUTO DETECTION
# ==========================================================

def detect_aws_usage(project_path):

    for root, dirs, files in os.walk(project_path):

        for file in files:

            # Terraform detection
            if file.endswith(".tf"):
                try:
                    with open(os.path.join(root, file), "r", errors="ignore") as f:
                        content = f.read().lower()
                        if 'provider "aws"' in content:
                            return True
                except:
                    pass

            # requirements detection
            if file == "requirements.txt":
                try:
                    with open(os.path.join(root, file), "r", errors="ignore") as f:
                        content = f.read().lower()
                        if "boto3" in content:
                            return True
                except:
                    pass

            # CloudFormation detection
            if file.endswith(".yaml") or file.endswith(".yml"):
                try:
                    with open(os.path.join(root, file), "r", errors="ignore") as f:
                        content = f.read().lower()
                        if "aws::" in content:
                            return True
                except:
                    pass

    return False


# ==========================================================
# Clone Repository
# ==========================================================

def clone_repository(repo_url):
    temp_dir = tempfile.mkdtemp(prefix="supplyguard_repo_")

    print(f"[*] Cloning repository into {temp_dir}...")

    result = subprocess.run(
        ["git", "clone", repo_url, temp_dir],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("❌ Failed to clone repository")
        print(result.stderr)
        shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)

    print("[+] Repository cloned successfully\n")
    return temp_dir


# ==========================================================
# Create Isolated Virtual Environment
# ==========================================================

def create_isolated_venv(project_path):
    venv_path = os.path.join(project_path, ".supplyguard_env")

    print("[*] Creating isolated virtual environment...")
    venv.create(venv_path, with_pip=True)

    python_path = os.path.join(venv_path, "Scripts", "python.exe")

    subprocess.run([python_path, "-m", "pip", "install", "--upgrade", "pip"],
                   stdout=subprocess.DEVNULL)

    subprocess.run([python_path, "-m", "pip", "install", "pipdeptree"],
                   stdout=subprocess.DEVNULL)

    print("[+] Virtual environment ready\n")
    return venv_path


# ==========================================================
# Install Project Inside Isolated Env
# ==========================================================

def install_project(project_path, venv_path):
    python_path = os.path.join(venv_path, "Scripts", "python.exe")

    print("[*] Installing project into isolated environment...")

    result = subprocess.run(
        [python_path, "-m", "pip", "install", "."],
        cwd=project_path,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[!] Could not install project as package.")
        print("    Trying requirements.txt fallback...\n")

        requirements_path = os.path.join(project_path, "requirements.txt")

        if os.path.exists(requirements_path):
            subprocess.run(
                [python_path, "-m", "pip", "install", "-r", requirements_path],
                cwd=project_path
            )
            print("[+] Installed using requirements.txt\n")
        else:
            print("[!] No installable project metadata found.\n")
    else:
        print("[+] Project installed successfully\n")


# ==========================================================
# Main Engine
# ==========================================================

def run_supplyguard(project_path, explain=False, visualize=False, ai_flag=False):

    temp_clone = None

    if is_git_url(project_path):
        temp_clone = clone_repository(project_path)
        isolated_venv = create_isolated_venv(temp_clone)
        install_project(temp_clone, isolated_venv)
        project_path = temp_clone

    print("\n==============================")
    print("      SUPPLYGUARD SCAN")
    print("==============================\n")

    if not os.path.isdir(project_path):
        print("[!] Invalid project path")
        sys.exit(1)

    print(f"[*] Scanning project: {project_path}\n")

    # =====================================================
    # Dependency Scan
    # =====================================================
    print("[1/3] Running dependency scan...")
    dependencies, docker_findings, yaml_findings, compose_findings, terraform_findings = scan_dependencies(project_path)
    print()

    # =====================================================
    # Secret Scan
    # =====================================================
    print("[*] Running secret scan...")
    secrets = scan_secrets(project_path)

    if secrets:
        print(f"[!] Found {len(secrets)} potential secrets")
    else:
        print("[+] No secrets detected")
    print()

    # =====================================================
    # Cloud Scan (AWS Auto Detection)
    # =====================================================
    print("[*] Checking for AWS usage in project...")

    cloud_findings = []

    aws_detected = detect_aws_usage(project_path)

    if aws_detected:
        print("[*] AWS usage detected. Running AWS scan...")
        cloud_findings = scan_aws_environment()
    else:
        print("[+] No AWS usage detected. Skipping AWS cloud scan.")

    # =====================================================
    # SBOM
    # =====================================================
    print("[2/3] Generating SBOM...")
    generate_sbom(dependencies)
    print("[+] SBOM generated successfully")
    
    # 🔐 Generate SBOM Integrity Hash
    generate_sbom_hash()
    integrity_ok = verify_sbom_integrity()
    print()

    # =====================================================
    # Risk Engine
    # =====================================================
    print("[3/3] Running systemic risk model...")
    project_risk = compute_project_risk(
        dependencies,
        secrets,
        terraform_findings,
        cloud_findings
    )

    print("\n======= PROJECT RISK SUMMARY =======")
    print(f"Project Score      : {project_risk['project_score']}")
    print(f"Risk Level         : {project_risk['risk_level']}")
    print(f"Total Dependencies : {project_risk['total_dependencies']}")
    print("====================================\n")

    if explain:
        explain_risk(dependencies, project_risk)

    # =====================================================
    # Visualization
    # =====================================================
    if visualize:
        from scanner.graph_visualizer import show_dependency_graph
        from scanner.risk_heatmap import show_risk_heatmap

        print("[*] Generating dependency graph...")
        show_dependency_graph(project_path)

        print("[*] Generating risk heatmap...")
        show_risk_heatmap(dependencies)

    # =====================================================
    # SAVE RESULTS FOR DASHBOARD
    # =====================================================
    results = {
        "dependencies": dependencies,
        "secrets": secrets,
        "cloud_findings": cloud_findings,
        "risk": project_risk
    }

    with open("last_scan.json", "w") as f:
        json.dump(results, f, indent=4)

    print("📁 Results saved to last_scan.json\n")
    
    if ai_flag:
        generate_ai_report(results)

    if project_risk.get("build_allowed", True) and integrity_ok:
        print("✅ BUILD ALLOWED — Policy thresholds satisfied")
        exit_code = 0
    else:
        if not integrity_ok:
            print("❌ BUILD BLOCKED — SBOM Integrity Verification Failed")
        else:
            print(f"❌ BUILD BLOCKED — Policy threshold exceeded ({project_risk['risk_level']})")
        exit_code = 1

    print("\nScan completed.\n")

    if temp_clone:
        shutil.rmtree(temp_clone, ignore_errors=True)

    return exit_code


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python supplyguard.py <project_path_or_git_url> [--explain] [--visualize] [--dashboard]")
        sys.exit(1)

    project_path = sys.argv[1]
    explain_flag = "--explain" in sys.argv
    visualize_flag = "--visualize" in sys.argv
    dashboard_flag = "--dashboard" in sys.argv
    ai_flag = "--ai" in sys.argv

    exit_code = run_supplyguard(project_path, explain_flag, visualize_flag, ai_flag)

    if dashboard_flag:
        print("🚀 Launching Dashboard...\n")
        subprocess.run(["streamlit", "run", "dashboard.py"])

    sys.exit(exit_code)