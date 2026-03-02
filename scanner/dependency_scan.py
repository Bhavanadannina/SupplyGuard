import os
import subprocess
import json

from scanner.nvd_parser import get_indexed_vulnerabilities, version_matches
from scanner.ecosystem_detector import detect_ecosystem
from scanner.node_dependency_scan import scan_node_dependencies
from scanner.java_dependency_scan import scan_java_dependencies
from scanner.docker_scan import scan_dockerfile
from scanner.iac_scan import scan_yaml_iac, scan_docker_compose, scan_terraform

# ----------------------------------------
# Utility
# ----------------------------------------

def normalize(name):
    return name.replace("-", "_").lower().strip()


# ----------------------------------------
# Python Dependency Scan
# ----------------------------------------

def run_pipdeptree(project_path):

    isolated_venv = os.path.join(project_path, ".supplyguard_env")

    if os.path.exists(isolated_venv):
        python_path = os.path.join(isolated_venv, "Scripts", "python.exe")
        cmd = [python_path, "-m", "pipdeptree", "--json-tree"]
    else:
        cmd = ["pipdeptree", "--json-tree"]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=project_path
    )

    if result.returncode != 0:
        print("[!] Error running pipdeptree")
        return []

    return json.loads(result.stdout)


def flatten_dependencies(tree):

    flat = {}
    relations = {}

    def recurse(pkg, parent=None, depth=1):

        if "package" in pkg:
            name = normalize(pkg["package"]["key"])
            version = pkg["package"]["installed_version"]
        else:
            name = normalize(pkg.get("key", ""))
            version = pkg.get("installed_version", "")

        if not name:
            return

        # Store dependency info
        if name not in flat:
            flat[name] = {
                "name": name,
                "version": version,
                "depth": depth,
                "dependencies": []
            }

        # Store parent-child relationship
        if parent:
            if parent not in relations:
                relations[parent] = []
            relations[parent].append(name)

        for dep in pkg.get("dependencies", []):
            recurse(dep, name, depth + 1)

    for pkg in tree:
        recurse(pkg)

    # Attach child dependencies
    for parent, children in relations.items():
        if parent in flat:
            flat[parent]["dependencies"] = list(set(children))

    return list(flat.values())


# ----------------------------------------
# CVSS Severity
# ----------------------------------------

def severity_from_cvss(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "NONE"


# ----------------------------------------
# Main Dependency Scan
# ----------------------------------------

def scan_dependencies(project_path):

    ecosystems = detect_ecosystem(project_path)
    print(f"[*] Detected ecosystems: {', '.join(ecosystems)}")
    print("[*] Running dependency scan (VERSION-AWARE MODE)...")

    all_flat_dependencies = []

    # Initialize infra findings (IMPORTANT)
    docker_findings = []
    yaml_findings = []
    compose_findings = []

    # ---------------------------------------
    # Python ecosystem
    # ---------------------------------------
    if "python" in ecosystems:

        tree = run_pipdeptree(project_path)
        flat_dependencies = flatten_dependencies(tree)

        for dep in flat_dependencies:
            dep["ecosystem"] = "PYTHON"

        all_flat_dependencies.extend(flat_dependencies)

    # ---------------------------------------
    # Node ecosystem
    # ---------------------------------------
    if "node" in ecosystems:

        print("[*] Running Node dependency scan...")
        node_deps = scan_node_dependencies(project_path)

        for dep in node_deps:
            dep["ecosystem"] = "NODE"
            dep["depth"] = dep.get("depth", 1)

        all_flat_dependencies.extend(node_deps)

    # ---------------------------------------
    # Java ecosystem
    # ---------------------------------------
    if "java" in ecosystems:

        print("[*] Running Java dependency scan...")
        java_deps = scan_java_dependencies(project_path)

        for dep in java_deps:
            dep["ecosystem"] = "JAVA"
            dep["depth"] = 1

        all_flat_dependencies.extend(java_deps)

    # ---------------------------------------
    # Dockerfile ecosystem
    # ---------------------------------------
    if "docker" in ecosystems:
        docker_findings = scan_dockerfile(project_path)

    # ---------------------------------------
    # YAML + Docker Compose ecosystem
    # ---------------------------------------
    if "yaml" in ecosystems:
        yaml_findings = scan_yaml_iac(project_path)
        compose_findings = scan_docker_compose(project_path)
     
    # ---------------------------------------
    # Terraform ecosystem
    # ---------------------------------------
    terraform_findings = []

    if "terraform" in ecosystems:
        terraform_findings = scan_terraform(project_path)

    # ---------------------------------------
    # If no dependencies found
    # ---------------------------------------
    if not all_flat_dependencies:
        print("[!] No supported dependency ecosystem detected")
        return [], docker_findings, yaml_findings, compose_findings, terraform_findings

    # ---------------------------------------
    # NVD Matching
    # ---------------------------------------

    print("[*] Indexing NVD dataset into memory cache...")
    nvd_index = get_indexed_vulnerabilities()
    print(f"[+] Indexed {len(nvd_index)} products into memory cache\n")

    results = []

    for dep in all_flat_dependencies:

        name = normalize(dep["name"])
        version = dep.get("version", "")

        matched = []
        scores = []

        if name in nvd_index:
            for vuln in nvd_index[name]:

                if version_matches(
                        version,
                        vuln.get("version", "*"),
                        vuln.get("match_obj", {})):

                    matched.append(vuln["cve_id"])
                    scores.append(vuln["cvss"])

        highest = max(scores) if scores else 0
        avg = sum(scores) / len(scores) if scores else 0

        results.append({
            "name": name,
            "version": version,
            "dependency_type": "DIRECT"
            if dep.get("depth", 1) == 1 else "TRANSITIVE",
            "depth": dep.get("depth", 1),
            "ecosystem": dep.get("ecosystem", "UNKNOWN"),
            "cve_count": len(matched),
            "avg_cvss": round(avg, 2),
            "highest_cvss": highest,
            "severity": severity_from_cvss(highest)
        })

    # Remove duplicates
    unique = {}
    for dep in results:
        key = f"{dep['name']}:{dep['version']}"
        unique[key] = dep

    final_results = list(unique.values())

    print(f"[+] Found {len(final_results)} dependencies")

    return final_results, docker_findings, yaml_findings, compose_findings, terraform_findings