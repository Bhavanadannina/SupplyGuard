import networkx as nx
import json
import os
from scanner.policy_loader import load_policy
from scanner.centrality_engine import compute_centrality_metrics


SEVERITY_WEIGHTS = {
    "CRITICAL": 3.0,
    "HIGH": 2.0,
    "MEDIUM": 1.2,
    "LOW": 0.5,
    "NONE": 0.0
}

TERRAFORM_RISK_WEIGHTS = {
    "0.0.0.0/0": 20,
    "publicly accessible": 25,
    "public": 15,
    "missing encryption": 10,
    "hardcoded": 30
}


def compute_project_risk(dependencies, secrets, terraform_findings=None, cloud_findings=None):

    policy = load_policy()

    block_cvss = policy.get("block_cvss", 9.0)
    block_cve_count = policy.get("block_cve_count", 5)
    block_severity = policy.get("block_severity", ["CRITICAL"])
    block_on_secrets = policy.get("block_on_secrets", False)

    dependency_count = len(dependencies)

    # Compute centrality only if dependencies exist
    centrality_scores = {}
    if dependency_count > 0:
        centrality_scores = compute_centrality_metrics(dependencies)

    # Secret-based hard blocking
    if block_on_secrets and secrets:
        return {
            "project_score": 100,
            "risk_level": "CRITICAL",
            "total_dependencies": dependency_count,
            "build_allowed": False,
            "centrality": centrality_scores
        }

    # Hard vulnerability blocking
    for dep in dependencies:

        highest_cvss = float(dep.get("highest_cvss", 0))
        severity = dep.get("severity", "NONE").upper()
        cve_count = int(dep.get("cve_count", 0))

        if highest_cvss >= block_cvss:
            return {
                "project_score": 95,
                "risk_level": "CRITICAL",
                "total_dependencies": dependency_count,
                "build_allowed": False,
                "centrality": centrality_scores
            }

        if cve_count >= block_cve_count:
            return {
                "project_score": 85,
                "risk_level": "HIGH",
                "total_dependencies": dependency_count,
                "build_allowed": False,
                "centrality": centrality_scores
            }

        if severity in block_severity:
            return {
                "project_score": 80,
                "risk_level": severity,
                "total_dependencies": dependency_count,
                "build_allowed": False,
                "centrality": centrality_scores
            }

    total_risk = 0

    # ==========================================
    # Dependency scoring with centrality factor
    # ==========================================
    for dep in dependencies:

        highest_cvss = float(dep.get("highest_cvss", 0))
        severity = dep.get("severity", "NONE").upper()
        name = dep.get("name")

        base_score = highest_cvss * 10
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)

        centrality_factor = 1
        if name in centrality_scores:
            centrality_factor += centrality_scores[name]["combined"]

        total_risk += base_score * weight * centrality_factor

    # ==========================================
    # Secret contribution
    # ==========================================
    if secrets:
        total_risk += 40

    # ==========================================
    # Cloud findings contribution
    # ==========================================
    if cloud_findings:
        for finding in cloud_findings:
            severity = finding.get("severity", "LOW")

            if severity == "CRITICAL":
                total_risk += 40
            elif severity == "HIGH":
                total_risk += 25
            elif severity == "MEDIUM":
                total_risk += 15
            else:
                total_risk += 5

    # ==========================================
    # Terraform findings contribution
    # ==========================================
    if terraform_findings:
        for finding in terraform_findings:
            for key, weight in TERRAFORM_RISK_WEIGHTS.items():
                if key.lower() in finding.lower():
                    total_risk += weight
                    break

    # ==========================================
    # Normalize score
    # ==========================================
    normalizer = max(1, dependency_count * 5)
    normalized_score = min(100, total_risk / normalizer)

    if normalized_score >= 75:
        level = "CRITICAL"
        allowed = False
    elif normalized_score >= 50:
        level = "HIGH"
        allowed = False
    elif normalized_score >= 30:
        level = "MEDIUM"
        allowed = True
    else:
        level = "LOW"
        allowed = True

    return {
        "project_score": round(normalized_score, 2),
        "risk_level": level,
        "total_dependencies": dependency_count,
        "build_allowed": allowed,
        "centrality": centrality_scores
    }