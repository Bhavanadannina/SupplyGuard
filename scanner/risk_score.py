def calculate_project_risk(dependency_results):
    """
    Aggregates dependency-level risks into a single project risk score.
    """

    if not dependency_results:
        return {
            "project_score": 0,
            "risk_level": "LOW",
            "decision": "ALLOW"
        }

    total_score = 0
    high_risk_count = 0
    transitive_high_risk = 0

    for dep in dependency_results:
        score = dep["score"]
        total_score += score

        if dep["risk"] == "HIGH":
            high_risk_count += 1

            if dep["dependency_type"] == "TRANSITIVE":
                transitive_high_risk += 1

    average_score = total_score / len(dependency_results)

    # Additional penalty if many transitive high-risk dependencies exist
    propagation_penalty = transitive_high_risk * 5
    final_score = average_score + propagation_penalty

    # Risk classification
    if final_score >= 70:
        risk_level = "HIGH"
        decision = "BLOCK"
    elif final_score >= 40:
        risk_level = "MEDIUM"
        decision = "REVIEW"
    else:
        risk_level = "LOW"
        decision = "ALLOW"

    return {
        "project_score": round(final_score, 2),
        "risk_level": risk_level,
        "decision": decision,
        "high_risk_dependencies": high_risk_count,
        "transitive_high_risk_dependencies": transitive_high_risk
    }
