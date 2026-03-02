import math
import networkx as nx


# Severity Weights (NEW)
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "NONE": 0
}


def compute_node_risk(G):
    """
    Compute advanced systemic risk for each node.
    Now CVSS-aware and severity-weighted.
    """

    centrality = nx.degree_centrality(G)
    node_scores = {}

    for node in G.nodes():

        if node == "PROJECT_ROOT":
            continue

        data = G.nodes[node]

        cve_count = data.get("cve_count", 0)
        highest_cvss = float(data.get("highest_cvss", 0))
        severity = data.get("highest_severity", "NONE")
        depth = data.get("depth", 1)
        dep_type = data.get("dependency_type", "DIRECT")

        # 1️⃣ Base CVE risk (log dampened)
        base_risk = math.log1p(cve_count) * 20

        # 2️⃣ CVSS weight boost (NEW)
        severity_weight = SEVERITY_WEIGHTS.get(severity, 0)
        cvss_boost = highest_cvss * 2

        # 3️⃣ Depth factor (closer = more impact)
        depth_factor = 1.5 if depth == 1 else 1.0

        # 4️⃣ Centrality impact
        centrality_factor = centrality.get(node, 0) * 40

        # 5️⃣ Transitive penalty
        transitive_penalty = 10 if dep_type == "TRANSITIVE" else 0

        risk_score = (
            (base_risk + cvss_boost + severity_weight)
            * depth_factor
            + centrality_factor
            + transitive_penalty
        )

        node_scores[node] = round(risk_score, 2)

    return node_scores


def propagate_risk(G, node_scores):
    """
    Propagate risk upward through the graph.
    """

    propagated = node_scores.copy()

    for node in reversed(list(nx.topological_sort(G))):

        parents = list(G.predecessors(node))

        for parent in parents:
            if parent == "PROJECT_ROOT":
                continue

            propagated[parent] += propagated[node] * 0.4

    return propagated


def compute_project_risk(G):
    """
    Full systemic project risk computation.
    """

    node_scores = compute_node_risk(G)
    propagated_scores = propagate_risk(G, node_scores)

    total_risk = sum(propagated_scores.values())

    normalized_score = min(100, total_risk / 8)

    # Hard override if CRITICAL exists
    has_critical = any(
        data.get("highest_severity") == "CRITICAL"
        for node, data in G.nodes(data=True)
        if node != "PROJECT_ROOT"
    )

    if has_critical:
        level = "CRITICAL"
        decision = "BLOCK"

    elif normalized_score >= 70:
        level = "HIGH"
        decision = "BLOCK"

    elif normalized_score >= 40:
        level = "MEDIUM"
        decision = "REVIEW"

    else:
        level = "LOW"
        decision = "ALLOW"

    return {
        "project_score": round(normalized_score, 2),
        "risk_level": level,
        "decision": decision,
        "total_nodes": len(node_scores),
    }