import networkx as nx


def compute_centrality_metrics(dependencies):

    G = nx.DiGraph()

    # Build simple graph: direct vs transitive
    for dep in dependencies:

        name = dep["name"]
        G.add_node(name)

        if dep.get("dependency_type") == "TRANSITIVE":
            # connect transitive to a synthetic root
            G.add_edge("ROOT", name)
        else:
            G.add_edge("ROOT", name)

    if len(G.nodes) <= 1:
        return {}

    degree = nx.degree_centrality(G)
    between = nx.betweenness_centrality(G)

    centrality_scores = {}

    for node in G.nodes:
        if node == "ROOT":
            continue

        centrality_scores[node] = {
            "degree": round(degree.get(node, 0), 3),
            "betweenness": round(between.get(node, 0), 3),
            "combined": round(
                (degree.get(node, 0) * 0.7) +
                (between.get(node, 0) * 0.3), 3
            )
        }

    return centrality_scores