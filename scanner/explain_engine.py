import networkx as nx


def build_graph_from_dependencies(dependencies):

    G = nx.DiGraph()

    for dep in dependencies:
        name = dep["name"]
        parent = dep.get("parent")

        G.add_node(name)

        if parent:
            G.add_edge(parent, name)

    return G


def compute_centrality(G):

    if len(G.nodes) == 0:
        return {}, {}

    degree = nx.degree_centrality(G)
    betweenness = nx.betweenness_centrality(G)

    return degree, betweenness


def explain_risk(dependencies, project_risk):

    print("\n🔍 EXPLANATION ENGINE REPORT")
    print("====================================")

    if not dependencies:
        print("No dependencies detected.")
        print("Build blocked due to secrets or policy thresholds.")
        print("====================================\n")
        return

    # Highest CVSS dependency
    highest = max(dependencies, key=lambda d: float(d.get("highest_cvss", 0)))

    print(f"🚨 Highest Risk Dependency : {highest['name']}")
    print(f"   - CVSS : {highest['highest_cvss']}")
    print(f"   - Severity : {highest['severity']}")
    print(f"   - CVE Count : {highest['cve_count']}")

    print("\nPolicy Result:")
    print(f"   Risk Level : {project_risk['risk_level']}")
    print("====================================\n")

    
    centrality = project_risk.get("centrality", {})

    if centrality:
       print("\n📈 Centrality Impact:")
       for name, metrics in sorted(
           centrality.items(),
           key=lambda x: x[1]["combined"],
           reverse=True
       )[:3]:

            print(f"   - {name}")
            print(f"     Degree: {metrics['degree']}")
            print(f"     Betweenness: {metrics['betweenness']}")
            print(f"     Combined Score: {metrics['combined']}")