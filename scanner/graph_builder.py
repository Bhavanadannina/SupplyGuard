import networkx as nx


def build_dependency_graph(dependencies):

    G = nx.DiGraph()
    G.add_node("PROJECT_ROOT")

    for dep in dependencies:

        name = dep["name"]
        parent = dep["parent"]

        G.add_node(
            name,
            cve_count=dep["cve_count"],
            depth=dep["depth"],
            dependency_type=dep["dependency_type"]
        )

        if parent:
            G.add_edge(parent, name)
        else:
            G.add_edge("PROJECT_ROOT", name)

    return G