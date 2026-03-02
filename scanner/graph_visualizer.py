import os
import subprocess
import json
import networkx as nx
import matplotlib.pyplot as plt
import math
from matplotlib.patches import Patch
import plotly.graph_objects as go


def show_dependency_graph(project_path):

    from scanner.dependency_scan import scan_dependencies
    dependencies, _, _, _, _ = scan_dependencies(project_path)

    G = nx.DiGraph()
    root = "PROJECT"

    G.add_node(root, level=0)

    # ----------------------------
    # Build Graph with Levels
    # ----------------------------

    for dep in dependencies:
        name = dep["name"]

        if dep.get("is_direct", True):
            G.add_node(name, level=1)
            G.add_edge(root, name)
        else:
            G.add_node(name, level=2)

        for child in dep.get("dependencies", []):
            G.add_node(child, level=2)
            G.add_edge(name, child)

    # ----------------------------
    # Position Nodes by Level
    # ----------------------------

    pos = {}

    levels = {0: [], 1: [], 2: []}

    for node, data in G.nodes(data=True):
        level = data.get("level", 1)
        levels[level].append(node)

    for level, nodes in levels.items():
        y = -level * 2
        x_spacing = 2
        start_x = - (len(nodes) - 1) * x_spacing / 2

        for i, node in enumerate(nodes):
            pos[node] = (start_x + i * x_spacing, y)

    # ----------------------------
    # Edges
    # ----------------------------

    edge_x = []
    edge_y = []

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]

        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=2, color="#444"),
        hoverinfo='none',
        mode='lines'
    )

    # ----------------------------
    # Nodes
    # ----------------------------

    node_x = []
    node_y = []
    node_color = []
    node_text = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        if node == root:
            node_color.append("#1f77b4")
            node_text.append("PROJECT ROOT")
            continue

        dep_data = next((d for d in dependencies if d["name"] == node), None)
        score = float(dep_data.get("highest_cvss", 0)) if dep_data else 0
        cve_count = dep_data.get("cve_count", 0) if dep_data else 0

        node_text.append(
            f"{node}<br>CVSS: {score}<br>CVEs: {cve_count}"
        )

        if score >= 9:
            node_color.append("#d62728")  # Critical
        elif score >= 7:
            node_color.append("#ff7f0e")  # High
        elif score >= 4:
            node_color.append("#ffbb78")  # Medium
        else:
            node_color.append("#2ca02c")  # Low

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        text=[n for n in G.nodes()],
        textposition="bottom center",
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=45,
            color=node_color,
            line=dict(width=2, color='black')
        )
    )

    # ----------------------------
    # Legend
    # ----------------------------

    legend_items = [
        dict(color="#1f77b4", label="Project Root"),
        dict(color="#d62728", label="Critical (CVSS ≥ 9)"),
        dict(color="#ff7f0e", label="High (7–8.9)"),
        dict(color="#ffbb78", label="Medium (4–6.9)"),
        dict(color="#2ca02c", label="Low (<4)")
    ]

    legend_traces = []

    for item in legend_items:
        legend_traces.append(
            go.Scatter(
                x=[None],
                y=[None],
                mode='markers',
                marker=dict(size=15, color=item["color"]),
                legendgroup=item["label"],
                showlegend=True,
                name=item["label"]
            )
        )

    # ----------------------------
    # Final Figure
    # ----------------------------

    fig = go.Figure(data=[edge_trace, node_trace] + legend_traces)

    fig.update_layout(
        title="SupplyGuard Dependency Architecture",
        showlegend=True,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )

    fig.show()