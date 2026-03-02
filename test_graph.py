from scanner.dependency_scan import scan_dependencies
from scanner.graph_builder import build_dependency_graph

project_path = r"C:\WINDOWS\system32\trivy-test\flask-realworld-example-app"

dependencies = scan_dependencies(project_path)

G, depth = build_dependency_graph(dependencies)

print("\n========== NODE DETAILS ==========")
for node, data in G.nodes(data=True):
    print(node, data)