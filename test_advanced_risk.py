from scanner.dependency_scan import scan_dependencies
from scanner.graph_builder import build_dependency_graph
from scanner.risk_propagation import compute_project_risk

project_path = r"C:\WINDOWS\system32\trivy-test\flask-realworld-example-app"

deps = scan_dependencies(project_path)
G, depth = build_dependency_graph(deps)

result = compute_project_risk(G)

print("\n===== ADVANCED SYSTEMIC RISK RESULT =====")
print(result)