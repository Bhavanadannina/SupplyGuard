from scanner.dependency_scan import scan_dependencies
from scanner.risk_score import calculate_project_risk

print("[*] Running dependency scan...")
results = scan_dependencies(".")

print("[*] Calculating project risk...")
project_risk = calculate_project_risk(results)

print("\n=== PROJECT RISK SUMMARY ===")
for k, v in project_risk.items():
    print(f"{k}: {v}")
