from scanner.dependency_scan import scan_dependencies
from scanner.sbom import generate_sbom

print("[*] Running dependency scan...")
results = scan_dependencies(".")

print("[*] Generating SBOM...")
generate_sbom(results)
