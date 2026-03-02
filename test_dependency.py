from scanner.dependency_scan import scan_dependencies

results = scan_dependencies(".")

for dep in results:
    print(dep)
