import matplotlib.pyplot as plt
import numpy as np
from scanner.dependency_scan import scan_dependencies
from matplotlib.patches import Patch


def show_risk_heatmap(dependencies):

    if not dependencies:
        print("No dependencies to visualize.")
        return

    # Sort by CVSS descending
    dependencies = sorted(
        dependencies,
        key=lambda x: float(x.get("highest_cvss", 0)),
        reverse=True
    )

    names = [d["name"] for d in dependencies]
    scores = [float(d.get("highest_cvss", 0)) for d in dependencies]

    colors = []

    for score in scores:
        if score >= 9:
            colors.append("#b10026")  # Deep Red - CRITICAL
        elif score >= 7:
            colors.append("#fc4e2a")  # Orange-Red - HIGH
        elif score >= 4:
            colors.append("#feb24c")  # Amber - MEDIUM
        elif score > 0:
            colors.append("#ffeda0")  # Light Yellow - LOW
        else:
            colors.append("#d9d9d9")  # Grey - No CVEs

    plt.figure(figsize=(13, 8))

    bars = plt.barh(names, scores, color=colors)

    plt.xlabel("CVSS Score (0 - 10)")
    plt.title("SupplyGuard Dependency Risk Heatmap", fontsize=14, weight="bold")

    plt.xlim(0, 10)
    plt.gca().invert_yaxis()

    # Add numeric labels
    for bar, score in zip(bars, scores):
        plt.text(
            bar.get_width() + 0.2,
            bar.get_y() + bar.get_height() / 2,
            f"{score}",
            va='center',
            fontsize=8
        )

    # -------------------------------------------------
    # PROFESSIONAL LEGEND (Conference Style)
    # -------------------------------------------------

    legend_elements = [
        Patch(facecolor="#b10026", label="CRITICAL (CVSS 9.0 - 10.0)"),
        Patch(facecolor="#fc4e2a", label="HIGH (CVSS 7.0 - 8.9)"),
        Patch(facecolor="#feb24c", label="MEDIUM (CVSS 4.0 - 6.9)"),
        Patch(facecolor="#ffeda0", label="LOW (CVSS 0.1 - 3.9)"),
        Patch(facecolor="#d9d9d9", label="No Known CVEs")
    ]

    plt.legend(
        handles=legend_elements,
        title="Risk Severity",
        loc="lower right",
        fontsize=9
    )

    plt.tight_layout()
    plt.savefig("risk_heatmap.png", dpi=300)
    plt.close()

    print("[+] Conference-grade risk_heatmap.png generated")