"""
Security Log Anomaly Detection — Visualization Suite
=====================================================
Generates professional charts for the anomaly detection project.
Run this AFTER running anomaly_detector.py (which creates results/anomaly_report.json).

Author: Michael Kurdi
Tools: matplotlib, seaborn, json
"""

import os
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RESULTS_FILE = "results/anomaly_report.json"
OUTPUT_DIR = "screenshots"
DPI = 300
COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#D97706",
    "low": "#65A30D",
    "primary": "#2563EB",
    "bg": "#FAFAFA",
}

sns.set_theme(style="whitegrid", font_scale=1.1)
plt.rcParams["figure.facecolor"] = COLORS["bg"]
plt.rcParams["axes.facecolor"] = "#FFFFFF"
plt.rcParams["font.family"] = "sans-serif"


def load_results() -> dict:
    """Load anomaly report from JSON file."""
    if not os.path.exists(RESULTS_FILE):
        print(f"ERROR: {RESULTS_FILE} not found.")
        print("Run anomaly_detector.py first to generate the report.")
        raise SystemExit(1)

    with open(RESULTS_FILE, "r") as f:
        return json.load(f)


def chart_alerts_by_severity(results: dict) -> None:
    """Bar chart of alerts grouped by severity level."""
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_colors = [COLORS["critical"], COLORS["high"], COLORS["medium"], COLORS["low"]]
    breakdown = results.get("severity_breakdown", {})

    labels = [s for s in severity_order if s in breakdown]
    counts = [breakdown[s] for s in labels]
    colors = [severity_colors[severity_order.index(s)] for s in labels]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(labels, counts, color=colors, edgecolor="white", linewidth=1.5, width=0.55)

    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", va="bottom", fontweight="bold", fontsize=14)

    ax.set_ylabel("Number of Alerts", fontsize=12)
    ax.set_title("Alerts by Severity Level", fontsize=14, fontweight="bold", pad=15)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_ylim(0, max(counts) * 1.25 if counts else 10)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "alerts_by_severity.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  ✓ alerts_by_severity.png")


def chart_alerts_by_rule(results: dict) -> None:
    """Horizontal bar chart of alerts by detection rule."""
    breakdown = results.get("rule_breakdown", {})
    if not breakdown:
        print("  ⚠ No rule breakdown found, skipping.")
        return

    # Sort by count descending
    sorted_rules = sorted(breakdown.items(), key=lambda x: x[1])
    names = [r[0].replace("_", " ").title() for r in sorted_rules]
    counts = [r[1] for r in sorted_rules]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(names, counts, color=COLORS["primary"], edgecolor="white",
                   linewidth=1, height=0.55)

    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                str(val), ha="left", va="center", fontweight="bold", fontsize=11)

    ax.set_xlabel("Number of Alerts", fontsize=12)
    ax.set_title("Alerts by Detection Rule", fontsize=14, fontweight="bold", pad=15)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "alerts_by_rule.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  ✓ alerts_by_rule.png")


def chart_detection_summary(results: dict) -> None:
    """Donut chart comparing total events vs. detected anomalies."""
    total = results.get("total_events", 0)
    alerts = results.get("total_alerts", 0)
    normal = total - alerts

    fig, ax = plt.subplots(figsize=(6, 5))
    sizes = [normal, alerts]
    labels = [f"Normal\n({normal})", f"Alerts\n({alerts})"]
    colors = ["#10B981", COLORS["critical"]]

    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.1f%%",
        startangle=90, pctdistance=0.75,
        wedgeprops=dict(width=0.45, edgecolor="white", linewidth=3),
        textprops={"fontsize": 12},
    )
    for autotext in autotexts:
        autotext.set_fontweight("bold")
        autotext.set_fontsize(13)

    ax.text(0, 0, f"{total}\nEvents", ha="center", va="center",
            fontsize=16, fontweight="bold", color="#333")
    ax.set_title("Event Classification", fontsize=14, fontweight="bold", pad=15)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "detection_summary.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  ✓ detection_summary.png")


def chart_detection_rate(results: dict) -> None:
    """Gauge-style chart showing detection accuracy."""
    rate = results.get("detection_rate", 0)
    if rate is None:
        rate = 0

    fig, ax = plt.subplots(figsize=(6, 4))

    # Background bar
    ax.barh(["Detection Rate"], [100], color="#E5E7EB", height=0.5, edgecolor="white")
    # Filled bar
    color = "#10B981" if rate >= 90 else COLORS["medium"] if rate >= 70 else COLORS["critical"]
    ax.barh(["Detection Rate"], [rate], color=color, height=0.5, edgecolor="white")

    ax.text(rate / 2, 0, f"{rate:.1f}%", ha="center", va="center",
            fontsize=20, fontweight="bold", color="white")

    ax.set_xlim(0, 105)
    ax.set_title("Anomaly Detection Rate (vs. Ground Truth)", fontsize=14, fontweight="bold", pad=15)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.set_yticks([])
    ax.set_xlabel("Percentage", fontsize=12)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "detection_rate.png"), dpi=DPI, bbox_inches="tight")
    plt.close()
    print("  ✓ detection_rate.png")


def main():
    """Generate all visualization charts."""
    print("=" * 60)
    print("ANOMALY DETECTION — GENERATING VISUALIZATIONS")
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results = load_results()

    print(f"\n  Loaded results from {RESULTS_FILE}")
    print(f"  Output directory: {OUTPUT_DIR}/\n")

    chart_alerts_by_severity(results)
    chart_alerts_by_rule(results)
    chart_detection_summary(results)
    chart_detection_rate(results)

    print(f"\n  All charts saved to {OUTPUT_DIR}/ at {DPI} DPI.")
    print("\nAdd these to your README.md for professional documentation.")
    print("=" * 60)


if __name__ == "__main__":
    main()
