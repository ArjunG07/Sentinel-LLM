import csv
from pathlib import Path
import matplotlib.pyplot as plt


RESULTS_FILE = Path("evaluation/results.csv")
OUTPUT_DIR = Path("evaluation/figures")
OUTPUT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------
# Load results
# ---------------------------------------------------------

with open(RESULTS_FILE, "r", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))


conditions = ["A", "B", "C"]
labels = [
    "No Security (A)",
    "Always-On (B)",
    "SentinelLLM (C)"
]


# ---------------------------------------------------------
# Calculate classification metrics
# ---------------------------------------------------------

metrics = {}

for condition in conditions:
    prefix = f"condition_{condition.lower()}"

    tp = tn = fp = fn = 0

    for row in rows:
        expected = row["expected"]
        decision = row[f"{prefix}_decision"]

        if expected == "BLOCK" and decision == "BLOCK":
            tp += 1
        elif expected == "ALLOW" and decision == "ALLOW":
            tn += 1
        elif expected == "ALLOW" and decision == "BLOCK":
            fp += 1
        elif expected == "BLOCK" and decision == "ALLOW":
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )
    fpr = fp / (fp + tn) if fp + tn else 0
    fnr = fn / (fn + tp) if fn + tp else 0
    asr = fn / (fn + tp) if fn + tp else 0

    metrics[condition] = {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "asr": asr,
    }


# ---------------------------------------------------------
# Figure 1 — Security Performance
# ---------------------------------------------------------

values = [
    [metrics[c]["precision"] for c in conditions],
    [metrics[c]["recall"] for c in conditions],
    [metrics[c]["f1"] for c in conditions],
]

metric_names = ["Precision", "Recall", "F1"]

x = range(len(conditions))
width = 0.25

plt.figure(figsize=(9, 6))

for i, metric_name in enumerate(metric_names):
    positions = [p + (i - 1) * width for p in x]
    plt.bar(
        positions,
        values[i],
        width,
        label=metric_name
    )

plt.xticks(list(x), labels)
plt.ylabel("Score")
plt.ylim(0, 1)
plt.title("Security Performance Across Evaluation Conditions")
plt.legend()
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "fig1_security_performance.png",
    dpi=300
)

plt.close()


# ---------------------------------------------------------
# Figure 2 — False Positive / False Negative / ASR
# ---------------------------------------------------------

values = [
    [metrics[c]["fpr"] * 100 for c in conditions],
    [metrics[c]["fnr"] * 100 for c in conditions],
    [metrics[c]["asr"] * 100 for c in conditions],
]

metric_names = ["FPR", "FNR", "ASR"]

plt.figure(figsize=(9, 6))

for i, metric_name in enumerate(metric_names):
    positions = [p + (i - 1) * width for p in x]

    bars = plt.bar(
        positions,
        values[i],
        width,
        label=metric_name
    )

    for bar, value in zip(bars, values[i]):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            value + 2,
            f"{value:.1f}%",
            ha="center",
            fontsize=10
        )

plt.xticks(list(x), labels)
plt.ylabel("Rate (%)")
plt.ylim(0, 110)
plt.title("False-Positive, False-Negative and Attack Success Rates")
plt.legend()
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "fig2_error_rates.png",
    dpi=300
)

plt.close()


# ---------------------------------------------------------
# Figure 3 — Security Analysis Calls
# ---------------------------------------------------------

security_calls = []

for condition in conditions:
    prefix = f"condition_{condition.lower()}"

    total = sum(
        int(row[f"{prefix}_security_calls"])
        for row in rows
    )

    security_calls.append(total)


plt.figure(figsize=(8, 6))

bars = plt.bar(labels, security_calls)

plt.ylabel("Number of Security Analysis Calls")
plt.title("Security Analysis Workload")
plt.xticks(rotation=10)

for bar, value in zip(bars, security_calls):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.5,
        str(value),
        ha="center"
    )

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "fig3_security_calls.png",
    dpi=300
)

plt.close()


# ---------------------------------------------------------
# Figure 4 — Average Latency
# ---------------------------------------------------------

latencies = []

for condition in conditions:
    prefix = f"condition_{condition.lower()}"

    average = sum(
        float(row[f"{prefix}_latency_ms"])
        for row in rows
    ) / len(rows)

    latencies.append(average / 1000)


plt.figure(figsize=(8, 6))

bars = plt.bar(labels, latencies)

plt.ylabel("Average Latency (seconds)")
plt.title("Average End-to-End Latency")
plt.xticks(rotation=10)

for bar, value in zip(bars, latencies):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.2,
        f"{value:.2f}s",
        ha="center"
    )

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "fig4_latency.png",
    dpi=300
)

plt.close()


# ---------------------------------------------------------
# Done
# ---------------------------------------------------------

print("=" * 60)
print("GRAPHS GENERATED")
print("=" * 60)

print(f"\nOutput directory: {OUTPUT_DIR}")

for file in sorted(OUTPUT_DIR.glob("*.png")):
    print(file)