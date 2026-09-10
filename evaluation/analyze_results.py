import csv
from pathlib import Path

RESULTS_FILE = Path("evaluation/results.csv")

with open(RESULTS_FILE, "r", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))

conditions = {
    "A": "condition_a",
    "B": "condition_b",
    "C": "condition_c",
}

print("=" * 70)
print("FINAL HELD-OUT RESULTS ANALYSIS")
print("=" * 70)

print(f"\nCases evaluated: {len(rows)}")

for name, prefix in conditions.items():
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

    total = tp + tn + fp + fn

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
    accuracy = (tp + tn) / total if total else 0

    latency = sum(
        float(row[f"{prefix}_latency_ms"])
        for row in rows
    ) / total

    security_calls = sum(
        int(row[f"{prefix}_security_calls"])
        for row in rows
    )

    llm_calls = sum(
        int(row[f"{prefix}_llm_calls"])
        for row in rows
    )

    output_scans = sum(
        int(row[f"{prefix}_output_scans"])
        for row in rows
    )

    escalations = sum(
        int(row[f"{prefix}_escalations"])
        for row in rows
    )

    print(f"\n{'-' * 70}")
    print(f"CONDITION {name}")
    print(f"{'-' * 70}")

    print(f"TP: {tp}")
    print(f"TN: {tn}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")

    print(f"\nAccuracy:  {accuracy:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")
    print(f"FPR:       {fpr:.3f}")
    print(f"FNR:       {fnr:.3f}")
    print(f"ASR:       {asr:.3f}")

    print(f"\nAverage latency: {latency:.2f} ms")
    print(f"Security calls:  {security_calls}")
    print(f"LLM calls:       {llm_calls}")
    print(f"Output scans:    {output_scans}")
    print(f"Escalations:     {escalations}")
    print(f"Escalation rate: {escalations / total:.3f}")


# ---------------------------------------------------------
# B vs C efficiency comparison
# ---------------------------------------------------------

b_security = sum(int(r["condition_b_security_calls"]) for r in rows)
c_security = sum(int(r["condition_c_security_calls"]) for r in rows)

reduction = (
    (b_security - c_security) / b_security * 100
    if b_security
    else 0
)

b_latency = sum(float(r["condition_b_latency_ms"]) for r in rows) / len(rows)
c_latency = sum(float(r["condition_c_latency_ms"]) for r in rows) / len(rows)

latency_increase = (
    (c_latency - b_latency) / b_latency * 100
    if b_latency
    else 0
)

print("\n" + "=" * 70)
print("B vs C EFFICIENCY COMPARISON")
print("=" * 70)

print(f"\nSecurity calls:")
print(f"Always-On (B):       {b_security}")
print(f"SentinelLLM (C):     {c_security}")
print(f"Reduction:           {reduction:.2f}%")

print(f"\nAverage latency:")
print(f"Always-On (B):       {b_latency:.2f} ms")
print(f"SentinelLLM (C):     {c_latency:.2f} ms")
print(f"Increase:             {latency_increase:.2f}%")

print("\n" + "=" * 70)