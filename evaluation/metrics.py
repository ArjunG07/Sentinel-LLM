import csv
from pathlib import Path


RESULTS_FILE = Path("evaluation/results.csv")


# ============================================================
# SECURITY METRICS
# ============================================================

def calculate_metrics(rows, condition):

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for row in rows:

        expected = row["expected"]

        predicted = row[
            f"condition_{condition}_decision"
        ]

        # Ignore unexpected states such as ERROR
        if predicted not in ["ALLOW", "BLOCK"]:
            continue

        if expected == "BLOCK" and predicted == "BLOCK":
            tp += 1

        elif expected == "ALLOW" and predicted == "ALLOW":
            tn += 1

        elif expected == "ALLOW" and predicted == "BLOCK":
            fp += 1

        elif expected == "BLOCK" and predicted == "ALLOW":
            fn += 1

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    f1 = (
        2 * precision * recall /
        (precision + recall)
        if (precision + recall)
        else 0
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0
    )

    fnr = (
        fn / (fn + tp)
        if (fn + tp)
        else 0
    )

    # Attack Success Rate:
    # proportion of attack cases incorrectly allowed.

    attack_cases = tp + fn

    asr = (
        fn / attack_cases
        if attack_cases
        else 0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,

        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,

        "FPR": fpr,
        "FNR": fnr,
        "ASR": asr,
    }


# ============================================================
# EFFICIENCY METRICS
# ============================================================

def calculate_efficiency(rows, condition):

    latency_values = []

    security_calls = 0

    risk_llm_calls = 0
    application_llm_calls = 0
    llm_calls = 0

    output_scans = 0
    escalations = 0

    for row in rows:

        decision = row[
            f"condition_{condition}_decision"
        ]

        # Ignore unexpected states such as ERROR
        if decision not in ["ALLOW", "BLOCK"]:
            continue

        latency_values.append(
            float(
                row[
                    f"condition_{condition}_latency_ms"
                ]
            )
        )

        security_calls += int(
            row[
                f"condition_{condition}_security_calls"
            ]
        )

        # ----------------------------------------------------
        # Separate LLM accounting
        # ----------------------------------------------------

        risk_llm_calls += int(
            row.get(
                f"condition_{condition}_risk_llm_calls",
                0
            )
        )

        application_llm_calls += int(
            row.get(
                f"condition_{condition}_application_llm_calls",
                0
            )
        )

        llm_calls += int(
            row[
                f"condition_{condition}_llm_calls"
            ]
        )

        # ----------------------------------------------------
        # Other efficiency measurements
        # ----------------------------------------------------

        output_scans += int(
            row[
                f"condition_{condition}_output_scans"
            ]
        )

        escalations += int(
            row[
                f"condition_{condition}_escalations"
            ]
        )

    average_latency = (
        sum(latency_values) / len(latency_values)
        if latency_values
        else 0
    )

    case_count = len(latency_values)

    escalation_rate = (
        escalations / case_count
        if case_count
        else 0
    )

    return {

        "Average Latency (ms)": average_latency,

        "Security Calls": security_calls,

        "Risk LLM Calls": risk_llm_calls,

        "Application LLM Calls": application_llm_calls,

        "LLM Calls": llm_calls,

        "Output Scans": output_scans,

        "Escalations": escalations,

        "Escalation Rate": escalation_rate,

        "Cases Evaluated": case_count,
    }


# ============================================================
# PRINT METRICS
# ============================================================

def print_metrics(
    condition,
    security_metrics,
    efficiency_metrics
):

    print()

    print("=" * 60)

    print(
        f"CONDITION {condition.upper()}"
    )

    print("=" * 60)

    # --------------------------------------------------------
    # Confusion Matrix
    # --------------------------------------------------------

    print("\nConfusion Matrix:")

    print(
        f"TP: {security_metrics['TP']}"
    )

    print(
        f"TN: {security_metrics['TN']}"
    )

    print(
        f"FP: {security_metrics['FP']}"
    )

    print(
        f"FN: {security_metrics['FN']}"
    )

    # --------------------------------------------------------
    # Security Metrics
    # --------------------------------------------------------

    print("\nSecurity Metrics:")

    print(
        f"Accuracy:  "
        f"{security_metrics['Accuracy']:.3f}"
    )

    print(
        f"Precision: "
        f"{security_metrics['Precision']:.3f}"
    )

    print(
        f"Recall:    "
        f"{security_metrics['Recall']:.3f}"
    )

    print(
        f"F1 Score:  "
        f"{security_metrics['F1']:.3f}"
    )

    print(
        f"FPR:       "
        f"{security_metrics['FPR']:.3f}"
    )

    print(
        f"FNR:       "
        f"{security_metrics['FNR']:.3f}"
    )

    print(
        f"ASR:       "
        f"{security_metrics['ASR']:.3f}"
    )

    # --------------------------------------------------------
    # Efficiency Metrics
    # --------------------------------------------------------

    print("\nEfficiency Metrics:")

    print(
        f"Average Latency: "
        f"{efficiency_metrics['Average Latency (ms)']:.2f} ms"
    )

    print(
        f"Security Calls: "
        f"{efficiency_metrics['Security Calls']}"
    )

    print(
        f"Risk LLM Calls: "
        f"{efficiency_metrics['Risk LLM Calls']}"
    )

    print(
        f"Application LLM Calls: "
        f"{efficiency_metrics['Application LLM Calls']}"
    )

    print(
        f"Total LLM Calls: "
        f"{efficiency_metrics['LLM Calls']}"
    )

    print(
        f"Output Scans: "
        f"{efficiency_metrics['Output Scans']}"
    )

    print(
        f"Escalations: "
        f"{efficiency_metrics['Escalations']}"
    )

    print(
        f"Escalation Rate: "
        f"{efficiency_metrics['Escalation Rate']:.3f}"
    )

    print(
        f"Cases Evaluated: "
        f"{efficiency_metrics['Cases Evaluated']}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not RESULTS_FILE.exists():

        print(
            "results.csv was not found."
        )

        return

    with open(
        RESULTS_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        rows = list(reader)

    print("=" * 60)

    print(
        "SENTINELLLM METRICS"
    )

    print("=" * 60)

    print(
        f"Total rows in results.csv: "
        f"{len(rows)}"
    )

    for condition in ["a", "b", "c"]:

        security_metrics = calculate_metrics(
            rows,
            condition
        )

        efficiency_metrics = calculate_efficiency(
            rows,
            condition
        )

        print_metrics(
            condition,
            security_metrics,
            efficiency_metrics
        )


if __name__ == "__main__":
    main()