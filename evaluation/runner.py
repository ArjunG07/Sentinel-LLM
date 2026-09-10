import sys
from pathlib import Path
import csv

sys.path.append(str(Path(__file__).resolve().parent.parent))

from tests.test_condition_a import run_condition_a
from tests.test_condition_b import run_condition_b
from tests.test_condition_c import run_condition_c


RESULTS_FILE = Path("evaluation/results.csv")


def run_experiment(test_cases):
    results = []

    total_cases = len(test_cases)

    print("\n========================================")
    print("       SENTINELLLM RESEARCH EVALUATION")
    print("========================================")
    print(f"\nCases selected: {total_cases}")
    print("\nRunning A/B/C evaluation...")

    for index, case in enumerate(test_cases, start=1):

        case_id = case["id"]
        category = case["category"]
        subcategory = case["subcategory"]
        query = case["query"]
        expected = case["expected"]
        output_attack = case["output_attack"]
        rag_document = case["rag_document"]

        print("\n===================================")
        print(f"CASE {index}/{total_cases}: {case_id}")
        print("===================================")
        print("QUERY:", query)
        print("EXPECTED:", expected)

        # -------------------------
        # Condition A
        # -------------------------
        print("\nRunning Condition A...")
        result_a = run_condition_a(
            query,
            output_attack,
            rag_document
        )

        # -------------------------
        # Condition B
        # -------------------------
        print("\nRunning Condition B...")
        result_b = run_condition_b(
            query,
            output_attack,
            rag_document
        )

        # -------------------------
        # Condition C
        # -------------------------
        print("\nRunning Condition C...")
        result_c = run_condition_c(
            query,
            output_attack,
            rag_document
        )

        results.append({
            "case_id": case_id,
            "category": category,
            "subcategory": subcategory,
            "expected": expected,

            # Condition A
            "condition_a_decision": result_a["decision"],
            "condition_a_latency_ms": result_a["latency_ms"],
            "condition_a_security_calls": result_a["security_calls"],
            "condition_a_llm_calls": result_a["llm_calls"],
            "condition_a_output_scans": result_a["output_scans"],
            "condition_a_escalations": result_a["escalations"],

            # Condition B
            "condition_b_decision": result_b["decision"],
            "condition_b_latency_ms": result_b["latency_ms"],
            "condition_b_security_calls": result_b["security_calls"],
            "condition_b_llm_calls": result_b["llm_calls"],
            "condition_b_output_scans": result_b["output_scans"],
            "condition_b_escalations": result_b["escalations"],

            # Condition C
            "condition_c_decision": result_c["decision"],
            "condition_c_latency_ms": result_c["latency_ms"],
            "condition_c_security_calls": result_c["security_calls"],
            "condition_c_llm_calls": result_c["llm_calls"],
            "condition_c_output_scans": result_c["output_scans"],
            "condition_c_escalations": result_c["escalations"],
            "condition_c_tiers": ",".join(result_c["tiers"])
        })

        print(f"\nCompleted {index}/{total_cases}")

    save_results(results)

    print_summary(results)

    return results


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(results):

    RESULTS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "case_id",
        "category",
        "subcategory",
        "expected",

        "condition_a_decision",
        "condition_a_latency_ms",
        "condition_a_security_calls",
        "condition_a_llm_calls",
        "condition_a_output_scans",
        "condition_a_escalations",

        "condition_b_decision",
        "condition_b_latency_ms",
        "condition_b_security_calls",
        "condition_b_llm_calls",
        "condition_b_output_scans",
        "condition_b_escalations",

        "condition_c_decision",
        "condition_c_latency_ms",
        "condition_c_security_calls",
        "condition_c_llm_calls",
        "condition_c_output_scans",
        "condition_c_escalations",
        "condition_c_tiers"
    ]

    with open(
        RESULTS_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("\n===================================")
    print("RESULTS SAVED")
    print("===================================")
    print(RESULTS_FILE)


# ============================================================
# SUMMARY TABLE
# ============================================================

def print_summary(results):

    if not results:
        print("\nNo results to display.")
        return

    total = len(results)

    def average(key):
        values = [
            float(row[key])
            for row in results
        ]

        return sum(values) / len(values)

    def total_value(key):
        return sum(
            float(row[key])
            for row in results
        )

    # -------------------------
    # Decision statistics
    # -------------------------

    def attack_metrics(condition):

        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for row in results:

            expected = row["expected"].upper()
            decision = row[f"{condition}_decision"].upper()

            is_attack = expected in {
                "BLOCK",
                "MALICIOUS",
                "ATTACK",
                "1"
            }

            blocked = decision == "BLOCK"

            if is_attack and blocked:
                tp += 1

            elif is_attack and not blocked:
                fn += 1

            elif not is_attack and blocked:
                fp += 1

            else:
                tn += 1

        adr = tp / (tp + fn) if (tp + fn) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        fnr = fn / (tp + fn) if (tp + fn) else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = adr

        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0
        )

        asr = fn / (tp + fn) if (tp + fn) else 0

        return {
            "adr": adr,
            "fpr": fpr,
            "fnr": fnr,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "asr": asr
        }

    metrics_a = attack_metrics("condition_a")
    metrics_b = attack_metrics("condition_b")
    metrics_c = attack_metrics("condition_c")

    # -------------------------
    # Other statistics
    # -------------------------

    latency_a = average("condition_a_latency_ms")
    latency_b = average("condition_b_latency_ms")
    latency_c = average("condition_c_latency_ms")

    security_a = total_value("condition_a_security_calls")
    security_b = total_value("condition_b_security_calls")
    security_c = total_value("condition_c_security_calls")

    llm_a = total_value("condition_a_llm_calls")
    llm_b = total_value("condition_b_llm_calls")
    llm_c = total_value("condition_c_llm_calls")

    output_a = total_value("condition_a_output_scans")
    output_b = total_value("condition_b_output_scans")
    output_c = total_value("condition_c_output_scans")

    escalation_c = total_value("condition_c_escalations")

    escalation_rate_c = (
        escalation_c / total
        if total
        else 0
    )

    # -------------------------
    # Presentation table
    # -------------------------

    print("\n\n")
    print("==============================================================")
    print("                 SENTINELLLM RESULTS")
    print("==============================================================")
    print(f"Cases evaluated: {total}")
    print()

    print(
        f"{'Metric':<25}"
        f"{'A: No Security':>17}"
        f"{'B: Always-On':>17}"
        f"{'C: Adaptive':>17}"
    )

    print("-" * 76)

    rows = [
        ("Attack Detection Rate",
         metrics_a["adr"],
         metrics_b["adr"],
         metrics_c["adr"]),

        ("False Positive Rate",
         metrics_a["fpr"],
         metrics_b["fpr"],
         metrics_c["fpr"]),

        ("False Negative Rate",
         metrics_a["fnr"],
         metrics_b["fnr"],
         metrics_c["fnr"]),

        ("Precision",
         metrics_a["precision"],
         metrics_b["precision"],
         metrics_c["precision"]),

        ("Recall",
         metrics_a["recall"],
         metrics_b["recall"],
         metrics_c["recall"]),

        ("F1 Score",
         metrics_a["f1"],
         metrics_b["f1"],
         metrics_c["f1"]),

        ("Attack Success Rate",
         metrics_a["asr"],
         metrics_b["asr"],
         metrics_c["asr"]),

        ("Avg Latency (ms)",
         latency_a,
         latency_b,
         latency_c),

        ("Security Calls",
         security_a,
         security_b,
         security_c),

        ("LLM Calls",
         llm_a,
         llm_b,
         llm_c),

        ("Output Scans",
         output_a,
         output_b,
         output_c),

        ("Escalation Rate",
         None,
         None,
         escalation_rate_c)
    ]

    for name, a, b, c in rows:

        if name in {
            "Attack Detection Rate",
            "False Positive Rate",
            "False Negative Rate",
            "Precision",
            "Recall",
            "F1 Score",
            "Attack Success Rate",
            "Escalation Rate"
        }:

            a_text = "N/A" if a is None else f"{a * 100:.1f}%"
            b_text = "N/A" if b is None else f"{b * 100:.1f}%"
            c_text = "N/A" if c is None else f"{c * 100:.1f}%"

        elif name == "Avg Latency (ms)":

            a_text = f"{a:.1f}"
            b_text = f"{b:.1f}"
            c_text = f"{c:.1f}"

        else:

            a_text = f"{a:.0f}"
            b_text = f"{b:.0f}"
            c_text = f"{c:.0f}"

        print(
            f"{name:<25}"
            f"{a_text:>17}"
            f"{b_text:>17}"
            f"{c_text:>17}"
        )

    print("-" * 76)

    print("\nA = No Security")
    print("B = Always-On Security")
    print("C = SentinelLLM Adaptive Security")

    print("\n==============================================================")
    print("                 END OF EVALUATION")
    print("==============================================================\n")


# ============================================================
# LOAD DATASET
# ============================================================

if __name__ == "__main__":

    dataset_file = Path("evaluation/dataset_eval.csv")

    test_cases = []

    with open(
        dataset_file,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            test_cases.append({
                "id": row["case_id"],
                "category": row["category"],
                "subcategory": row["subcategory"],
                "query": row["query"],
                "expected": row["expected"],
                "output_attack": row["output_attack"],
                "rag_document": row["rag_document"] or ""
            })

    # Default: all cases
    run_experiment(test_cases)