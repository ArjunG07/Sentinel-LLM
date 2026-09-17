import sys
from pathlib import Path
import csv

sys.path.append(str(Path(__file__).resolve().parent.parent))

from tests.test_condition_a import run_condition_a
from tests.test_condition_b import run_condition_b
from tests.test_condition_c import run_condition_c

from evaluation.metrics import calculate_metrics, calculate_efficiency


RESULTS_FILE = Path("evaluation/results.csv")


# ============================================================
# SAFE CONDITION EXECUTION
# ============================================================

def run_condition_safely(
    condition_name,
    function,
    query,
    output_attack,
    rag_document
):
    """
    Run one experimental condition without allowing an
    exception to terminate the complete experiment.

    IMPORTANT:
    An exception is recorded as ERROR, never converted into
    ALLOW or BLOCK.
    """

    try:
        result = function(
            query,
            output_attack,
            rag_document
        )

        result["status"] = "OK"
        result["error"] = ""

        return result

    except Exception as error:

        print(
            f"\n!!! {condition_name} ERROR !!!"
        )

        print(
            type(error).__name__,
            ":",
            error
        )

        return {
            "decision": "ERROR",
            "response": None,
            "latency_ms": "",

            "security_calls": 0,

            "risk_llm_calls": 0,
            "application_llm_calls": 0,
            "llm_calls": 0,

            "output_scans": 0,
            "escalations": 0,
            "tiers": [],

            "user_risk": "",
            "max_document_risk": "",
            "cumulative_session_risk": "",

            "status": "ERROR",
            "error": f"{type(error).__name__}: {error}"
        }


# ============================================================
# RUN EXPERIMENT
# ============================================================

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

        # -----------------------------------------------------
        # CONDITION A
        # -----------------------------------------------------

        print("\nRunning Condition A...")

        result_a = run_condition_safely(
            "Condition A",
            run_condition_a,
            query,
            output_attack,
            rag_document
        )

        # -----------------------------------------------------
        # CONDITION B
        # -----------------------------------------------------

        print("\nRunning Condition B...")

        result_b = run_condition_safely(
            "Condition B",
            run_condition_b,
            query,
            output_attack,
            rag_document
        )

        # -----------------------------------------------------
        # CONDITION C
        # -----------------------------------------------------

        print("\nRunning Condition C...")

        result_c = run_condition_safely(
            "Condition C",
            run_condition_c,
            query,
            output_attack,
            rag_document
        )

        # -----------------------------------------------------
        # SAVE CASE
        # -----------------------------------------------------

        results.append({

            "case_id": case_id,
            "category": category,
            "subcategory": subcategory,
            "expected": expected,

            # =================================================
            # CONDITION A
            # =================================================

            "condition_a_status":
                result_a["status"],

            "condition_a_error":
                result_a["error"],

            "condition_a_decision":
                result_a["decision"],

            "condition_a_latency_ms":
                result_a["latency_ms"],

            "condition_a_security_calls":
                result_a["security_calls"],

            "condition_a_risk_llm_calls":
                result_a["risk_llm_calls"],

            "condition_a_application_llm_calls":
                result_a["application_llm_calls"],

            "condition_a_llm_calls":
                result_a["llm_calls"],

            "condition_a_output_scans":
                result_a["output_scans"],

            "condition_a_escalations":
                result_a["escalations"],

            # =================================================
            # CONDITION B
            # =================================================

            "condition_b_status":
                result_b["status"],

            "condition_b_error":
                result_b["error"],

            "condition_b_decision":
                result_b["decision"],

            "condition_b_latency_ms":
                result_b["latency_ms"],

            "condition_b_security_calls":
                result_b["security_calls"],

            "condition_b_risk_llm_calls":
                result_b["risk_llm_calls"],

            "condition_b_application_llm_calls":
                result_b["application_llm_calls"],

            "condition_b_llm_calls":
                result_b["llm_calls"],

            "condition_b_output_scans":
                result_b["output_scans"],

            "condition_b_escalations":
                result_b["escalations"],

            # =================================================
            # CONDITION C
            # =================================================

            "condition_c_status":
                result_c["status"],

            "condition_c_error":
                result_c["error"],

            "condition_c_decision":
                result_c["decision"],

            "condition_c_latency_ms":
                result_c["latency_ms"],

            "condition_c_security_calls":
                result_c["security_calls"],

            "condition_c_risk_llm_calls":
                result_c["risk_llm_calls"],

            "condition_c_application_llm_calls":
                result_c["application_llm_calls"],

            "condition_c_llm_calls":
                result_c["llm_calls"],

            "condition_c_output_scans":
                result_c["output_scans"],

            "condition_c_escalations":
                result_c["escalations"],

            "condition_c_tiers":
                ",".join(result_c["tiers"]),

            "condition_c_user_risk":
                result_c.get("user_risk", ""),

            "condition_c_max_document_risk":
                result_c.get("max_document_risk", ""),

            "condition_c_cumulative_session_risk":
                result_c.get(
                    "cumulative_session_risk",
                    ""
                )
        })

        print(f"\nCompleted {index}/{total_cases}")

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    save_results(results)

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

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

        # -----------------------------------------------------
        # Condition A
        # -----------------------------------------------------

        "condition_a_status",
        "condition_a_error",
        "condition_a_decision",
        "condition_a_latency_ms",
        "condition_a_security_calls",
        "condition_a_risk_llm_calls",
        "condition_a_application_llm_calls",
        "condition_a_llm_calls",
        "condition_a_output_scans",
        "condition_a_escalations",

        # -----------------------------------------------------
        # Condition B
        # -----------------------------------------------------

        "condition_b_status",
        "condition_b_error",
        "condition_b_decision",
        "condition_b_latency_ms",
        "condition_b_security_calls",
        "condition_b_risk_llm_calls",
        "condition_b_application_llm_calls",
        "condition_b_llm_calls",
        "condition_b_output_scans",
        "condition_b_escalations",

        # -----------------------------------------------------
        # Condition C
        # -----------------------------------------------------

        "condition_c_status",
        "condition_c_error",
        "condition_c_decision",
        "condition_c_latency_ms",
        "condition_c_security_calls",
        "condition_c_risk_llm_calls",
        "condition_c_application_llm_calls",
        "condition_c_llm_calls",
        "condition_c_output_scans",
        "condition_c_escalations",
        "condition_c_tiers",
        "condition_c_user_risk",
        "condition_c_max_document_risk",
        "condition_c_cumulative_session_risk"
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
# SUMMARY
# ============================================================

def print_summary(results):

    if not results:
        print("\nNo results to display.")
        return

    print("\n\n")
    print("==============================================================")
    print("                 SENTINELLLM RESULTS")
    print("==============================================================")

    print(f"Cases attempted: {len(results)}")

    # ---------------------------------------------------------
    # Error counts
    # ---------------------------------------------------------

    for condition in [
        "condition_a",
        "condition_b",
        "condition_c"
    ]:

        successful = sum(
            row[f"{condition}_status"] == "OK"
            for row in results
        )

        failed = sum(
            row[f"{condition}_status"] == "ERROR"
            for row in results
        )

        print(
            f"{condition}: "
            f"{successful} successful, "
            f"{failed} errors"
        )

    print()

    # ---------------------------------------------------------
    # Calculate metrics
    # ---------------------------------------------------------

    metrics_a = calculate_metrics(
        results,
        "a"
    )

    metrics_b = calculate_metrics(
        results,
        "b"
    )

    metrics_c = calculate_metrics(
        results,
        "c"
    )

    efficiency_a = calculate_efficiency(
        results,
        "a"
    )

    efficiency_b = calculate_efficiency(
        results,
        "b"
    )

    efficiency_c = calculate_efficiency(
        results,
        "c"
    )

    # ---------------------------------------------------------
    # Presentation table
    # ---------------------------------------------------------

    print("==============================================================")

    print(
        f"{'Metric':<25}"
        f"{'A: No Security':>17}"
        f"{'B: Always-On':>17}"
        f"{'C: Adaptive':>17}"
    )

    print("-" * 76)

    table_rows = [

        (
            "Attack Detection Rate",
            metrics_a["Recall"],
            metrics_b["Recall"],
            metrics_c["Recall"]
        ),

        (
            "False Positive Rate",
            metrics_a["FPR"],
            metrics_b["FPR"],
            metrics_c["FPR"]
        ),

        (
            "False Negative Rate",
            metrics_a["FNR"],
            metrics_b["FNR"],
            metrics_c["FNR"]
        ),

        (
            "Precision",
            metrics_a["Precision"],
            metrics_b["Precision"],
            metrics_c["Precision"]
        ),

        (
            "Recall",
            metrics_a["Recall"],
            metrics_b["Recall"],
            metrics_c["Recall"]
        ),

        (
            "F1 Score",
            metrics_a["F1"],
            metrics_b["F1"],
            metrics_c["F1"]
        ),

        (
            "Attack Success Rate",
            metrics_a["ASR"],
            metrics_b["ASR"],
            metrics_c["ASR"]
        ),

        (
            "Avg Latency (ms)",
            efficiency_a["Average Latency (ms)"],
            efficiency_b["Average Latency (ms)"],
            efficiency_c["Average Latency (ms)"]
        ),

        (
            "Security Calls",
            efficiency_a["Security Calls"],
            efficiency_b["Security Calls"],
            efficiency_c["Security Calls"]
        ),

        (
            "Risk LLM Calls",
            efficiency_a.get("Risk LLM Calls", 0),
            efficiency_b.get("Risk LLM Calls", 0),
            efficiency_c.get("Risk LLM Calls", 0)
        ),

        (
            "Application LLM Calls",
            efficiency_a.get("Application LLM Calls", 0),
            efficiency_b.get("Application LLM Calls", 0),
            efficiency_c.get("Application LLM Calls", 0)
        ),

        (
            "Total LLM Calls",
            efficiency_a["LLM Calls"],
            efficiency_b["LLM Calls"],
            efficiency_c["LLM Calls"]
        ),

        (
            "Output Scans",
            efficiency_a["Output Scans"],
            efficiency_b["Output Scans"],
            efficiency_c["Output Scans"]
        ),

        (
            "Escalation Rate",
            None,
            None,
            efficiency_c["Escalation Rate"]
        )
    ]

    for name, a, b, c in table_rows:

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

            a_text = (
                "N/A"
                if a is None
                else f"{a * 100:.1f}%"
            )

            b_text = (
                "N/A"
                if b is None
                else f"{b * 100:.1f}%"
            )

            c_text = (
                "N/A"
                if c is None
                else f"{c * 100:.1f}%"
            )

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

    dataset_file = Path(
        "evaluation/dataset_eval.csv"
    )

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