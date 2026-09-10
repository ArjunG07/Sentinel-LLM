import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
import csv
from pathlib import Path

from tests.test_condition_a import run_condition_a
from tests.test_condition_b import run_condition_b
from tests.test_condition_c import run_condition_c


RESULTS_FILE = Path("evaluation/results.csv")


def run_experiment(test_cases):
    results = []

    for case in test_cases:
        case_id = case["id"]
        category = case["category"]
        subcategory = case["subcategory"]
        query = case["query"]
        expected = case["expected"]
        output_attack = case["output_attack"]
        rag_document = case["rag_document"]
        print("\n===================================")
        print("TEST CASE:", case_id)
        print("===================================")
        print("QUERY:", query)
        print("EXPECTED:", expected)

        # Condition A
        print("\nRunning Condition A...")
        result_a = run_condition_a(query, output_attack, rag_document)

        # Condition B
        print("\nRunning Condition B...")
        result_b = run_condition_b(query, output_attack, rag_document)

        # Condition C
        print("\nRunning Condition C...")
        result_c = run_condition_c(query, output_attack, rag_document)

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

    save_results(results)

    return results


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

run_experiment(test_cases)