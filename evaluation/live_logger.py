import csv
import os
from datetime import datetime


LIVE_DATASET = os.path.join(
    os.path.dirname(__file__),
    "live_dataset.csv"
)


FIELDS = [
    "test_id",
    "timestamp",
    "prompt",
    "source",
    "risk_score",
    "rule_risk",
    "llm_risk",
    "llm_category",
    "tier",
    "escalate",
    "final_decision",
    "latency_ms",
    "output_scan_decision",
    "ground_truth",
    "attack_type",
    "notes"
]


def log_live_case(result):
    """
    Save one completed SentinelLLM request as a live evaluation case.

    Ground truth is intentionally left blank and must be
    assigned after the collection session.
    """

    file_exists = os.path.exists(LIVE_DATASET)

    if file_exists:
        with open(LIVE_DATASET, "r", newline="", encoding="utf-8") as f:
            existing_rows = list(csv.reader(f))
            test_number = len(existing_rows)
    else:
        test_number = 1

    test_id = f"LIVE{test_number:03d}"

    user_analysis = result.get("user_analysis", {})
    output_scan = result.get("output_scan")

    row = {
        "test_id": test_id,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "prompt": result.get("query", ""),
        "source": "user",

        "risk_score": user_analysis.get("risk_score"),
        "rule_risk": user_analysis.get("rule_risk"),
        "llm_risk": user_analysis.get("llm_risk"),
        "llm_category": user_analysis.get("llm_category"),

        "tier": user_analysis.get("tier"),
        "escalate": user_analysis.get("escalate"),

        "final_decision": result.get("final_decision"),
        "latency_ms": round(result.get("latency_ms", 0), 2),

        "output_scan_decision": (
            output_scan.get("decision")
            if output_scan
            else None
        ),

        # Researcher labels these AFTER collection.
        "ground_truth": "",
        "attack_type": "",
        "notes": ""
    }

    with open(
        LIVE_DATASET,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=FIELDS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    return test_id