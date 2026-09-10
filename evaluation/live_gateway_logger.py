import csv
import os
from datetime import datetime


LOG_FILE = os.path.join(
    "evaluation",
    "live_gateway_results.csv"
)


def log_gateway_case(data: dict):
    file_exists = os.path.exists(LOG_FILE)

    fields = [
        "timestamp",
        "prompt",
        "current_risk",
        "historical_risk",
        "cumulative_risk",
        "initial_tier",
        "effective_tier",
        "security_decision",
        "qwen_called",
        "output_scan_decision",
        "final_decision",
        "latency_ms",
    ]

    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
            **data
        })

    return LOG_FILE