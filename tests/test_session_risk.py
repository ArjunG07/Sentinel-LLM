import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.security.tier3 import calculate_cumulative_risk


def test_cumulative_risk():

    session_history = []

    print("\n===================================")
    print(" SENTINELLLM SESSION RISK TEST")
    print("===================================")

    # Request 1
    current_risk = 0.40

    result_1 = calculate_cumulative_risk(
        current_risk,
        session_history
    )

    print("\nRequest 1")
    print("Current risk:", current_risk)
    print("Historical risk:", result_1["historical_risk"])
    print("Cumulative risk:", result_1["cumulative_risk"])

    session_history.append(current_risk)

    # Request 2
    current_risk = 0.40

    result_2 = calculate_cumulative_risk(
        current_risk,
        session_history
    )

    print("\nRequest 2")
    print("Current risk:", current_risk)
    print("Historical risk:", result_2["historical_risk"])
    print("Cumulative risk:", result_2["cumulative_risk"])

    session_history.append(current_risk)

    # Request 3
    current_risk = 0.40

    result_3 = calculate_cumulative_risk(
        current_risk,
        session_history
    )

    print("\nRequest 3")
    print("Current risk:", current_risk)
    print("Historical risk:", result_3["historical_risk"])
    print("Cumulative risk:", result_3["cumulative_risk"])

    session_history.append(current_risk)

    print("\nFinal session history:", session_history)


if __name__ == "__main__":
    test_cumulative_risk()