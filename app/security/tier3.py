from app.security.tier2 import tier2_scan
from app.routing.risk import calculate_risk


# Maximum amount of previous risk retained from one turn to the next.
RISK_DECAY = 0.70

# Cumulative risk required to trigger a Tier 3 block.
CUMULATIVE_RISK_THRESHOLD = 0.70


def scan_output(output: str):
    suspicious_output_patterns = [
        "system prompt",
        "developer instructions",
        "secret key",
        "api key",
        "password",
        "confidential"
    ]

    output_lower = output.lower()

    matches = []

    for pattern in suspicious_output_patterns:
        if pattern in output_lower:
            matches.append(pattern)

    detected = len(matches) > 0

    if detected:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "detected": detected,
        "matches": matches
    }


def tier3_scan(
    text: str,
    source: str = "user",
    output: str = "",
    session_history: list = None
):
    if session_history is None:
        session_history = []

    # -------------------------------------------------
    # CURRENT TURN RISK
    # -------------------------------------------------

    current_risk = calculate_risk(
        text,
        source
    )

    # -------------------------------------------------
    # TIER 2 SECURITY ANALYSIS
    # -------------------------------------------------

    tier2_result = tier2_scan(
        text,
        source
    )

    # Definite attacks are blocked immediately.
    if tier2_result["decision"] == "BLOCK":
        return {
            "decision": "BLOCK",
            "tier2": tier2_result,
            "output_scan": None,
            "current_risk": current_risk,
            "cumulative_risk": 1.0
        }

    # -------------------------------------------------
    # DECAYED CUMULATIVE RISK
    # -------------------------------------------------

    historical_risk = 0.0

    for index, previous_risk in enumerate(
        reversed(session_history)
    ):
        historical_risk += previous_risk * (
            RISK_DECAY ** (index + 1)
        )

    cumulative_risk = min(
        current_risk + historical_risk,
        1.0
    )

    # -------------------------------------------------
    # CUMULATIVE RISK DECISION
    # -------------------------------------------------

    if cumulative_risk >= CUMULATIVE_RISK_THRESHOLD:
        return {
            "decision": "BLOCK",
            "tier2": tier2_result,
            "output_scan": None,
            "current_risk": current_risk,
            "cumulative_risk": cumulative_risk
        }

    # -------------------------------------------------
    # OUTPUT SECURITY SCAN
    # -------------------------------------------------

    output_result = scan_output(output)

    if output_result["decision"] == "BLOCK":
        final_decision = "BLOCK"
    else:
        final_decision = "ALLOW"

    # -------------------------------------------------
    # FINAL RESULT
    # -------------------------------------------------

    return {
        "decision": final_decision,
        "tier2": tier2_result,
        "output_scan": output_result,
        "current_risk": current_risk,
        "cumulative_risk": cumulative_risk
    }