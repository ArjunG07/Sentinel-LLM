RISK_DECAY = 0.70
CUMULATIVE_RISK_THRESHOLD = 0.70


def scan_output(output: str):
    """
    Scan an LLM response for likely sensitive-information leakage.

    The scanner looks for explicit disclosure patterns rather than
    blocking harmless discussion of security-related concepts.
    """

    output_lower = output.lower()
    matches = []

    leakage_patterns = [
        "the system prompt is",
        "system prompt:",
        "here is the system prompt",
        "here's the system prompt",

        "the developer instructions are",
        "developer instructions:",
        "here are the developer instructions",

        "the api key is",
        "api key:",
        "here is the api key",
        "here's the api key",

        "the secret key is",
        "secret key:",
        "here is the secret key",
        "here's the secret key",

        "the password is",
        "password:",
        "here is the password",
        "here's the password",

        "the user's password is",
        "the user password is",

        "confidential information:",
        "here is the confidential information",
        "contains confidential developer instructions",
        "confidential developer instructions",
        "contains an api key",
        "and an api key",
    ]

    for pattern in leakage_patterns:
        if pattern in output_lower:
            matches.append(pattern)

    detected = len(matches) > 0

    return {
        "decision": "BLOCK" if detected else "ALLOW",
        "detected": detected,
        "matches": matches,
    }


def calculate_cumulative_risk(
    current_risk: float,
    session_history: list = None
):
    """
    Calculate cumulative risk using decayed session history.
    """

    if session_history is None:
        session_history = []

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

    return {
        "historical_risk": historical_risk,
        "cumulative_risk": cumulative_risk,
    }


def tier3_scan(
    text: str,
    source: str = "user",
    current_risk: float = 0.0,
    session_history: list = None,
    tier2_result: dict = None,
    output: str = ""
):
    """
    Tier 3 security analysis.

    Tier 3 receives the risk already calculated by the routing layer
    and the result of Tier 2 security analysis.

    It does not rerun Tier 2 or the risk engine.
    """

    if session_history is None:
        session_history = []

    if tier2_result is None:
        tier2_result = {
            "decision": "ALLOW"
        }

    # -------------------------------------------------
    # STEP 1: Respect Tier 2 decision
    # -------------------------------------------------

    if tier2_result["decision"] == "BLOCK":
        return {
            "decision": "BLOCK",
            "tier2": tier2_result,
            "output_scan": None,
            "current_risk": current_risk,
            "historical_risk": 0.0,
            "cumulative_risk": 1.0,
        }

    # -------------------------------------------------
    # STEP 2: Calculate decayed cumulative risk
    # -------------------------------------------------

    risk_result = calculate_cumulative_risk(
        current_risk,
        session_history
    )

    historical_risk = risk_result["historical_risk"]
    cumulative_risk = risk_result["cumulative_risk"]

    # -------------------------------------------------
    # STEP 3: Cumulative risk decision
    # -------------------------------------------------

    if cumulative_risk >= CUMULATIVE_RISK_THRESHOLD:
        return {
            "decision": "BLOCK",
            "tier2": tier2_result,
            "output_scan": None,
            "current_risk": current_risk,
            "historical_risk": historical_risk,
            "cumulative_risk": cumulative_risk,
        }

    # -------------------------------------------------
    # STEP 4: Output security scan
    # -------------------------------------------------

    output_result = scan_output(output)

    if output_result["decision"] == "BLOCK":
        final_decision = "BLOCK"
    else:
        final_decision = "ALLOW"

    # -------------------------------------------------
    # STEP 5: Final result
    # -------------------------------------------------

    return {
        "decision": final_decision,
        "tier2": tier2_result,
        "output_scan": output_result,
        "current_risk": current_risk,
        "historical_risk": historical_risk,
        "cumulative_risk": cumulative_risk,
    }