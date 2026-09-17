from app.routing.risk import calculate_risk


TIER1_THRESHOLD = 0.30


# These terms do NOT automatically make a request malicious.
# They simply indicate that contextual analysis may be useful.
CONTEXTUAL_ESCALATION_PATTERNS = [
    "bypass authentication",
    "bypass login",
    "bypass a login",
    "bypass security",
    "bypass security controls",
    "bypass a security control",
    "security restriction",
    "security restrictions",
    "login restriction",
    "login restrictions",
    "authentication",
    "prompt injection",
    "attacker",
    "attackers",
]


def contextual_escalation_check(text: str) -> bool:
    """
    Detects security-related context that may require
    deeper analysis without assigning additional risk.
    """

    text_lower = text.lower()

    for pattern in CONTEXTUAL_ESCALATION_PATTERNS:
        if pattern in text_lower:
            return True

    return False


def tier1_scan(text: str, source: str = "user"):
    """
    Fast first-pass security scan.

    Tier 1 uses deterministic rules to calculate an initial
    risk score.

    Contextual escalation does NOT increase the risk score.
    It only allows the request to receive deeper LLM analysis.
    """

    risk_score = calculate_risk(text, source)

    contextual_escalation = contextual_escalation_check(text)

    if risk_score >= TIER1_THRESHOLD:
        decision = "ESCALATE"
        escalate = True

    elif contextual_escalation:
        decision = "ESCALATE"
        escalate = True

    else:
        decision = "ALLOW"
        escalate = False

    return {
        "tier": "TIER_1",
        "decision": decision,
        "escalate": escalate,
        "risk_score": risk_score,
        "threshold": TIER1_THRESHOLD,
        "contextual_escalation": contextual_escalation,
    }