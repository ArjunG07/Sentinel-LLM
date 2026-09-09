from app.routing.risk import calculate_risk
from app.routing.tiers import assign_tier
from app.routing.trust import get_trust_level


def route_request(text: str, source: str = "user"):
    # Fast rule-based risk assessment
    rule_risk = calculate_risk(text, source)

    # Tier assignment is based on the fast risk score
    final_risk = rule_risk

    tier = assign_tier(final_risk)

    # Get trust level of the source
    trust_level = get_trust_level(source)

    # Escalate whenever the request is above Tier 1
    escalate = tier != "TIER_1"

    if tier == "TIER_1":
        reason = "Low risk — Tier 1 is sufficient."
    elif tier == "TIER_2":
        reason = "Medium risk — additional security analysis required."
    else:
        reason = "High risk — maximum security analysis required."

    return {
        "risk_score": final_risk,
        "rule_risk": rule_risk,

        # Kept for compatibility with existing evaluation code.
        # LLM risk analysis is not used in the default router.
        "llm_risk": None,
        "risk_analysis_used": False,

        "trust_level": trust_level,
        "tier": tier,
        "escalate": escalate,
        "reason": reason
    }