from app.routing.risk import calculate_risk
from app.routing.tiers import assign_tier
from app.routing.trust import get_trust_level
from app.routing.llm_risk import analyze_risk


def route_request(text: str, source: str = "user"):
    # --------------------------------------------------
    # STEP 1: Fast rule-based scan
    # --------------------------------------------------
    rule_risk = calculate_risk(text, source)

    # --------------------------------------------------
    # STEP 2: If clearly low risk, stay at Tier 1
    # --------------------------------------------------
    if rule_risk < 0.30:
        final_risk = rule_risk
        llm_result = None
        risk_analysis_used = False

    # --------------------------------------------------
    # STEP 3: Suspicious query -> ask the LLM
    # --------------------------------------------------
    else:
        llm_result = analyze_risk(text, source)

        final_risk = llm_result["risk_score"]
        risk_analysis_used = True

    # --------------------------------------------------
    # STEP 4: Assign security tier
    # --------------------------------------------------
    tier = assign_tier(final_risk)

    # --------------------------------------------------
    # STEP 5: Trust level
    # --------------------------------------------------
    trust_level = get_trust_level(source)

    # --------------------------------------------------
    # STEP 6: Escalation
    # --------------------------------------------------
    escalate = tier != "TIER_1"

    # --------------------------------------------------
    # STEP 7: Explanation
    # --------------------------------------------------
    if tier == "TIER_1":
        reason = "Low risk — Tier 1 is sufficient."

    elif tier == "TIER_2":
        reason = "Medium risk — additional security analysis required."

    else:
        reason = "High risk — maximum security analysis required."

    # Add LLM explanation when it was used
    if llm_result is not None:
        reason += f" LLM classification: {llm_result['category']}."

    return {
        "risk_score": final_risk,
        "rule_risk": rule_risk,

        "llm_risk": (
            llm_result["risk_score"]
            if llm_result is not None
            else None
        ),

        "llm_category": (
            llm_result["category"]
            if llm_result is not None
            else None
        ),

        "llm_reason": (
            llm_result["reason"]
            if llm_result is not None
            else None
        ),

        "risk_analysis_used": risk_analysis_used,

        "trust_level": trust_level,

        "tier": tier,

        "escalate": escalate,

        "reason": reason
    }