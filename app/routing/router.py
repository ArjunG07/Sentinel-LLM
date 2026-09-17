from app.security.tier1 import tier1_scan
from app.routing.tiers import assign_tier
from app.routing.trust import get_trust_level
from app.routing.llm_risk import analyze_risk


def route_request(
    text: str,
    source: str = "user"
):

    tier1 = tier1_scan(
        text,
        source
    )

    rule_risk = tier1["risk_score"]

    # --------------------------------------------------
    # LLM RISK ANALYSIS
    # --------------------------------------------------

    if not tier1["escalate"]:

        final_risk = rule_risk
        llm_result = None
        risk_analysis_used = False
        risk_llm_calls = 0

    else:

        llm_result = analyze_risk(
            text,
            source
        )

        llm_risk = llm_result["risk_score"]

        # Use the more conservative risk estimate.
        final_risk = max(
            rule_risk,
            llm_risk
        )

        risk_analysis_used = True

        risk_llm_calls = llm_result.get(
            "risk_llm_calls",
            1
        )

    # --------------------------------------------------
    # TIER ASSIGNMENT
    # --------------------------------------------------

    tier = assign_tier(
        final_risk
    )

    trust_level = get_trust_level(
        source
    )

    escalate = tier != "TIER_1"

    # --------------------------------------------------
    # REASON
    # --------------------------------------------------

    if tier == "TIER_1":

        reason = (
            "Low risk — Tier 1 is sufficient."
        )

    elif tier == "TIER_2":

        reason = (
            "Medium risk — additional "
            "security analysis required."
        )

    else:

        reason = (
            "High risk — maximum security "
            "analysis required."
        )

    if llm_result is not None:

        reason += (
            f" LLM classification: "
            f"{llm_result['category']}."
        )

    # --------------------------------------------------
    # RESULT
    # --------------------------------------------------

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

        "risk_analysis_used":
            risk_analysis_used,

        "risk_llm_calls":
            risk_llm_calls,

        "trust_level":
            trust_level,

        "tier":
            tier,

        "escalate":
            escalate,

        "reason":
            reason
    }