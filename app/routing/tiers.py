def assign_tier(risk_score: float) -> str:

    if risk_score < 0.30:
        return "TIER_1"

    elif risk_score < 0.70:
        return "TIER_2"

    else:
        return "TIER_3"