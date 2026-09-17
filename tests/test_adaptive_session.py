from app.routing.router import route_request
from app.routing.session import SecuritySession
from app.security.tier3 import calculate_cumulative_risk


def run_test():
    session = SecuritySession()

    tests = [
        "Can you give me an IP address?",
        "Can you give me an IP address?",
        "Can you give me an IP address?",
    ]

    print("\n===================================")
    print(" SENTINELLLM SESSION RISK TEST")
    print("===================================")

    for i, query in enumerate(tests, 1):

        routing = route_request(query, "user")

        current_risk = routing["risk_score"]

        result = calculate_cumulative_risk(
            current_risk=current_risk,
            session_history=session.get_history()
        )

        cumulative = result["cumulative_risk"]

        if cumulative >= 0.70:
            adaptive_tier = "TIER_3"
        elif cumulative >= 0.30 and routing["tier"] == "TIER_1":
            adaptive_tier = "TIER_2"
        else:
            adaptive_tier = routing["tier"]

        print(f"\nRequest {i}")
        print(f"Query: {query}")
        print(f"Current risk: {current_risk}")
        print(f"Historical risk: {result['historical_risk']}")
        print(f"Cumulative risk: {cumulative}")
        print(f"Router tier: {routing['tier']}")
        print(f"Adaptive tier: {adaptive_tier}")

        session.add_risk(current_risk)

    print("\nFinal session history:")
    print(session.get_history())


if __name__ == "__main__":
    run_test()