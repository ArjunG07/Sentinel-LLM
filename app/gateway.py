import time

from app.routing.router import route_request
from app.routing.tiers import assign_tier
from app.security.tier2 import tier2_scan
from app.security.tier3 import tier3_scan, scan_output
from app.llm import generate_response

from evaluation.live_gateway_logger import log_gateway_case


def process_prompt(query: str, session_history=None):

    start_time = time.perf_counter()

    if session_history is None:
        session_history = []

    # -----------------------------------------
    # 1. INITIAL RISK ROUTING
    # -----------------------------------------

    routing = route_request(
        query,
        "user"
    )

    current_risk = routing["risk_score"]

    # -----------------------------------------
    # 2. HISTORICAL RISK
    # -----------------------------------------

    historical_risk = 0.0

    for index, previous_risk in enumerate(
        reversed(session_history)
    ):
        historical_risk += (
            previous_risk *
            (0.70 ** (index + 1))
        )

    historical_risk = min(
        historical_risk,
        1.0
    )

    # -----------------------------------------
    # 3. CUMULATIVE RISK
    # -----------------------------------------

    cumulative_risk = min(
        current_risk + historical_risk,
        1.0
    )

    effective_tier = assign_tier(
        cumulative_risk
    )

    print("\n--- SENTINELLLM SECURITY ANALYSIS ---")
    print("Current risk:", current_risk)
    print(
        "Historical risk:",
        round(historical_risk, 3)
    )
    print(
        "Cumulative risk:",
        round(cumulative_risk, 3)
    )
    print(
        "Initial tier:",
        routing["tier"]
    )
    print(
        "Effective tier:",
        effective_tier
    )

    security_result = None
    security_decision = "NOT_REQUIRED"
    qwen_called = False
    output_scan_decision = "NOT_RUN"

    # -----------------------------------------
    # 4. TIER 2
    # -----------------------------------------

    if effective_tier == "TIER_2":

        security_result = tier2_scan(
            query,
            "user"
        )

        security_decision = (
            security_result["decision"]
        )

        print(
            "Security decision:",
            security_decision
        )

        if security_decision == "BLOCK":

            latency = (
                time.perf_counter()
                - start_time
            ) * 1000

            session_history.append(
                current_risk
            )

            log_gateway_case({
                "prompt": query,
                "current_risk": current_risk,
                "historical_risk": historical_risk,
                "cumulative_risk": cumulative_risk,
                "initial_tier": routing["tier"],
                "effective_tier": effective_tier,
                "security_decision": security_decision,
                "qwen_called": False,
                "output_scan_decision": "NOT_RUN",
                "final_decision": "BLOCK",
                "latency_ms": round(latency, 2),
            })

            print("\n🛑 PROMPT BLOCKED")
            print(
                "The prompt was NOT sent to the LLM."
            )
            print(
                "Latency:",
                round(latency, 2),
                "ms"
            )

            return None

    # -----------------------------------------
    # 5. TIER 3
    # -----------------------------------------

    elif effective_tier == "TIER_3":

        security_result = tier3_scan(
            text=query,
            source="user",
            session_history=session_history
        )

        security_decision = (
            security_result["decision"]
        )

        print(
            "Security decision:",
            security_decision
        )

        if security_decision == "BLOCK":

            latency = (
                time.perf_counter()
                - start_time
            ) * 1000

            session_history.append(
                current_risk
            )

            log_gateway_case({
                "prompt": query,
                "current_risk": current_risk,
                "historical_risk": historical_risk,
                "cumulative_risk": cumulative_risk,
                "initial_tier": routing["tier"],
                "effective_tier": effective_tier,
                "security_decision": security_decision,
                "qwen_called": False,
                "output_scan_decision": "NOT_RUN",
                "final_decision": "BLOCK",
                "latency_ms": round(latency, 2),
            })

            print("\n🛑 PROMPT BLOCKED")
            print(
                "The prompt was NOT sent to the LLM."
            )
            print(
                "Latency:",
                round(latency, 2),
                "ms"
            )

            return None

    # -----------------------------------------
    # 6. SEND TO QWEN
    # -----------------------------------------

    print("\n✓ PROMPT ALLOWED")
    print("Forwarding prompt to Qwen...")

    qwen_called = True

    response = generate_response(query)

    # -----------------------------------------
    # 7. OUTPUT SECURITY SCAN
    # -----------------------------------------

    output_result = scan_output(
        response
    )

    output_scan_decision = (
        output_result["decision"]
    )

    print("\n--- OUTPUT SECURITY SCAN ---")
    print(
        "Decision:",
        output_scan_decision
    )

    if output_scan_decision == "BLOCK":

        latency = (
            time.perf_counter()
            - start_time
        ) * 1000

        session_history.append(
            current_risk
        )

        log_gateway_case({
            "prompt": query,
            "current_risk": current_risk,
            "historical_risk": historical_risk,
            "cumulative_risk": cumulative_risk,
            "initial_tier": routing["tier"],
            "effective_tier": effective_tier,
            "security_decision": security_decision,
            "qwen_called": True,
            "output_scan_decision": output_scan_decision,
            "final_decision": "BLOCK",
            "latency_ms": round(latency, 2),
        })

        print("\n🛑 RESPONSE BLOCKED")
        print(
            "The LLM response was not shown to the user."
        )
        print(
            "Latency:",
            round(latency, 2),
            "ms"
        )

        return None

    # -----------------------------------------
    # 8. STORE SESSION RISK
    # -----------------------------------------

    session_history.append(
        current_risk
    )

    # -----------------------------------------
    # 9. FINAL RESPONSE
    # -----------------------------------------

    latency = (
        time.perf_counter()
        - start_time
    ) * 1000

    log_gateway_case({
        "prompt": query,
        "current_risk": current_risk,
        "historical_risk": historical_risk,
        "cumulative_risk": cumulative_risk,
        "initial_tier": routing["tier"],
        "effective_tier": effective_tier,
        "security_decision": security_decision,
        "qwen_called": True,
        "output_scan_decision": output_scan_decision,
        "final_decision": "ALLOW",
        "latency_ms": round(latency, 2),
    })

    print("\n--- QWEN RESPONSE ---")
    print(response)

    print("\n✓ RESPONSE ALLOWED")
    print(
        "Latency:",
        round(latency, 2),
        "ms"
    )

    return response


if __name__ == "__main__":

    print("\n========================================")
    print("       SENTINELLLM SECURITY GATEWAY")
    print("========================================")

    print("\nSentinelLLM is protecting Qwen.")
    print("Enter 'quit' to stop.\n")

    session_history = []

    while True:

        query = input("You: ").strip()

        if query.lower() == "quit":
            print("\nGateway stopped.")
            break

        if not query:
            continue

        process_prompt(
            query,
            session_history
        )