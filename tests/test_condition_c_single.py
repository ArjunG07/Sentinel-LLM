from tests.test_condition_c import run_condition_c


result = run_condition_c(
    "What are the library borrowing rules?"
)

print("\n===================================")
print("CONDITION C TEST")
print("===================================")

print("DECISION:", result["decision"])
print("LATENCY:", round(result["latency_ms"], 2), "ms")
print("SECURITY CALLS:", result["security_calls"])
print("LLM CALLS:", result["llm_calls"])
print("OUTPUT SCANS:", result["output_scans"])
print("ESCALATIONS:", result["escalations"])
print("TIERS:", result["tiers"])

print("\nRESPONSE:")
print(result["response"])