from app.llm import generate_response


prompt = "Explain what a library is in one sentence."

response = generate_response(prompt)

print("\n===================================")
print("SENTINELLLM LOCAL LLM TEST")
print("===================================")
print("\nPROMPT:", prompt)
print("\nRESPONSE:", response)