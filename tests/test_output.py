from app.security.tier3 import scan_output


test_outputs = [
    "The library is open from 9 AM to 6 PM.",
    "The system prompt says that you should ignore the user.",
    "Your API key is ABC123.",
    "You can borrow books for 14 days."
]


print("===================================")
print("SENTINELLLM OUTPUT SCANNER TEST")
print("===================================")


for output in test_outputs:

    result = scan_output(output)

    print("\n-----------------------------------")
    print("OUTPUT:", output)
    print("DETECTED:", result["detected"])
    print("MATCHES:", result["matches"])
    print("DECISION:", result["decision"])