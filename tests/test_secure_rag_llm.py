from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.llm import generate_response
from app.routing.router import route_request
from app.security.tier2 import tier2_scan
from app.security.tier3 import scan_output


def secure_rag_llm(query: str):

    print("\n===================================")
    print("SENTINELLLM SECURE RAG + LLM")
    print("===================================")

    print("\nQUERY:")
    print(query)

    # Step 1: Retrieve documents
    documents = retrieve(query)

    if not documents:
        print("\nNo documents found.")
        return

    print("\nRETRIEVED DOCUMENTS:")

    for document in documents:
        print("-", document["id"])

    # Step 2: Security analysis of retrieved content
    for document in documents:

        routing = route_request(
            document["text"],
            document["source"]
        )

        print("\n-----------------------------------")
        print("DOCUMENT:", document["id"])
        print("RISK:", routing["risk_score"])
        print("TRUST:", routing["trust_level"])
        print("TIER:", routing["tier"])

        if routing["escalate"]:

            security = tier2_scan(
                document["text"],
                document["source"]
            )

            print("SECURITY DECISION:", security["decision"])

            if security["decision"] == "BLOCK":
                print("\n🚨 REQUEST BLOCKED")
                print("The LLM was NOT called.")
                return

        else:
            print("SECURITY DECISION: ALLOW")

    # Step 3: Build RAG prompt
    prompt = build_rag_prompt(
        query,
        documents
    )

    # Step 4: Call LLM
    print("\nLLM STATUS: CALLED")

    response = generate_response(prompt)
    
    print("\nRAW LLM RESPONSE:")
    print(response)

    # Step 5: Scan LLM output
    output_security = scan_output(response)

    print("\n-----------------------------------")
    print("OUTPUT SECURITY")
    print("DETECTED:", output_security["detected"])
    print("MATCHES:", output_security["matches"])
    print("DECISION:", output_security["decision"])

    # Step 6: Final response
    if output_security["decision"] == "BLOCK":

        print("\n🚨 OUTPUT BLOCKED")
        print("The generated response was not returned.")

    else:

        print("\n✅ FINAL RESPONSE:")
        print(response)


if __name__ == "__main__":

    query = "What are the computer lab rules?"

    secure_rag_llm(query)