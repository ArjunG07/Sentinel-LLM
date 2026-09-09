import time

from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.routing.router import route_request
from app.security.tier2 import tier2_scan
from app.security.tier3 import scan_output
from app.llm import generate_response


def analyze_rag_query(query: str):
    start_time = time.perf_counter()

    # 1. Analyze the user's query
    user_routing = route_request(query, "user")

    if user_routing["escalate"]:
        user_security = tier2_scan(query, "user")

        if user_security["decision"] == "BLOCK":
            end_time = time.perf_counter()

            return {
                "query": query,
                "user_analysis": user_routing,
                "user_security": user_security,
                "documents": [],
                "final_decision": "BLOCK",
                "response": None,
                "output_scan": None,
                "latency_ms": (end_time - start_time) * 1000
            }
    else:
        user_security = None

    # 2. Retrieve documents
    documents = retrieve(query)

    if not documents:
        end_time = time.perf_counter()

        return {
            "query": query,
            "user_analysis": user_routing,
            "user_security": user_security,
            "documents": [],
            "final_decision": "NO_DOCUMENTS",
            "response": None,
            "output_scan": None,
            "latency_ms": (end_time - start_time) * 1000
        }

    # 3. Analyze retrieved documents
    results = []
    safe_documents = []

    for document in documents:

        routing_result = route_request(
            document["text"],
            document["source"]
        )

        security_result = None

        if routing_result["escalate"]:
            security_result = tier2_scan(
                document["text"],
                document["source"]
            )

            final_decision = security_result["decision"]

        else:
            final_decision = "ALLOW"

        # Keep only safe documents for the final RAG prompt
        if final_decision == "ALLOW":
            safe_documents.append(document)

        results.append({
            "document_id": document["id"],
            "source": document["source"],
            "risk_score": routing_result["risk_score"],
            "rule_risk": routing_result["rule_risk"],
            "llm_risk": routing_result["llm_risk"],
            "trust_level": routing_result["trust_level"],
            "tier": routing_result["tier"],
            "escalate": routing_result["escalate"],
            "reason": routing_result["reason"],
            "security": security_result,
            "decision": final_decision
        })

    # 4. If every retrieved document was unsafe, stop
    if not safe_documents:
        end_time = time.perf_counter()

        return {
            "query": query,
            "user_analysis": user_routing,
            "user_security": user_security,
            "documents": results,
            "final_decision": "BLOCK",
            "response": None,
            "output_scan": None,
            "latency_ms": (end_time - start_time) * 1000
        }

    # 5. Build RAG prompt using ONLY safe documents
    rag_prompt = build_rag_prompt(
        query,
        safe_documents
    )

    # 6. Generate answer using Qwen
    response = generate_response(rag_prompt)

    # 7. Scan Qwen's output
    output_result = scan_output(response)

    if output_result["decision"] == "BLOCK":
        final_decision = "BLOCK"
        final_response = None
    else:
        final_decision = "ALLOW"
        final_response = response

    end_time = time.perf_counter()

    return {
        "query": query,
        "user_analysis": user_routing,
        "user_security": user_security,
        "documents": results,
        "final_decision": final_decision,
        "response": final_response,
        "output_scan": output_result,
        "latency_ms": (end_time - start_time) * 1000
    }


if __name__ == "__main__":

    query = "What are the library borrowing rules?"

    result = analyze_rag_query(query)

    print("\n===================================")
    print("SENTINELLLM END-TO-END PIPELINE")
    print("===================================")

    print("\nQUERY:", result["query"])

    print("\n--- USER ANALYSIS ---")
    print("RISK:", result["user_analysis"]["risk_score"])
    print("TIER:", result["user_analysis"]["tier"])
    print("ESCALATE:", result["user_analysis"]["escalate"])

    print("\n--- DOCUMENTS ---")

    for document in result["documents"]:
        print("\nDOCUMENT:", document["document_id"])
        print("RISK:", document["risk_score"])
        print("TIER:", document["tier"])
        print("DECISION:", document["decision"])

    print("\n--- FINAL RESULT ---")
    print("DECISION:", result["final_decision"])

    if result["response"]:
        print("\n--- QWEN RESPONSE ---")
        print(result["response"])

    print("\n--- OUTPUT SCAN ---")
    print(result["output_scan"])

    print("\nLATENCY:", round(result["latency_ms"], 2), "ms")