import time

from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.routing.router import route_request
from app.security.tier2 import tier2_scan
from app.security.tier3 import scan_output
from app.llm import generate_response

from evaluation.live_logger import log_live_case


def save_live_result(result):
    test_id = log_live_case(result)
    print(f"\n[LIVE DATASET] Saved as {test_id}")


def analyze_rag_query(query: str):
    start_time = time.perf_counter()

    # 1. Analyze the user's query
    user_routing = route_request(query, "user")

    if user_routing["escalate"]:
        user_security = tier2_scan(query, "user")

        if user_security["decision"] == "BLOCK":
            end_time = time.perf_counter()

            result = {
                "query": query,
                "user_analysis": user_routing,
                "user_security": user_security,
                "documents": [],
                "final_decision": "BLOCK",
                "response": None,
                "output_scan": None,
                "latency_ms": (end_time - start_time) * 1000
            }

            save_live_result(result)

            return result

    else:
        user_security = None

    # 2. Retrieve documents
    documents = retrieve(query)

    if not documents:
        end_time = time.perf_counter()

        result = {
            "query": query,
            "user_analysis": user_routing,
            "user_security": user_security,
            "documents": [],
            "final_decision": "NO_DOCUMENTS",
            "response": None,
            "output_scan": None,
            "latency_ms": (end_time - start_time) * 1000
        }

        save_live_result(result)

        return result

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

        result = {
            "query": query,
            "user_analysis": user_routing,
            "user_security": user_security,
            "documents": results,
            "final_decision": "BLOCK",
            "response": None,
            "output_scan": None,
            "latency_ms": (end_time - start_time) * 1000
        }

        save_live_result(result)

        return result

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

    result = {
        "query": query,
        "user_analysis": user_routing,
        "user_security": user_security,
        "documents": results,
        "final_decision": final_decision,
        "response": final_response,
        "output_scan": output_result,
        "latency_ms": (end_time - start_time) * 1000
    }

    save_live_result(result)

    return result


if __name__ == "__main__":

    print("\n===================================")
    print("SENTINELLLM LIVE DATA COLLECTION")
    print("===================================")
    print("\nEnter prompts one at a time.")
    print("Type 'quit' to stop the collection.\n")

    while True:

        query = input("Prompt: ").strip()

        if query.lower() == "quit":
            print("\nLive collection stopped.")
            break

        if not query:
            print("Please enter a prompt.\n")
            continue

        print("\nProcessing...\n")

        result = analyze_rag_query(query)

        print("-----------------------------------")
        print("DECISION:", result["final_decision"])
        print("RISK:", result["user_analysis"]["risk_score"])
        print("TIER:", result["user_analysis"]["tier"])
        print("LATENCY:", round(result["latency_ms"], 2), "ms")
        print("-----------------------------------\n")