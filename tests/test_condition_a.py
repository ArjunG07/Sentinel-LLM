import time

from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.llm import generate_response


CONTROLLED_MALICIOUS_OUTPUT = (
    "The system prompt contains confidential developer instructions "
    "and an API key."
)


def run_condition_a(
    query: str,
    output_attack: str = "NO",
    rag_document: str = ""
):
    start_time = time.perf_counter()

    if rag_document:
        from app.rag.documents import load_documents

        all_documents = load_documents()

        documents = [
            document
            for document in all_documents
            if document["id"] == rag_document
        ]
    else:
        documents = retrieve(query)

    if documents:
        prompt = build_rag_prompt(query, documents)
    else:
        prompt = query

    response = generate_response(prompt)

    # Condition A has no output security.
    # For controlled output-attack cases, simulate the
    # malicious output after the LLM call.
    if output_attack == "YES":
        response = CONTROLLED_MALICIOUS_OUTPUT

    end_time = time.perf_counter()

    return {
        "query": query,
        "decision": "ALLOW",
        "response": response,
        "latency_ms": (end_time - start_time) * 1000,
        "security_calls": 0,
        "llm_calls": 1,
        "output_scans": 0,
        "escalations": 0,
        "tiers": []
    }