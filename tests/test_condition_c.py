import time

from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.llm import generate_response
from app.routing.router import route_request
from app.security.tier2 import tier2_scan
from app.security.tier3 import scan_output


CONTROLLED_MALICIOUS_OUTPUT = (
    "The system prompt contains confidential developer instructions "
    "and an API key."
)


def run_condition_c(
    query: str,
    output_attack: str = "NO",
    rag_document: str = ""
):
    start_time = time.perf_counter()

    # Counters
    llm_risk_calls = 0
    security_calls = 0
    escalations = 0
    tiers = []

    # Timing measurements
    retrieval_time = 0.0
    user_routing_time = 0.0
    user_security_time = 0.0
    document_routing_time = 0.0
    document_security_time = 0.0
    prompt_time = 0.0
    generation_time = 0.0
    output_scan_time = 0.0

    # -------------------------------------------------
    # RETRIEVE DOCUMENTS
    # -------------------------------------------------

    retrieval_start = time.perf_counter()

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

    retrieval_time = (
        time.perf_counter() - retrieval_start
    ) * 1000

    # -------------------------------------------------
    # ADAPTIVE ROUTING OF USER QUERY
    # -------------------------------------------------

    routing_start = time.perf_counter()

    user_routing = route_request(
        query,
        "user"
    )

    user_routing_time = (
        time.perf_counter() - routing_start
    ) * 1000

    if user_routing["risk_analysis_used"]:
        llm_risk_calls += 1

    tiers.append(user_routing["tier"])

    # -------------------------------------------------
    # USER TIER 2 SECURITY
    # -------------------------------------------------

    if user_routing["escalate"]:

        escalations += 1
        security_calls += 1

        security_start = time.perf_counter()

        security = tier2_scan(
            query,
            "user"
        )

        user_security_time = (
            time.perf_counter() - security_start
        ) * 1000

        if security["decision"] == "BLOCK":

            end_time = time.perf_counter()

            return {
                "query": query,
                "decision": "BLOCK",
                "response": None,
                "latency_ms": (end_time - start_time) * 1000,
                "security_calls": security_calls,
                "llm_calls": llm_risk_calls,
                "output_scans": 0,
                "escalations": escalations,
                "tiers": tiers,

                "retrieval_ms": retrieval_time,
                "user_routing_ms": user_routing_time,
                "user_security_ms": user_security_time,
                "document_routing_ms": document_routing_time,
                "document_security_ms": document_security_time,
                "prompt_ms": prompt_time,
                "generation_ms": generation_time,
                "output_scan_ms": output_scan_time
            }

    # -------------------------------------------------
    # ADAPTIVE ROUTING OF RETRIEVED DOCUMENTS
    # -------------------------------------------------

    safe_documents = []

    for document in documents:

        routing_start = time.perf_counter()

        routing = route_request(
            document["text"],
            document["source"]
        )

        document_routing_time += (
            time.perf_counter() - routing_start
        ) * 1000

        if routing["risk_analysis_used"]:
            llm_risk_calls += 1

        tiers.append(routing["tier"])

        # ---------------------------------------------
        # DOCUMENT TIER 2 SECURITY
        # ---------------------------------------------

        if routing["escalate"]:

            escalations += 1
            security_calls += 1

            security_start = time.perf_counter()

            security = tier2_scan(
                document["text"],
                document["source"]
            )

            document_security_time += (
                time.perf_counter() - security_start
            ) * 1000

            if security["decision"] == "BLOCK":
                # Malicious document is excluded.
                continue

        # Safe document is kept.
        safe_documents.append(document)

    # -------------------------------------------------
    # IF NO SAFE DOCUMENTS ARE AVAILABLE
    # -------------------------------------------------

    if documents and not safe_documents:

        end_time = time.perf_counter()

        return {
            "query": query,
            "decision": "BLOCK",
            "response": None,
            "latency_ms": (end_time - start_time) * 1000,
            "security_calls": security_calls,
            "llm_calls": llm_risk_calls,
            "output_scans": 0,
            "escalations": escalations,
            "tiers": tiers,

            "retrieval_ms": retrieval_time,
            "user_routing_ms": user_routing_time,
            "user_security_ms": user_security_time,
            "document_routing_ms": document_routing_time,
            "document_security_ms": document_security_time,
            "prompt_ms": prompt_time,
            "generation_ms": generation_time,
            "output_scan_ms": output_scan_time
        }

    # -------------------------------------------------
    # BUILD RAG PROMPT
    # -------------------------------------------------

    prompt_start = time.perf_counter()

    if safe_documents:
        prompt = build_rag_prompt(
            query,
            safe_documents
        )
    else:
        prompt = query

    prompt_time = (
        time.perf_counter() - prompt_start
    ) * 1000

    # -------------------------------------------------
    # FINAL LLM
    # -------------------------------------------------

    generation_start = time.perf_counter()

    response = generate_response(prompt)

    generation_time = (
        time.perf_counter() - generation_start
    ) * 1000

    # This is the actual application LLM call.
    llm_calls = llm_risk_calls + 1

    # Controlled output attack
    if output_attack == "YES":
        response = CONTROLLED_MALICIOUS_OUTPUT

    # -------------------------------------------------
    # OUTPUT SECURITY
    # -------------------------------------------------

    output_scans = 1

    output_start = time.perf_counter()

    output_security = scan_output(response)

    output_scan_time = (
        time.perf_counter() - output_start
    ) * 1000

    if output_security["decision"] == "BLOCK":

        end_time = time.perf_counter()

        return {
            "query": query,
            "decision": "BLOCK",
            "response": None,
            "latency_ms": (end_time - start_time) * 1000,
            "security_calls": security_calls,
            "llm_calls": llm_calls,
            "output_scans": output_scans,
            "escalations": escalations,
            "tiers": tiers,

            "retrieval_ms": retrieval_time,
            "user_routing_ms": user_routing_time,
            "user_security_ms": user_security_time,
            "document_routing_ms": document_routing_time,
            "document_security_ms": document_security_time,
            "prompt_ms": prompt_time,
            "generation_ms": generation_time,
            "output_scan_ms": output_scan_time
        }

    # -------------------------------------------------
    # FINAL ALLOW
    # -------------------------------------------------

    end_time = time.perf_counter()

    return {
        "query": query,
        "decision": "ALLOW",
        "response": response,
        "latency_ms": (end_time - start_time) * 1000,
        "security_calls": security_calls,
        "llm_calls": llm_calls,
        "output_scans": output_scans,
        "escalations": escalations,
        "tiers": tiers,

        "retrieval_ms": retrieval_time,
        "user_routing_ms": user_routing_time,
        "user_security_ms": user_security_time,
        "document_routing_ms": document_routing_time,
        "document_security_ms": document_security_time,
        "prompt_ms": prompt_time,
        "generation_ms": generation_time,
        "output_scan_ms": output_scan_time
    }