import time

from app.routing.router import route_request
from app.rag.retriever import retrieve
from app.security.tier2 import tier2_scan
from app.llm import generate_response
from app.rag.prompt import build_rag_prompt


query = "What are the library borrowing rules?"

print("\n" + "=" * 60)
print("PIPELINE TIMING TEST")
print("=" * 60)

# 1. User risk analysis
start = time.perf_counter()
user_analysis = route_request(query, "user")
end = time.perf_counter()

print("\nUSER RISK ANALYSIS:")
print("Time:", round((end - start) * 1000, 2), "ms")
print(user_analysis)


# 2. Retrieval
start = time.perf_counter()
documents = retrieve(query)
end = time.perf_counter()

print("\nRETRIEVAL:")
print("Time:", round((end - start) * 1000, 2), "ms")

for document in documents:
    print("DOCUMENT:", document["id"])


# 3. Document security analysis
safe_documents = []

for document in documents:

    start = time.perf_counter()

    routing = route_request(
        document["text"],
        document["source"]
    )

    security = None

    if routing["escalate"]:
        security = tier2_scan(
            document["text"],
            document["source"]
        )

    end = time.perf_counter()

    print("\nDOCUMENT:", document["id"])
    print("Time:", round((end - start) * 1000, 2), "ms")
    print("Risk:", routing["risk_score"])
    print("Tier:", routing["tier"])
    print("Decision:", security["decision"] if security else "ALLOW")

    if security is None or security["decision"] == "ALLOW":
        safe_documents.append(document)


# 4. Qwen generation
rag_prompt = build_rag_prompt(
    query,
    safe_documents
)

start = time.perf_counter()

response = generate_response(rag_prompt)

end = time.perf_counter()

print("\nQWEN GENERATION:")
print("Time:", round((end - start) * 1000, 2), "ms")

print("\nRESPONSE:")
print(response)

print("\n" + "=" * 60)