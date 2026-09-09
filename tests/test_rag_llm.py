from app.rag.retriever import retrieve
from app.rag.prompt import build_rag_prompt
from app.llm import generate_response


query = "What are the library borrowing rules?"

documents = retrieve(query)

prompt = build_rag_prompt(query, documents)

response = generate_response(prompt)

print("\n===================================")
print("SENTINELLLM RAG + LLM TEST")
print("===================================")

print("\nQUERY:")
print(query)

print("\nRETRIEVED DOCUMENTS:")

for document in documents:
    print("-", document["id"])

print("\nLLM RESPONSE:")
print(response)