from app.rag.retriever import retrieve


queries = [
    "What are the library borrowing rules?",
    "What are the computer lab rules?",
]


for query in queries:
    print("\n" + "=" * 60)
    print("QUERY:", query)

    documents = retrieve(query)

    for document in documents:
        print("DOCUMENT:", document["id"])