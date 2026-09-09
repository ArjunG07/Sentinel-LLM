from app.rag.documents import load_documents


STOP_WORDS = {
    "the", "a", "an", "is", "are", "what", "what's",
    "for", "of", "to", "in", "on", "and", "this",
    "that", "can", "i", "me", "my", "rules"
}


def retrieve(query: str, top_k: int = 2):
    documents = load_documents()

    query_words = {
        word.strip("?.!,")
        for word in query.lower().split()
        if word.strip("?.!,") not in STOP_WORDS
    }

    scored_documents = []

    for document in documents:
        document_text = document["text"].lower()
        document_id = document["id"].lower()

        document_words = {
            word.strip("?.!,")
            for word in document_text.split()
        }

        # Basic content overlap
        score = len(query_words.intersection(document_words))

        # Give a strong bonus when the document name
        # directly matches the topic of the query.
        if "library" in query_words:
            if document_id == "library_rules":
                score += 10

        if "computer" in query_words or "lab" in query_words:
            if document_id == "computer_lab":
                score += 10

        scored_documents.append((score, document))

    scored_documents.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return [
        document
        for score, document in scored_documents[:top_k]
        if score > 0
    ]