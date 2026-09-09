def build_rag_prompt(query: str, documents: list) -> str:

    context_parts = []

    for document in documents:
        context_parts.append(
            f"Source: {document['id']}\n"
            f"{document['text']}"
        )

    context = "\n\n".join(context_parts)

    prompt = f"""
You are an assistant answering questions using the provided college documents.

Use the provided context to answer the user's question.
If the answer is not present in the context, say that the information is not available in the provided documents.
Do not make up information.

CONTEXT:
{context}

USER QUESTION:
{query}

ANSWER:
"""

    return prompt