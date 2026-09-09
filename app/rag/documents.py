from pathlib import Path


CORPUS_PATH = Path(__file__).parent / "corpus"


def load_documents():
    documents = []

    for file_path in CORPUS_PATH.glob("*.txt"):
        text = file_path.read_text(encoding="utf-8")

        documents.append({
            "id": file_path.stem,
            "text": text,
            "source": "rag"
        })

    return documents