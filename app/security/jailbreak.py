JAILBREAK_PATTERNS = [
    "jailbreak",
    "bypass safety",
    "bypass security",
    "disable safety",
    "disable your safety",
    "pretend you have no restrictions",
]


def detect_jailbreak(text: str) -> dict:

    text_lower = text.lower()

    matches = []

    for pattern in JAILBREAK_PATTERNS:
        if pattern in text_lower:
            matches.append(pattern)

    return {
        "detected": len(matches) > 0,
        "matches": matches
    }