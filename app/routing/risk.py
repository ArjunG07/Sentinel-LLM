def calculate_risk(text: str, source: str = "user"):
    text_lower = text.lower()

    risk = 0.0

    suspicious_patterns = {
        "ignore previous instructions": 0.45,
        "ignore all previous instructions": 0.50,
        "system prompt": 0.40,
        "reveal your instructions": 0.35,
        "reveal the system prompt": 0.40,
        "jailbreak": 0.40,
        "developer message": 0.30,
        "bypass": 0.25,

        # Role manipulation
        "pretend you are the system": 0.50,
        "pretend you are the administrator": 0.50,
        "pretend you are the system administrator": 0.60,
        "act as the system administrator": 0.50,
        "act as an unrestricted": 0.50,
        "no restrictions": 0.50,

        # Information extraction
        "hidden instructions": 0.35,
        "confidential information": 0.30,
        "secret key": 0.30,
        "api key": 0.30,
    }

    # Check suspicious phrases
    for pattern, score in suspicious_patterns.items():
        if pattern in text_lower:
            risk += score

    # Combination-based role manipulation
    role_words = [
        "administrator",
        "admin",
        "system",
        "developer",
        "unrestricted"
    ]

    role_action_words = [
        "pretend",
        "act as",
        "become",
        "assume"
    ]

    if (
        any(word in text_lower for word in role_words)
        and any(action in text_lower for action in role_action_words)
    ):
        risk += 0.50

    # Detect attempts to reduce/remove restrictions
    if (
        "restriction" in text_lower
        and (
            "fewer" in text_lower
            or "remove" in text_lower
            or "ignore" in text_lower
            or "bypass" in text_lower
        )
    ):
        risk += 0.40

    # Retrieved RAG content gets a small additional risk
    if source.lower() == "rag":
        risk += 0.20

    return min(risk, 1.0)