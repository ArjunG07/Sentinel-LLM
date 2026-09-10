SENSITIVE_PATTERNS = [
    "password",
    "passwords",
    "credentials",
    "api key",
    "api keys",
    "secret key",
    "secret keys",
    "access token",
    "authentication token",
    "private key",
]

EXTRACTION_ACTIONS = [
    "give me",
    "show me",
    "tell me",
    "send me",
    "reveal",
    "find",
    "retrieve",
    "get",
    "extract",
    "list",
]

HARMFUL_CYBER_TERMS = [
    "hack",
    "hacking",
    "malware",
    "virus",
    "ransomware",
    "trojan",
    "keylogger",
]

HARMFUL_CYBER_ACTIONS = [
    "how do i",
    "how to",
    "show me how",
    "teach me how",
    "help me",
    "give me instructions",
    "download",
    "install",
    "create",
    "deploy",
    "run",
]


def detect_sensitive_request(text: str) -> dict:
    text_lower = text.lower()

    matches = []

    has_sensitive_target = any(
        pattern in text_lower
        for pattern in SENSITIVE_PATTERNS
    )

    has_extraction_action = any(
        action in text_lower
        for action in EXTRACTION_ACTIONS
    )

    if has_sensitive_target and has_extraction_action:
        for pattern in SENSITIVE_PATTERNS:
            if pattern in text_lower:
                matches.append(pattern)

    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "category": "SENSITIVE_INFORMATION"
        if matches
        else None
    }


def detect_harmful_cyber_request(text: str) -> dict:
    text_lower = text.lower()

    matches = []

    has_harmful_term = any(
        term in text_lower
        for term in HARMFUL_CYBER_TERMS
    )

    has_harmful_action = any(
        action in text_lower
        for action in HARMFUL_CYBER_ACTIONS
    )

    if has_harmful_term and has_harmful_action:
        for term in HARMFUL_CYBER_TERMS:
            if term in text_lower:
                matches.append(term)

    return {
        "detected": len(matches) > 0,
        "matches": matches,
        "category": "HARMFUL_CYBER_REQUEST"
        if matches
        else None
    }