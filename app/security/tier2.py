from app.security.injection import detect_injection
from app.security.jailbreak import detect_jailbreak
from app.security.hierarchy import check_instruction_hierarchy
from app.security.sensitive import (
    detect_sensitive_request,
    detect_harmful_cyber_request,
)
from app.routing.risk import calculate_risk


def detect_role_manipulation(text: str) -> dict:
    """
    Detect attempts to make the LLM adopt a privileged
    or authoritative role.
    """

    text_lower = text.lower()

    role_terms = [
        "administrator",
        "admin",
        "root",
        "superuser",
        "moderator",
        "developer",
        "system",
    ]

    role_actions = [
        "pretend",
        "act as",
        "act like",
        "become",
        "assume",
        "you are now",
        "you're now",
        "your now",
        "you are an",
        "you're an",
        "your an",
    ]

    has_role = any(
        role in text_lower
        for role in role_terms
    )

    has_role_action = any(
        action in text_lower
        for action in role_actions
    )

    detected = has_role and has_role_action

    matches = []

    if detected:
        for role in role_terms:
            if role in text_lower:
                matches.append(role)

    return {
        "detected": detected,
        "matches": matches,
        "category": "ROLE_MANIPULATION" if detected else None,
    }


def detect_security_control_bypass(text: str) -> dict:
    """
    Detect attempts to remove, disable, bypass or override
    security restrictions or guardrails.
    """

    text_lower = text.lower()

    restriction_terms = [
        "restriction",
        "restrictions",
        "safety rules",
        "safety controls",
        "security controls",
        "guardrails",
        "limitations",
        "limits",
    ]

    bypass_actions = [
        "remove",
        "disable",
        "bypass",
        "ignore",
        "override",
        "avoid",
        "turn off",
        "get rid of",
    ]

    has_restriction = any(
        term in text_lower
        for term in restriction_terms
    )

    has_bypass_action = any(
        action in text_lower
        for action in bypass_actions
    )

    detected = (
        has_restriction
        and has_bypass_action
    )

    matches = []

    if detected:
        for term in restriction_terms:
            if term in text_lower:
                matches.append(term)

    return {
        "detected": detected,
        "matches": matches,
        "category": (
            "SECURITY_CONTROL_BYPASS"
            if detected
            else None
        ),
    }


def tier2_scan(text: str, source: str = "user"):

    injection = detect_injection(text)

    jailbreak = detect_jailbreak(text)

    hierarchy = check_instruction_hierarchy(
        text,
        source
    )

    sensitive = detect_sensitive_request(text)

    cyber = detect_harmful_cyber_request(text)

    role = detect_role_manipulation(text)

    bypass = detect_security_control_bypass(text)

    detected = (
        injection["detected"]
        or jailbreak["detected"]
        or hierarchy["conflict"]
        or sensitive["detected"]
        or cyber["detected"]
        or role["detected"]
        or bypass["detected"]
    )

    decision = (
        "BLOCK"
        if detected
        else "ALLOW"
    )

    return {
        "decision": decision,

        "injection": injection,

        "jailbreak": jailbreak,

        "hierarchy": hierarchy,

        "sensitive": sensitive,

        "cyber": cyber,

        "role": role,

        "bypass": bypass,
    }