from app.routing.trust import get_trust_level


def check_instruction_hierarchy(
    text: str,
    source: str
) -> dict:

    trust_level = get_trust_level(source)

    suspicious = (
        "ignore previous instructions" in text.lower()
        or "ignore all previous instructions" in text.lower()
    )

    conflict = (
        suspicious
        and trust_level <= 1
    )

    return {
        "source": source,
        "trust_level": trust_level,
        "conflict": conflict
    }