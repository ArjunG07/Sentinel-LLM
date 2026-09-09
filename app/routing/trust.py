TRUST_LEVELS = {
    "system": 4,
    "developer": 3,
    "user": 2,
    "rag": 1
}


def get_trust_level(source: str) -> int:
    """
    Return the trust level associated with an instruction source.
    """

    source = source.lower()

    return TRUST_LEVELS.get(source, 1)


def is_trusted(source: str) -> bool:
    """
    Determine whether the source is considered trusted.
    """

    return get_trust_level(source) >= 3