from app.routing.trust import get_trust_level


# ============================================================
# INSTRUCTION HIERARCHY
# ============================================================

# Higher number = higher trust
#
# System       = 4
# Developer    = 3
# User         = 2
# RAG/Third-party = 1


# These patterns indicate that content is attempting
# to override, replace, or impersonate a higher-priority
# instruction source.
CONFLICT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore prior instructions",
    "disregard previous instructions",
    "disregard all previous instructions",
    "forget previous instructions",
    "override previous instructions",
    "override system instructions",
    "override developer instructions",
    "replace the system instruction",
    "replace the developer instruction",
    "follow this instead",
    "obey this instruction instead",
    "treat this as a system instruction",
    "treat this message as a system instruction",
    "treat this as a developer instruction",
    "treat this message as a developer instruction",
    "higher priority instruction",
    "higher-priority instruction",
    "you are now the system",
    "you are now the developer",
]


def check_instruction_hierarchy(
    text: str,
    source: str = "user"
):
    """
    Check whether content from a given trust source
    attempts to conflict with higher-priority instructions.

    Trust hierarchy:

        system > developer > user > rag

    RAG content is treated as third-party/untrusted data.
    """

    text_lower = text.lower()

    trust_level = get_trust_level(source)

    matched_patterns = [
        pattern
        for pattern in CONFLICT_PATTERNS
        if pattern in text_lower
    ]

    conflict = len(matched_patterns) > 0

    # A hierarchy conflict matters most when the content
    # comes from a lower-trust source.
    #
    # RAG = 1
    # User = 2
    # Developer = 3
    # System = 4
    #
    # Lower-trust content attempting to override instructions
    # is therefore treated as suspicious.
    if trust_level <= 2 and conflict:
        conflict = True
    else:
        conflict = False

    return {
        "source": source,
        "trust_level": trust_level,
        "conflict": conflict,
        "matched_patterns": matched_patterns,
    }