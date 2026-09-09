from app.security.injection import detect_injection
from app.security.jailbreak import detect_jailbreak
from app.security.hierarchy import check_instruction_hierarchy


def tier2_scan(text: str, source: str = "user"):

    injection = detect_injection(text)

    jailbreak = detect_jailbreak(text)

    hierarchy = check_instruction_hierarchy(
        text,
        source
    )

    detected = (
        injection["detected"]
        or jailbreak["detected"]
        or hierarchy["conflict"]
    )

    if detected:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "injection": injection,
        "jailbreak": jailbreak,
        "hierarchy": hierarchy
    }