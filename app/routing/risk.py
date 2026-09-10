def calculate_risk(text: str, source: str = "user"):
    text_lower = text.lower()
    risk = 0.0

    # --------------------------------------------------
    # 1. DIRECT PROMPT INJECTION
    # --------------------------------------------------

    direct_injection_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "disregard previous instructions",
        "forget previous instructions",
        "override previous instructions",
        "ignore your instructions",
        "disregard your instructions",
        "forget your instructions",
        "ignore what you were told",
        "ignore what i told you",
        "ignore whatever i say",
    ]

    for pattern in direct_injection_patterns:
        if pattern in text_lower:
            risk += 0.45
            break

    # --------------------------------------------------
    # 2. SYSTEM / DEVELOPER PROMPT EXTRACTION
    # --------------------------------------------------

    system_targets = [
        "system prompt",
        "system instructions",
        "system message",
        "developer prompt",
        "developer instructions",
        "developer message",
        "hidden instructions",
    ]

    extraction_actions = [
        "reveal",
        "show",
        "tell me",
        "give me",
        "print",
        "display",
        "provide",
        "send me",
        "tell",
    ]

    has_system_target = any(
        target in text_lower
        for target in system_targets
    )

    has_extraction_action = any(
        action in text_lower
        for action in extraction_actions
    )

    if has_system_target and has_extraction_action:
        risk += 0.70

    # --------------------------------------------------
    # 3. JAILBREAK / RESTRICTION BYPASS
    # --------------------------------------------------

    jailbreak_terms = [
        "jailbreak",
        "bypass safety",
        "bypass security",
        "disable safety",
        "disable security",
        "remove restrictions",
        "remove the restrictions",
        "get rid of restrictions",
        "get rid of the restrictions",
        "disable restrictions",
        "disable the restrictions",
        "bypass restrictions",
        "bypass the restrictions",
        "no restrictions",
        "without restrictions",
        "unrestricted",
    ]

    for pattern in jailbreak_terms:
        if pattern in text_lower:
            risk += 0.50
            break

    # More flexible restriction detection.
    restriction_words = [
        "restriction",
        "restrictions",
        "safety rules",
        "safety controls",
        "security controls",
        "guardrails",
        "limitations",
        "limits",
    ]

    restriction_actions = [
        "remove",
        "disable",
        "bypass",
        "avoid",
        "ignore",
        "get rid of",
        "turn off",
        "override",
    ]

    has_restriction = any(
        word in text_lower
        for word in restriction_words
    )

    has_restriction_action = any(
        action in text_lower
        for action in restriction_actions
    )

    if has_restriction and has_restriction_action:
        risk += 0.40

    # --------------------------------------------------
    # 4. ROLE MANIPULATION
    # --------------------------------------------------

    role_terms = [
        "administrator",
        "admin",
        "system",
        "developer",
        "root",
        "superuser",
        "moderator",
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

    if has_role and has_role_action:
        risk += 0.60

    # Handle common role-manipulation wording such as:
    # "give yourself admin abilities"
    # "give yourself more permissions"
    # "make yourself administrator"
    permission_terms = [
        "permission",
        "permissions",
        "abilities",
        "access",
        "privileges",
        "privilege",
        "authority",
    ]

    permission_actions = [
        "give",
        "grant",
        "increase",
        "add",
        "get",
        "gain",
        "obtain",
        "give yourself",
        "grant yourself",
        "make yourself",
    ]

    has_permission_term = any(
        term in text_lower
        for term in permission_terms
    )

    has_permission_action = any(
        action in text_lower
        for action in permission_actions
    )

    if has_permission_term and has_permission_action:
        risk += 0.35

    # --------------------------------------------------
    # 5. CREDENTIAL / SENSITIVE INFORMATION EXTRACTION
    # --------------------------------------------------

    sensitive_targets = [
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

    sensitive_actions = [
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
        "display",
        "provide",
    ]

    has_sensitive_target = any(
        target in text_lower
        for target in sensitive_targets
    )

    has_sensitive_action = any(
        action in text_lower
        for action in sensitive_actions
    )

    if has_sensitive_target and has_sensitive_action:
        risk += 0.70

    # --------------------------------------------------
    # 6. SENSITIVE DEVICE INFORMATION
    # --------------------------------------------------

    device_targets = [
        "ip address",
        "ip",
        "mac address",
        "mac",
        "phone number",
        "device id",
        "device identifier",
        "location",
    ]

    device_actions = [
        "give me",
        "show me",
        "tell me",
        "find",
        "get",
        "retrieve",
        "list",
        "reveal",
        "provide",
    ]

    has_device_target = any(
        target in text_lower
        for target in device_targets
    )

    has_device_action = any(
        action in text_lower
        for action in device_actions
    )

    if has_device_target and has_device_action:
        risk += 0.50

    # --------------------------------------------------
    # 7. HARMFUL CYBER REQUEST
    # --------------------------------------------------

    cyber_terms = [
        "hack",
        "hacking",
        "malware",
        "virus",
        "ransomware",
        "trojan",
        "keylogger",
        "exploit",
        "payload",
    ]

    cyber_actions = [
        "how do i",
        "how to",
        "show me how",
        "teach me how",
        "help me",
        "give me instructions",
        "create",
        "build",
        "deploy",
        "install",
        "download",
        "run",
        "execute",
    ]

    has_cyber_term = any(
        term in text_lower
        for term in cyber_terms
    )

    has_cyber_action = any(
        action in text_lower
        for action in cyber_actions
    )

    if has_cyber_term and has_cyber_action:
        risk += 0.70

    # --------------------------------------------------
    # 8. RAG SOURCE PENALTY
    # --------------------------------------------------

    if source.lower() == "rag":
        risk += 0.20

    return min(risk, 1.0)