VALID_PROFILES = {
    "baseline",
    "prompt_injection",
    "tool_coercion",
    "data_exfiltration",
    "oversized_payload",
    "high_entropy",
    "schema_confusion",
    "mixed_content",
    "assistant_impersonation",
    "role_confusion",
    "delayed_instruction",
    "obfuscated_injection",
    "tool_args_smuggling",
    "data_poisoning",
    "context_stuffing",
}

PROFILE_ID_TO_NAME = {
    0: "baseline",
    1: "prompt_injection",
    2: "tool_coercion",
    3: "data_exfiltration",
    4: "oversized_payload",
    5: "high_entropy",
    6: "schema_confusion",
    7: "mixed_content",
    8: "assistant_impersonation",
    9: "role_confusion",
    10: "delayed_instruction",
    11: "obfuscated_injection",
    12: "tool_args_smuggling",
    13: "data_poisoning",
    14: "context_stuffing",
}

PROFILE_NAME_TO_ID = {v: k for k, v in PROFILE_ID_TO_NAME.items()}
