"""Quick-pick reasons for "Not suspicious?", "Not fake?" and "This is fake".

They live here, not in the web package, because the store reads them back
when it hands the analysis engine the client's feedback: a report for a
trusted sender says "You told us you trust this sender (reason: I ordered
this)". A reason is context for people; it never changes the trust math.
"""

from __future__ import annotations

# "Not suspicious?" on an email we labelled Suspicious.
SAFE_REASONS: dict[str, str] = {
    "known_sender": "I know this sender",
    "expected": "I ordered this / expected it",
    "newsletter": "It's a newsletter I signed up for",
    "other": "Other",
}
# "Not fake?" on an email we put in Quarantine.
NOT_FAKE_REASONS: dict[str, str] = {
    "known_sender": "I know this sender",
    "expecting": "I was expecting this",
    "company": "It's from a company I use",
    "other": "Other",
}
FAKE_REASONS: dict[str, str] = {
    "unknown_sender": "I don't know this sender",
    "money_or_codes": "Asks for money or codes",
    "impersonation": "Pretends to be someone",
    "other": "Other",
}
# Set by the assistant's proposal cards, never offered as a radio button.
ASSISTANT_REASON = ("assistant", "Agreed with the assistant's suggestion")


def reason_label(decision: str, code: str) -> str:
    """The quick-pick wording for a stored reason code ("" when unknown)."""
    if code == ASSISTANT_REASON[0]:
        return ASSISTANT_REASON[1]
    if decision == "safe":
        return SAFE_REASONS.get(code) or NOT_FAKE_REASONS.get(code, "")
    return FAKE_REASONS.get(code, "")


def allowed_codes(decision: str) -> frozenset[str]:
    codes = set(SAFE_REASONS) | set(NOT_FAKE_REASONS) if decision == "safe" else set(FAKE_REASONS)
    return frozenset(codes | {ASSISTANT_REASON[0]})


def reason_words(decision: str, code: str, text: str) -> str:
    """The reason in one line: the quick-pick label plus the client's own words."""
    label = reason_label(decision, code) if code != "other" else ""
    if label and text:
        return f"{label}. {text}"
    return text or label
