"""Guard against the "VARCHAR too small" class of bug.

SQLite (every other test) ignores ``VARCHAR(n)``; PostgreSQL (production)
enforces it. A Graph delta-link cursor in a ``String(100)`` column therefore
passed every test and crashed every worker cycle in production. These tests
fail as soon as someone adds or shrinks a bounded column without saying why
it is safe.
"""

from __future__ import annotations

from sqlalchemy import String, Text

from reddysec.store.models import Base

# Values a mail or identity provider hands us. We do not control their length,
# so they must be Text (or, at the very least, String(512+)).
PROVIDER_OPAQUE = {
    ("mailboxes", "cursor"),  # Gmail historyId, IMAP "uv:uid|uv:uid", Graph JSON with two delta links
    ("messages", "provider_message_id"),  # Graph immutable ids ~150+, IMAP "folder:uidvalidity:uid"
    ("messages", "thread_id"),  # Graph conversationId ~150+
    ("messages", "rfc_message_id"),  # Message-ID header; IMAP looks moved mail up by it
    ("audit_log", "target"),  # often a provider message id
    ("user_identities", "subject"),  # provider's id for the person (sub / oid)
    ("users", "google_sub"),
    ("mailbox_secrets", "ciphertext"),  # encrypted OAuth token bundle
    ("detonations", "target"),  # a URL or file name from an email
    ("reading_rooms", "url"),
}

OUR_ID = "id we generate (core.ids.new_id: prefix + 26 chars) or a job/session id of the same shape"
ENUM = "a value from a fixed set in our code"
CUT = "human text the writer truncates to the column size"
HASH = "our own fixed-size encoding (argon2 hash / AES-GCM token of a 32-char secret / key id)"

# Every bounded String column, with the reason its bound is safe. A new column
# must be added here (or be Text); a test below checks the sizes too.
BOUNDED: dict[tuple[str, str], tuple[int, str]] = {
    ("users", "id"): (40, OUR_ID),
    ("users", "display_name"): (200, CUT),
    ("users", "login_email"): (320, "email address: 254 is the protocol maximum"),
    ("users", "role"): (20, ENUM),
    ("users", "password_hash"): (300, HASH),
    ("users", "totp_secret_enc"): (300, HASH),
    ("users", "principal_id"): (40, OUR_ID),
    ("mailboxes", "id"): (40, OUR_ID),
    ("mailboxes", "user_id"): (40, OUR_ID),
    ("mailboxes", "provider"): (20, ENUM),
    ("mailboxes", "address"): (320, "email address: the web forms reject more than 254"),
    ("mailboxes", "mode"): (10, ENUM),
    ("mailboxes", "status"): (20, ENUM),
    ("mailbox_secrets", "mailbox_id"): (40, OUR_ID),
    ("mailbox_secrets", "kind"): (20, ENUM),
    ("mailbox_secrets", "key_id"): (20, HASH),
    ("mailbox_tasks", "id"): (40, OUR_ID),
    ("mailbox_tasks", "mailbox_id"): (40, OUR_ID),
    ("mailbox_tasks", "kind"): (20, ENUM),
    ("mailbox_tasks", "state"): (30, ENUM),
    ("mailbox_tasks", "reason"): (30, ENUM),
    ("mailbox_tasks", "requested_by"): (40, OUR_ID),
    ("messages", "id"): (40, OUR_ID),
    ("messages", "mailbox_id"): (40, OUR_ID),
    ("messages", "from_address"): (320, CUT),
    ("messages", "from_name"): (300, CUT),
    ("messages", "subject"): (1000, CUT),
    ("messages", "state"): (30, ENUM),
    ("messages", "lane"): (20, ENUM),
    ("messages", "level"): (20, ENUM),
    ("detonations", "job_id"): (40, OUR_ID),
    ("detonations", "message_id"): (40, OUR_ID),
    ("detonations", "kind"): (10, ENUM),
    ("detonations", "status"): (20, ENUM),
    ("detonations", "sandbox_backend"): (20, ENUM),
    ("hold_heartbeats", "mailbox_id"): (40, OUR_ID),
    ("contacts", "id"): (40, OUR_ID),
    ("contacts", "mailbox_id"): (40, OUR_ID),
    ("contacts", "address"): (320, CUT),
    ("sender_feedback", "id"): (40, OUR_ID),
    ("sender_feedback", "mailbox_id"): (40, OUR_ID),
    ("sender_feedback", "scope"): (10, ENUM),
    ("sender_feedback", "value"): (320, "a stored from_address (cut to 320) or a domain (max 253)"),
    ("sender_feedback", "decision"): (10, ENUM),
    ("sender_feedback", "source_message_id"): (40, OUR_ID),
    ("sender_feedback", "created_by"): (40, OUR_ID),
    ("user_identities", "id"): (40, OUR_ID),
    ("user_identities", "user_id"): (40, OUR_ID),
    ("user_identities", "provider"): (20, ENUM),
    ("user_identities", "email"): (320, CUT),
    ("user_identities", "tenant"): (64, "Microsoft tenant GUID (36), cut to 64"),
    ("sender_trust_stats", "id"): (40, OUR_ID),
    ("sender_trust_stats", "mailbox_id"): (40, OUR_ID),
    ("sender_trust_stats", "scope"): (10, ENUM),
    ("sender_trust_stats", "value"): (320, CUT),
    ("sender_trust_stats", "last_outcome"): (20, ENUM),
    ("reading_rooms", "session_id"): (40, OUR_ID),
    ("reading_rooms", "user_id"): (40, OUR_ID),
    ("reading_rooms", "message_id"): (40, OUR_ID),
    ("reading_rooms", "state"): (20, ENUM),
    ("notifications", "id"): (40, OUR_ID),
    ("notifications", "user_id"): (40, OUR_ID),
    ("notifications", "message_id"): (40, OUR_ID),
    ("notifications", "channel"): (20, ENUM),
    ("notifications", "level"): (20, ENUM),
    ("notifications", "title"): (300, CUT),
    ("audit_log", "id"): (40, OUR_ID),
    ("audit_log", "actor_id"): (40, OUR_ID),
    ("audit_log", "actor_role"): (20, ENUM),
    ("audit_log", "action"): (60, ENUM),
    ("audit_log", "mailbox_id"): (40, OUR_ID),
    ("feedback_reasons", "id"): (40, OUR_ID),
    ("feedback_reasons", "sender_feedback_id"): (40, OUR_ID),
    ("feedback_reasons", "message_id"): (40, OUR_ID),
    ("feedback_reasons", "user_id"): (40, OUR_ID),
    ("feedback_reasons", "decision"): (10, ENUM),
    ("feedback_reasons", "reason_code"): (30, ENUM),
    ("feedback_reasons", "reason_text"): (500, CUT),
    ("assistant_conversations", "id"): (40, OUR_ID),
    ("assistant_conversations", "user_id"): (40, OUR_ID),
    ("assistant_conversations", "title"): (200, CUT),
    ("assistant_messages", "id"): (40, OUR_ID),
    ("assistant_messages", "conversation_id"): (40, OUR_ID),
    ("assistant_messages", "role"): (10, ENUM),
    ("user_preferences", "id"): (40, OUR_ID),
    ("user_preferences", "user_id"): (40, OUR_ID),
    ("user_preferences", "key"): (40, ENUM),
    ("user_preferences", "value"): (200, "a value from a fixed set or one of our ids"),
    ("user_sessions", "id"): (64, HASH),
    ("user_sessions", "handle"): (40, OUR_ID),
    ("user_sessions", "user_id"): (40, OUR_ID),
    ("user_sessions", "user_agent"): (120, CUT),
    ("user_sessions", "ip_prefix"): (64, "an IPv4 /24 or IPv6 /48 prefix we compute"),
    ("user_sessions", "auth_method"): (20, ENUM),
    ("user_sessions", "revoked_reason"): (30, ENUM),
    ("app_locks", "user_id"): (40, OUR_ID),
    ("app_locks", "kind"): (10, ENUM),
    ("app_locks", "secret_hash"): (300, HASH),
    ("user_passkeys", "id"): (40, OUR_ID),
    ("user_passkeys", "user_id"): (40, OUR_ID),
    ("user_passkeys", "name"): (100, CUT),
    ("user_mfa", "user_id"): (40, OUR_ID),
    ("mfa_recovery_codes", "id"): (40, OUR_ID),
    ("mfa_recovery_codes", "user_id"): (40, OUR_ID),
    ("mfa_recovery_codes", "code_hash"): (300, HASH),
    ("mfa_trusted_devices", "id"): (64, HASH),
    ("mfa_trusted_devices", "user_id"): (40, OUR_ID),
    ("mfa_trusted_devices", "session_id"): (64, HASH),
    ("mfa_trusted_devices", "user_agent"): (120, CUT),
}


def _columns():
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            yield (table.name, column.name), column


def _bounded():
    return {
        key: column.type.length
        for key, column in _columns()
        if isinstance(column.type, String) and not isinstance(column.type, Text)
    }


def test_provider_values_are_text_or_wide():
    columns = dict(_columns())
    for key in PROVIDER_OPAQUE:
        column_type = columns[key].type
        wide = isinstance(column_type, Text) or (column_type.length or 0) >= 512
        assert wide, f"{key} holds values a provider controls; make it Text (it is {column_type})"


def test_every_bounded_column_is_justified():
    actual = _bounded()
    unexplained = sorted(set(actual) - set(BOUNDED))
    assert not unexplained, (
        f"new bounded String columns {unexplained}: make them Text, or add them to BOUNDED with the reason "
        "their writers can never exceed the size (and truncate cosmetic text in its writer)"
    )
    stale = sorted(set(BOUNDED) - set(actual))
    assert not stale, f"BOUNDED lists columns that are gone or now Text: {stale}"
    for key, length in actual.items():
        assert length == BOUNDED[key][0], f"{key} changed size to {length}; re-check its writers and BOUNDED"


def test_no_provider_value_hides_in_a_bounded_column():
    assert not PROVIDER_OPAQUE & set(_bounded())


def test_our_ids_fit():
    from reddysec.core.ids import new_id

    longest_prefix = max(len(p) for p in ("usr", "mbx", "msg", "aud", "ntf", "sfb", "sts", "uid", "tsk", "room"))
    assert len(new_id("x" * longest_prefix)) <= 40
    assert len("det_" + "0" * 26) <= 40  # analysis.pipeline._job_id
