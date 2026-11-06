""""Ask Secureddy": an in-app assistant the client can talk to about their mail.

Architecture::

    browser (static/assistant.js, no innerHTML)
        |  POST /assistant/send  (CSRF form post, JSON back)
    web/routes/assistant.py  -- auth, CSRF, authz 404s, rendering
        |
    agent.Assistant.ask      -- daily limit, audit row, the tool loop
        |            \\
    llm.ChatModel     tools.ToolBox  -- read-only, scoped to the user's mailboxes
    (Anthropic /      (list_messages, get_message_report, get_stats,
     Foundry /         list_trusted_and_blocked, explain_signal,
     Azure OpenAI)     propose_mark_safe / propose_mark_fake / propose_recheck)
        |
    store            -- assistant_conversations / assistant_messages

The model never acts. Email subjects and sender names are written by
attackers, so anything the model "decides" is at most a proposal card; the
only thing that changes data is the person clicking a real, CSRF-protected
button that posts to the same routes as the report page. See ``agent`` for
the full reasoning and ``tools`` for the untrusted-field wrapping.

Settings (``RS_`` environment variables): ``ASSISTANT_PROVIDER`` (none,
anthropic, azure_foundry, azure_openai; empty follows ``LLM_PROVIDER``),
``ASSISTANT_MODEL``, ``ASSISTANT_MAX_TURNS``, ``ASSISTANT_DAILY_MESSAGE_LIMIT``.
API keys are the existing ``ANTHROPIC_API_KEY`` / ``AZURE_FOUNDRY_*`` /
``AZURE_OPENAI_*``.
"""
