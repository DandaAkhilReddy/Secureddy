# Contributing

Thanks for helping. Secureddy is built first for a small group of people we
know, so we keep it simple, careful and well tested.

1. **Open an issue first** for anything bigger than a small fix, so we can
   agree on the approach.
2. **Set up**:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   pre-commit install          # secret scan + lint on every commit
   python -m playwright install chromium
   ```
3. **Test**: `pytest` (unit and functional), `pytest -m integration` (real
   browser), `pytest -m postgres` (real PostgreSQL). New code comes with tests;
   keep coverage where it is.
4. **Lint**: `ruff check src tests`.
5. **Never commit secrets**, real email addresses or real email content. Use
   `example.com` addresses and made-up messages in fixtures.
6. **Write for the person, not the engineer.** Text people see in the app is
   short, plain English, no jargon.
7. Open a pull request with what changed and how you tested it.

By contributing you agree that your work is licensed under the Apache License
2.0, like the rest of the project. Please follow our
[Code of Conduct](CODE_OF_CONDUCT.md).
