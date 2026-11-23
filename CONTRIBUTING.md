# Contributing to Sentinel

Thank you for your interest in improving Sentinel. This guide explains how to set up a development environment and what a change needs before it can be merged.

## Ground rules

- Sentinel is a defensive platform. Contributions that add offensive capability (exploitation, credential harvesting, stealth, persistence) will not be accepted.
- Use synthetic data only. Never commit real logs, credentials, `.env` files or database dumps.
- Detection logic must stay deterministic, documented and tested. AI and machine learning may add context but must never decide alerts or scores.

## Development setup

Follow "Option B" in the [README](README.md#installation). In short:

```bash
cd backend && pip install -r requirements-dev.txt && alembic upgrade head
cd frontend && npm ci
```

Backend tests need a PostgreSQL database for tests:

```bash
createdb sentinel_test --owner sentinel
export SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:<password>@localhost:5432/sentinel_test
```

## Before opening a pull request

Run every check that CI runs:

```bash
cd backend && pytest                      # all tests must pass
cd frontend && npm run typecheck && npm test && npm run build
```

And make sure that:

1. New behaviour has tests. A new detection rule needs normal, suspicious, borderline, incomplete-data and out-of-window cases in `tests/test_detection_rules.py`.
2. New endpoints declare a permission with `Depends(require(Perm.X))` and are added to the authorization matrix test.
3. Database changes come with an Alembic migration (`alembic revision --autogenerate -m "..."`) that you have reviewed and run on an empty database.
4. Documentation in `docs/` matches the change (rules, API, schema).
5. No secrets, real data or personal information appear in code, tests, fixtures or screenshots.

## Adding a detection rule

1. Add its definition (ID, description, parameters, investigation steps, false-positive notes) to `backend/app/detection/definitions.py`.
2. Implement a `Rule` subclass in `backend/app/detection/rules.py` with `relevant()`, `evaluate()` and, if it needs history, `lookback()`. Keep it pure: no database access.
3. Register it in `RULES` and add tests.
4. Add a scenario to `scripts/generate_sample_data.py` if the demo should show it, and regenerate the sample files.
5. Regenerate the rule reference in `docs/detection-rules.md`.

## Style

- Python: type hints, small functions, clear names, comments where they explain why. Keep business logic in services, not in route functions.
- TypeScript: strict mode, no `any`, components small enough to read on one screen.
- Commit messages: imperative mood, short summary line, details in the body when useful.

## Reporting bugs

Open an issue with steps to reproduce, expected and actual behaviour, and logs if relevant. Report security problems privately as described in [SECURITY.md](SECURITY.md).
