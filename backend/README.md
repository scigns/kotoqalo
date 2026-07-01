# Dreamers-Media Pacific — Financial Backend

Phase 1: PostgreSQL schema and migrations. The FastAPI application layer
is added in later phases.

## Local setup

Requires PostgreSQL 16+ locally.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

Create the database and a schema-owning role (production provisions this
via infrastructure-as-code, not by hand — this is the local dev
equivalent):

```sql
CREATE ROLE dreamers_migrator LOGIN CREATEROLE PASSWORD '...';
CREATE DATABASE dreamers_media OWNER dreamers_migrator;
```

Copy `.env.example` to `.env` and fill in real connection strings (the
`.env` file is gitignored and must never be committed). Then:

```bash
set -a && source .env && set +a
alembic upgrade head
```

The first migration run also creates the `app_rw` (application runtime)
and `app_ro` (read-only) database roles. Set their passwords out-of-band
(secrets manager in production; `ALTER ROLE ... PASSWORD` locally) —
migrations never embed credentials.

## Running tests

```bash
set -a && source .env && set +a
pytest -v
```

Tests run inside a single rolled-back transaction per test (using
`SET ROLE` to switch privilege context and `SAVEPOINT` to recover from
expected failures), so nothing persists in the database — including
successfully-inserted rows in the append-only ledger/audit tables, which
have no supported cleanup path by design.

## Schema overview

- `currencies`, `chart_of_accounts` — reference data (AUD/FJD/USD seeded;
  add a currency by inserting a row, not a migration).
- `users`, `user_roles` — identity is delegated to a managed auth
  provider (Phase 2); `user_roles` is soft-revoked (`revoked_at`), never
  deleted, to preserve RBAC history.
- `clients`, `contracts`, `milestones` — standard mutable entities.
  Contact PII on `clients` is stored as ciphertext columns
  (`*_encrypted`), to be populated by application-layer envelope
  encryption in Phase 3.
- `invoices` — mutable while `status = 'draft'`; a trigger freezes the
  financial fields (amounts, currency, invoice number) once issued.
- `ledger_transactions` / `ledger_entries` — append-only, double-entry.
  No `UPDATE`/`DELETE` grant exists for `app_rw`, and a trigger blocks
  those operations (plus `TRUNCATE`) for every role, including the
  schema owner. A deferred constraint trigger rejects any transaction
  whose entries don't balance per currency. Corrections are new
  transactions referencing the original via
  `reversal_of_transaction_id`. `ledger_entries` is additionally
  hash-chained (`previous_hash`/`row_hash`, SHA-256 over each row's
  plaintext fields) so tampering is detectable by recomputing the chain
  independently of the live database — see
  `alembic/versions/0011_ledger_hash_chain.py` and
  `tests/test_ledger_hash_chain.py` for the exact hash construction.
- `audit_log` — append-only for the same reason as the ledger (not
  hash-chained; the doc that scoped this asked for tamper-evidence on
  "the core ledger table" specifically).

See `alembic/versions/` for the full DDL; each migration's docstring/SQL
comments explain the reasoning inline.
