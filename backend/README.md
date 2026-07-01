# Dreamers-Media Pacific — Financial Backend

Phase 1: PostgreSQL schema and migrations. Phase 2: Auth0-backed
authentication and RBAC enforced at the API layer. Later phases add the
core financial application logic and integrations.

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
- `invoices` — mutable while `status = 'draft'`; a trigger freezes
  financial fields once issued. The freeze is fail-closed: it compares
  the whole row (via `to_jsonb`) minus an explicit allowlist of fields
  that stay mutable (`status`, `issued_at`, `due_date`, `pdf_object_key`,
  `updated_by`, `updated_at`), rather than enumerating which columns to
  freeze — a future migration adding a new financial column is frozen
  automatically, with no matching trigger update required. A second
  trigger separately rejects any transition back to `status = 'draft'`
  from `issued`/`paid`/`void` — without it, reverting to draft would
  silently reopen the financial-field freeze on the *next* update
  (since the freeze trigger only applies while `OLD.status <> 'draft'`),
  a real gap caught by independent review; see
  `tests/test_invoice_immutability.py` for the closed-loop proof.
- `ledger_transactions` / `ledger_entries` — append-only, double-entry.
  No `UPDATE`/`DELETE` grant exists for `app_rw`, and a trigger blocks
  those operations (plus `TRUNCATE`) for every role, including the
  schema owner. A deferred constraint trigger rejects any transaction
  whose entries don't balance per currency. Corrections are new
  transactions referencing the original via
  `reversal_of_transaction_id`. `ledger_entries` is additionally
  hash-chained (`previous_hash`/`row_hash`, SHA-256 over every real
  column except the hash-chain bookkeeping columns themselves) via a
  dedicated single-row `ledger_chain_tip` table that the chaining
  trigger locks with `SELECT ... FOR UPDATE` — this (not a "last row of
  `ledger_entries`" lookup) is what makes two concurrent first-inserts
  serialize instead of both chaining from genesis. The hash uses an
  explicit column list rather than `to_jsonb(NEW) - excluded_keys`
  (unlike the invoice-freeze trigger) because `to_jsonb`'s key ordering
  for a row/composite value is not a documented cross-version guarantee,
  and this hash is meant to be independently reverifiable indefinitely,
  not just compared within one transaction; see
  `alembic/versions/0011_ledger_hash_chain.py` and
  `tests/test_ledger_hash_chain.py` (including a real two-connection
  concurrency test and a negative control proving an earlier version of
  this trigger missed `id`/`created_at` tampering) for the full
  reasoning and hash construction.
- `audit_log` — append-only for the same reason as the ledger (not
  hash-chained; the doc that scoped this asked for tamper-evidence on
  "the core ledger table" specifically).
- `tests/test_append_only_invariant.py` cross-checks
  `APPEND_ONLY_TABLES` against the database's actual privilege/trigger
  state (no `UPDATE`/`DELETE` grant + both guard triggers present) —
  update that list when adding a new append-only table so it's covered
  automatically instead of needing a bespoke test written per table.

See `alembic/versions/` for the full DDL; each migration's docstring/SQL
comments explain the reasoning inline.

## Auth and RBAC (Phase 2)

`app/auth.py` verifies bearer JWTs issued by Auth0: it fetches
`https://{AUTH0_DOMAIN}/.well-known/jwks.json`, checks the RS256
signature against the key named by the token's `kid`, and checks
`aud`/`iss`. The verified token's `sub` claim is looked up against
`users.external_auth_subject` — a token with no matching, active local
`users` row is rejected (403) even if the signature is genuinely valid;
provisioning a `users` row is a separate, deliberate step (not built yet
— there's no self-service signup endpoint, since every user of this
system is added by the owner).

`app/rbac.py`'s `require_role(*roles)` FastAPI dependency 403s unless the
caller holds one of the given roles in `user_roles` (non-revoked only).
The app always connects to Postgres as `app_rw` regardless of which
human role made the request — RBAC for the three business roles
(`owner_admin`/`bookkeeper`/`read_only_auditor`) is enforced at the API
layer per Phase 2's requirement, not by switching the DB connection's
role per request. The `app_rw`/`app_ro` DB-level split from Phase 1 is a
separate defense layer (protects the ledger/audit log if the
application itself is compromised), not a stand-in for human RBAC.

`app/main.py` currently exposes only the minimal surface needed to prove
the RBAC boundary (`POST /clients` for owner_admin/bookkeeper,
`POST`/`DELETE /admin/users/{id}/roles` for owner_admin only) — full
contract/invoice CRUD and audit-logging middleware are Phase 3. Path
parameters like `user_id`/`role` are typed (`uuid.UUID` /
`Literal[...]`) so malformed input is a 422 from FastAPI's own
validation, not an unhandled 500 from Postgres rejecting a bad UUID/enum
literal; a non-existent (but well-formed) `user_id` is a 404. A JWKS
fetch failure (Auth0 unreachable, or a `kid` that can't be resolved
because the refresh itself failed) is a 503, distinct from a genuinely
unrecognized `kid` (401) — see `JWKSUnavailableError` in `app/auth.py`.

**Not yet wired to a real tenant.** `AUTH0_DOMAIN`/`AUTH0_AUDIENCE` in
`.env.example` are placeholders; `tests/test_rbac.py` proves the
verification and RBAC logic entirely locally, signing test tokens with a
throwaway RSA keypair and substituting `StaticJWKSClient` for the real
JWKS fetch (see `app/auth.py`) — no live Auth0 credentials are required
to run the test suite. Swapping in a real tenant only requires setting
the two env vars; no code changes.

## Known verification gaps

- JWKSClient's live httpx fetch against Auth0's JWKS endpoint has not
  been executed end-to-end in this dev environment due to sandbox
  network restrictions; verify this specific fetch succeeds once
  deployed to any environment with real egress, before this handles
  production traffic.
