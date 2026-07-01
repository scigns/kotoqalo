"""FastAPI app: auth/RBAC (Phase 2), field-level encryption for client
PII, and contract/milestone CRUD with audit logging on every mutating
endpoint (Phase 3). Invoice generation and ledger posting live in this
module too; see the section breaks below.
"""

import uuid
from datetime import date as date_type
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status

from app.audit import record_audit_event
from app.auth import AuthenticatedUser, get_current_user
from app.crud_helpers import apply_partial_update, fetch_row_as_dict, require_exists
from app.crypto import KeyProvider, decrypt_field, encrypt_field, get_key_provider
from app.db import get_db
from app.invoicing import allocate_invoice_number
from app.ledger import post_ledger_transaction
from app.pdf import generate_invoice_pdf, read_invoice_pdf, store_invoice_pdf
from app.rbac import require_role
from app.schemas import (
    ClientCreate,
    ClientOut,
    ContractCreate,
    ContractOut,
    ContractUpdate,
    ExpenseCreate,
    InvoiceCreate,
    InvoiceOut,
    MilestoneCreate,
    MilestoneOut,
    MilestoneUpdate,
    ReceiptCreate,
    RoleGrant,
)

app = FastAPI(title="Dreamers-Media Pacific Financial Backend")

RoleName = Literal["owner_admin", "bookkeeper", "read_only_auditor"]


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/me")
def me(user: AuthenticatedUser = Depends(get_current_user)):
    return {"user_id": user.user_id, "roles": sorted(user.roles)}


# --------------------------------------------------------------------------
# Clients (Phase 2 create/read; PII fields encrypted, see app/crypto.py)
# --------------------------------------------------------------------------


def _encrypt_optional(key: bytes, value: Optional[str]) -> Optional[bytes]:
    return encrypt_field(key, value) if value is not None else None


def _decrypt_optional(key: bytes, value) -> Optional[str]:
    return decrypt_field(key, bytes(value)) if value is not None else None


@app.post("/clients", status_code=201)
def create_client(
    payload: ClientCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
    key_provider: KeyProvider = Depends(get_key_provider),
):
    key = key_provider.get_data_encryption_key()
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO clients (
                display_name, country_code,
                contact_email_encrypted, contact_phone_encrypted, billing_address_encrypted,
                created_by
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                payload.display_name,
                payload.country_code,
                _encrypt_optional(key, payload.contact_email),
                _encrypt_optional(key, payload.contact_phone),
                _encrypt_optional(key, payload.billing_address),
                user.user_id,
            ),
        )
        client_id = cur.fetchone()[0]

    # Contact fields are deliberately excluded from the audit trail --
    # neither plaintext nor ciphertext bytes belong in audit_log, which
    # is not itself field-encrypted (mirrors the "don't log full email
    # bodies with banking details" principle from the Phase 4b plan).
    record_audit_event(
        db,
        actor_user_id=user.user_id,
        actor_roles=user.roles,
        action="CREATE",
        entity_type="client",
        entity_id=str(client_id),
        before_state=None,
        after_state={"display_name": payload.display_name, "country_code": payload.country_code},
    )
    return {"id": str(client_id)}


@app.get("/clients/{client_id}", response_model=ClientOut)
def get_client(
    client_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
    key_provider: KeyProvider = Depends(get_key_provider),
):
    del user  # any authenticated role may read, including read_only_auditor
    key = key_provider.get_data_encryption_key()
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT id, display_name, country_code,
                   contact_email_encrypted, contact_phone_encrypted, billing_address_encrypted
            FROM clients WHERE id = %s
            """,
            (str(client_id),),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such client")

    return ClientOut(
        id=str(row[0]),
        display_name=row[1],
        country_code=row[2],
        contact_email=_decrypt_optional(key, row[3]),
        contact_phone=_decrypt_optional(key, row[4]),
        billing_address=_decrypt_optional(key, row[5]),
    )


# --------------------------------------------------------------------------
# Access control (Phase 2)
# --------------------------------------------------------------------------


@app.post("/admin/users/{user_id}/roles", status_code=201)
def grant_role(
    user_id: uuid.UUID,
    payload: RoleGrant,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    """Access-control settings: owner_admin only, deliberately excluding
    bookkeeper even though bookkeeper can write elsewhere in the app.

    user_id/role are typed (uuid.UUID / Literal[...]) rather than plain
    str so FastAPI rejects malformed input with a 422 before it ever
    reaches a query -- a malformed UUID or invalid role name previously
    reached Postgres as a raw string and surfaced as an unhandled 500
    (invalid input syntax for uuid / invalid input value for enum),
    potentially leaking DB error detail in the response.
    """
    require_exists(db, "users", user_id, "no such user")

    cur = db.cursor()
    cur.execute(
        "SELECT granted_at, revoked_at FROM user_roles WHERE user_id = %s AND role = %s",
        (str(user_id), payload.role),
    )
    before_row = cur.fetchone()
    before_state = {"granted_at": before_row[0], "revoked_at": before_row[1]} if before_row else None

    cur.execute(
        """
        INSERT INTO user_roles (user_id, role, granted_by)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id, role)
        DO UPDATE SET revoked_at = NULL, granted_by = EXCLUDED.granted_by, granted_at = now()
        """,
        (str(user_id), payload.role, actor.user_id),
    )

    record_audit_event(
        db,
        actor_user_id=actor.user_id,
        actor_roles=actor.roles,
        action="GRANT_ROLE",
        entity_type="user_role",
        entity_id=str(user_id),
        before_state=before_state,
        after_state={"user_id": str(user_id), "role": payload.role, "revoked_at": None},
    )
    return {"status": "granted"}


@app.delete("/admin/users/{user_id}/roles/{role}")
def revoke_role(
    user_id: uuid.UUID,
    role: RoleName,
    actor: AuthenticatedUser = Depends(require_role("owner_admin")),
    db=Depends(get_db),
):
    require_exists(db, "users", user_id, "no such user")

    cur = db.cursor()
    cur.execute(
        "UPDATE user_roles SET revoked_at = now() WHERE user_id = %s AND role = %s AND revoked_at IS NULL",
        (str(user_id), role),
    )

    record_audit_event(
        db,
        actor_user_id=actor.user_id,
        actor_roles=actor.roles,
        action="REVOKE_ROLE",
        entity_type="user_role",
        entity_id=str(user_id),
        before_state={"role": role, "revoked_at": None},
        after_state={"role": role, "revoked_at": "now"},
    )
    return {"status": "revoked"}


# --------------------------------------------------------------------------
# Contracts (standard mutability -- only the ledger is append-only)
# --------------------------------------------------------------------------

_CONTRACT_COLUMNS = [
    "id", "client_id", "title", "description", "currency_code",
    "total_value", "status", "start_date", "end_date",
]


def _contract_out(row: dict) -> ContractOut:
    return ContractOut(
        id=str(row["id"]),
        client_id=str(row["client_id"]),
        title=row["title"],
        description=row["description"],
        currency_code=row["currency_code"],
        total_value=row["total_value"],
        status=row["status"],
        start_date=row["start_date"],
        end_date=row["end_date"],
    )


@app.post("/contracts", status_code=201, response_model=ContractOut)
def create_contract(
    payload: ContractCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    require_exists(db, "clients", payload.client_id, "no such client")

    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO contracts (client_id, title, description, currency_code, total_value, start_date, end_date, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            payload.client_id, payload.title, payload.description, payload.currency_code,
            payload.total_value, payload.start_date, payload.end_date, user.user_id,
        ),
    )
    contract_id = cur.fetchone()[0]
    row = fetch_row_as_dict(db, "contracts", _CONTRACT_COLUMNS, contract_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="CREATE", entity_type="contract", entity_id=str(contract_id),
        before_state=None, after_state=row,
    )
    return _contract_out(row)


@app.get("/contracts/{contract_id}", response_model=ContractOut)
def get_contract(
    contract_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    row = fetch_row_as_dict(db, "contracts", _CONTRACT_COLUMNS, contract_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such contract")
    return _contract_out(row)


@app.get("/contracts", response_model=list[ContractOut])
def list_contracts(
    client_id: Optional[uuid.UUID] = Query(default=None),
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    cur = db.cursor()
    column_list = ", ".join(_CONTRACT_COLUMNS)
    if client_id is not None:
        cur.execute(f"SELECT {column_list} FROM contracts WHERE client_id = %s ORDER BY created_at", (str(client_id),))
    else:
        cur.execute(f"SELECT {column_list} FROM contracts ORDER BY created_at")
    rows = [dict(zip(_CONTRACT_COLUMNS, row)) for row in cur.fetchall()]
    return [_contract_out(row) for row in rows]


@app.patch("/contracts/{contract_id}", response_model=ContractOut)
def update_contract(
    contract_id: uuid.UUID,
    payload: ContractUpdate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    before = fetch_row_as_dict(db, "contracts", _CONTRACT_COLUMNS, contract_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such contract")

    updates = payload.model_dump(exclude_unset=True)
    apply_partial_update(db, "contracts", contract_id, updates, user.user_id)
    after = fetch_row_as_dict(db, "contracts", _CONTRACT_COLUMNS, contract_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="UPDATE", entity_type="contract", entity_id=str(contract_id),
        before_state=before, after_state=after,
    )
    return _contract_out(after)


# --------------------------------------------------------------------------
# Milestones (standard mutability, belong to a contract)
# --------------------------------------------------------------------------

_MILESTONE_COLUMNS = [
    "id", "contract_id", "title", "description", "amount",
    "currency_code", "due_date", "status",
]


def _milestone_out(row: dict) -> MilestoneOut:
    return MilestoneOut(
        id=str(row["id"]),
        contract_id=str(row["contract_id"]),
        title=row["title"],
        description=row["description"],
        amount=row["amount"],
        currency_code=row["currency_code"],
        due_date=row["due_date"],
        status=row["status"],
    )


@app.post("/milestones", status_code=201, response_model=MilestoneOut)
def create_milestone(
    payload: MilestoneCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    require_exists(db, "contracts", payload.contract_id, "no such contract")

    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO milestones (contract_id, title, description, amount, currency_code, due_date, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            payload.contract_id, payload.title, payload.description,
            payload.amount, payload.currency_code, payload.due_date, user.user_id,
        ),
    )
    milestone_id = cur.fetchone()[0]
    row = fetch_row_as_dict(db, "milestones", _MILESTONE_COLUMNS, milestone_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="CREATE", entity_type="milestone", entity_id=str(milestone_id),
        before_state=None, after_state=row,
    )
    return _milestone_out(row)


@app.get("/milestones/{milestone_id}", response_model=MilestoneOut)
def get_milestone(
    milestone_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    row = fetch_row_as_dict(db, "milestones", _MILESTONE_COLUMNS, milestone_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such milestone")
    return _milestone_out(row)


@app.get("/contracts/{contract_id}/milestones", response_model=list[MilestoneOut])
def list_milestones_for_contract(
    contract_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    require_exists(db, "contracts", contract_id, "no such contract")
    cur = db.cursor()
    column_list = ", ".join(_MILESTONE_COLUMNS)
    cur.execute(f"SELECT {column_list} FROM milestones WHERE contract_id = %s ORDER BY created_at", (str(contract_id),))
    rows = [dict(zip(_MILESTONE_COLUMNS, row)) for row in cur.fetchall()]
    return [_milestone_out(row) for row in rows]


@app.patch("/milestones/{milestone_id}", response_model=MilestoneOut)
def update_milestone(
    milestone_id: uuid.UUID,
    payload: MilestoneUpdate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    before = fetch_row_as_dict(db, "milestones", _MILESTONE_COLUMNS, milestone_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such milestone")

    updates = payload.model_dump(exclude_unset=True)
    apply_partial_update(db, "milestones", milestone_id, updates, user.user_id)
    after = fetch_row_as_dict(db, "milestones", _MILESTONE_COLUMNS, milestone_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="UPDATE", entity_type="milestone", entity_id=str(milestone_id),
        before_state=before, after_state=after,
    )
    return _milestone_out(after)


# --------------------------------------------------------------------------
# Invoices: multi-currency, sequential numbering, PDF generation, ledger
# posting on issuance. total_amount is always computed server-side
# (subtotal + tax) -- never accepted from the client -- so it can never
# disagree with its own components.
# --------------------------------------------------------------------------

_INVOICE_COLUMNS = [
    "id", "invoice_number", "invoice_year", "invoice_seq", "contract_id",
    "milestone_id", "client_id", "currency_code", "subtotal_amount",
    "tax_amount", "total_amount", "status", "issued_at", "due_date",
]


def _invoice_out(row: dict) -> InvoiceOut:
    return InvoiceOut(
        id=str(row["id"]),
        invoice_number=row["invoice_number"],
        invoice_year=row["invoice_year"],
        invoice_seq=row["invoice_seq"],
        contract_id=str(row["contract_id"]),
        milestone_id=str(row["milestone_id"]) if row["milestone_id"] else None,
        client_id=str(row["client_id"]),
        currency_code=row["currency_code"],
        subtotal_amount=row["subtotal_amount"],
        tax_amount=row["tax_amount"],
        total_amount=row["total_amount"],
        status=row["status"],
        issued_at=str(row["issued_at"]) if row["issued_at"] else None,
        due_date=row["due_date"],
    )


@app.post("/invoices", status_code=201, response_model=InvoiceOut)
def create_invoice(
    payload: InvoiceCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    require_exists(db, "contracts", payload.contract_id, "no such contract")
    require_exists(db, "clients", payload.client_id, "no such client")
    if payload.milestone_id is not None:
        require_exists(db, "milestones", payload.milestone_id, "no such milestone")
        cur = db.cursor()
        cur.execute("SELECT contract_id FROM milestones WHERE id = %s", (payload.milestone_id,))
        if str(cur.fetchone()[0]) != str(payload.contract_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "milestone does not belong to the given contract")

    total_amount = payload.subtotal_amount + payload.tax_amount
    year = date_type.today().year
    invoice_number, invoice_seq = allocate_invoice_number(db, year)

    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO invoices (
            invoice_number, invoice_year, invoice_seq, contract_id, milestone_id, client_id,
            currency_code, subtotal_amount, tax_amount, total_amount, due_date, created_by
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            invoice_number, year, invoice_seq, payload.contract_id, payload.milestone_id, payload.client_id,
            payload.currency_code, payload.subtotal_amount, payload.tax_amount, total_amount,
            payload.due_date, user.user_id,
        ),
    )
    invoice_id = cur.fetchone()[0]
    row = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="CREATE", entity_type="invoice", entity_id=str(invoice_id),
        before_state=None, after_state=row,
    )
    return _invoice_out(row)


@app.get("/invoices/{invoice_id}", response_model=InvoiceOut)
def get_invoice(
    invoice_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    row = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invoice")
    return _invoice_out(row)


@app.get("/invoices", response_model=list[InvoiceOut])
def list_invoices(
    contract_id: Optional[uuid.UUID] = Query(default=None),
    client_id: Optional[uuid.UUID] = Query(default=None),
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    cur = db.cursor()
    column_list = ", ".join(_INVOICE_COLUMNS)
    clauses = []
    params: list = []
    if contract_id is not None:
        clauses.append("contract_id = %s")
        params.append(str(contract_id))
    if client_id is not None:
        clauses.append("client_id = %s")
        params.append(str(client_id))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    cur.execute(f"SELECT {column_list} FROM invoices {where} ORDER BY created_at", params)
    rows = [dict(zip(_INVOICE_COLUMNS, row)) for row in cur.fetchall()]
    return [_invoice_out(row) for row in rows]


@app.post("/invoices/{invoice_id}/issue", response_model=InvoiceOut)
def issue_invoice(
    invoice_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
    key_provider: KeyProvider = Depends(get_key_provider),
):
    before = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invoice")
    if before["status"] != "draft":
        raise HTTPException(status.HTTP_409_CONFLICT, f"invoice has status {before['status']!r}, can only issue from draft")

    cur = db.cursor()
    cur.execute("SELECT display_name, contact_email_encrypted FROM clients WHERE id = %s", (str(before["client_id"]),))
    client_display_name, _ = cur.fetchone()
    cur.execute("SELECT title FROM contracts WHERE id = %s", (str(before["contract_id"]),))
    contract_title = cur.fetchone()[0]
    milestone_title = None
    if before["milestone_id"] is not None:
        cur.execute("SELECT title FROM milestones WHERE id = %s", (str(before["milestone_id"]),))
        milestone_title = cur.fetchone()[0]
    del key_provider  # PDF only uses non-encrypted fields (names/titles), not contact details

    pdf_bytes = generate_invoice_pdf(before, client_display_name, contract_title, milestone_title)
    object_key = store_invoice_pdf(str(invoice_id), pdf_bytes)

    cur.execute(
        "UPDATE invoices SET status = 'issued', issued_at = now(), pdf_object_key = %s WHERE id = %s",
        (object_key, str(invoice_id)),
    )

    ledger_entries = [
        {"account_code": "1000", "direction": "debit", "amount": before["total_amount"], "currency_code": before["currency_code"]},
        {"account_code": "4000", "direction": "credit", "amount": before["subtotal_amount"], "currency_code": before["currency_code"]},
    ]
    if before["tax_amount"] > 0:
        ledger_entries.append(
            {"account_code": "2000", "direction": "credit", "amount": before["tax_amount"], "currency_code": before["currency_code"]}
        )
    try:
        post_ledger_transaction(
            db,
            actor_user_id=user.user_id,
            transaction_date=date_type.today(),
            description=f"Invoice {before['invoice_number']} issued",
            reference_type="invoice_issued",
            reference_id=str(invoice_id),
            entries=ledger_entries,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    after = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)
    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="ISSUE", entity_type="invoice", entity_id=str(invoice_id),
        before_state=before, after_state=after,
    )
    return _invoice_out(after)


@app.post("/invoices/{invoice_id}/void", response_model=InvoiceOut)
def void_invoice(
    invoice_id: uuid.UUID,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    before = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invoice")
    if before["status"] not in ("draft", "issued"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"invoice has status {before['status']!r}, cannot void")

    cur = db.cursor()
    cur.execute("UPDATE invoices SET status = 'void' WHERE id = %s", (str(invoice_id),))
    after = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, invoice_id)

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="VOID", entity_type="invoice", entity_id=str(invoice_id),
        before_state=before, after_state=after,
    )
    return _invoice_out(after)


@app.get("/invoices/{invoice_id}/pdf")
def get_invoice_pdf(
    invoice_id: uuid.UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    db=Depends(get_db),
):
    del user
    row = fetch_row_as_dict(db, "invoices", ["pdf_object_key"], invoice_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invoice")
    if row["pdf_object_key"] is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invoice has not been issued yet -- no PDF exists")
    pdf_bytes = read_invoice_pdf(row["pdf_object_key"])
    return Response(content=pdf_bytes, media_type="application/pdf")


# --------------------------------------------------------------------------
# Manually recorded receipts and expenses (ledger posting outside of
# invoice issuance).
# --------------------------------------------------------------------------


@app.post("/receipts", status_code=201)
def create_receipt(
    payload: ReceiptCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    require_exists(db, "clients", payload.client_id, "no such client")

    invoice_before = None
    if payload.invoice_id is not None:
        invoice_before = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, payload.invoice_id)
        if invoice_before is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invoice")
        if invoice_before["status"] != "issued":
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"invoice has status {invoice_before['status']!r}, can only record a receipt against an issued invoice",
            )

    try:
        transaction_id = post_ledger_transaction(
            db,
            actor_user_id=user.user_id,
            transaction_date=payload.received_date,
            description=payload.description,
            reference_type="receipt",
            reference_id=payload.invoice_id,
            entries=[
                {"account_code": "1010", "direction": "debit", "amount": payload.amount, "currency_code": payload.currency_code},
                {"account_code": "1000", "direction": "credit", "amount": payload.amount, "currency_code": payload.currency_code},
            ],
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    if payload.invoice_id is not None:
        cur = db.cursor()
        cur.execute("UPDATE invoices SET status = 'paid' WHERE id = %s", (payload.invoice_id,))
        invoice_after = fetch_row_as_dict(db, "invoices", _INVOICE_COLUMNS, payload.invoice_id)
        record_audit_event(
            db, actor_user_id=user.user_id, actor_roles=user.roles,
            action="MARK_PAID", entity_type="invoice", entity_id=payload.invoice_id,
            before_state=invoice_before, after_state=invoice_after,
        )

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="CREATE", entity_type="receipt", entity_id=transaction_id,
        before_state=None,
        after_state={
            "client_id": payload.client_id, "invoice_id": payload.invoice_id,
            "amount": payload.amount, "currency_code": payload.currency_code,
        },
    )
    return {"ledger_transaction_id": transaction_id}


@app.post("/expenses", status_code=201)
def create_expense(
    payload: ExpenseCreate,
    user: AuthenticatedUser = Depends(require_role("owner_admin", "bookkeeper")),
    db=Depends(get_db),
):
    try:
        transaction_id = post_ledger_transaction(
            db,
            actor_user_id=user.user_id,
            transaction_date=payload.expense_date,
            description=payload.description,
            reference_type="expense",
            reference_id=None,
            entries=[
                {"account_code": payload.account_code, "direction": "debit", "amount": payload.amount, "currency_code": payload.currency_code},
                {"account_code": "1010", "direction": "credit", "amount": payload.amount, "currency_code": payload.currency_code},
            ],
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    record_audit_event(
        db, actor_user_id=user.user_id, actor_roles=user.roles,
        action="CREATE", entity_type="expense", entity_id=transaction_id,
        before_state=None,
        after_state={"account_code": payload.account_code, "amount": payload.amount, "currency_code": payload.currency_code},
    )
    return {"ledger_transaction_id": transaction_id}
