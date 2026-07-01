from datetime import date
from decimal import Decimal
from typing import Literal, Optional

from pydantic import BaseModel


class ClientCreate(BaseModel):
    display_name: str
    country_code: str
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    billing_address: Optional[str] = None


class ClientOut(BaseModel):
    id: str
    display_name: str
    country_code: str
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    billing_address: Optional[str] = None


class RoleGrant(BaseModel):
    role: Literal["owner_admin", "bookkeeper", "read_only_auditor"]


ContractStatus = Literal["draft", "active", "completed", "cancelled"]
MilestoneStatus = Literal["pending", "invoiced", "paid", "cancelled"]


class ContractCreate(BaseModel):
    client_id: str
    title: str
    description: Optional[str] = None
    currency_code: str
    total_value: Decimal
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class ContractUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ContractStatus] = None
    total_value: Optional[Decimal] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class ContractOut(BaseModel):
    id: str
    client_id: str
    title: str
    description: Optional[str] = None
    currency_code: str
    total_value: Decimal
    status: str
    start_date: Optional[date] = None
    end_date: Optional[date] = None


class MilestoneCreate(BaseModel):
    contract_id: str
    title: str
    description: Optional[str] = None
    amount: Decimal
    currency_code: str
    due_date: Optional[date] = None


class MilestoneUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    amount: Optional[Decimal] = None
    due_date: Optional[date] = None
    status: Optional[MilestoneStatus] = None


class MilestoneOut(BaseModel):
    id: str
    contract_id: str
    title: str
    description: Optional[str] = None
    amount: Decimal
    currency_code: str
    due_date: Optional[date] = None
    status: str


class InvoiceCreate(BaseModel):
    contract_id: str
    milestone_id: Optional[str] = None
    client_id: str
    currency_code: str
    subtotal_amount: Decimal
    tax_amount: Decimal = Decimal("0")
    due_date: Optional[date] = None


class InvoiceOut(BaseModel):
    id: str
    invoice_number: str
    invoice_year: int
    invoice_seq: int
    contract_id: str
    milestone_id: Optional[str] = None
    client_id: str
    currency_code: str
    subtotal_amount: Decimal
    tax_amount: Decimal
    total_amount: Decimal
    status: str
    issued_at: Optional[str] = None
    due_date: Optional[date] = None


class ReceiptCreate(BaseModel):
    invoice_id: Optional[str] = None
    client_id: str
    amount: Decimal
    currency_code: str
    description: str
    received_date: date


class ExpenseCreate(BaseModel):
    account_code: str
    amount: Decimal
    currency_code: str
    description: str
    expense_date: date
