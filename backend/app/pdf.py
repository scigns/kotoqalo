"""Invoice PDF generation and storage.

Storage: local disk only for now (backend/var/invoice_pdfs/), matching
the same "placeholder until a real backend is provisioned" pattern as
Auth0/KeyProvider -- production needs real object storage (S3/GCS/etc.),
which, like the secrets manager, hasn't been decided yet in this
project. pdf_object_key stores a relative path under that directory;
swapping to real object storage later means changing where the bytes
are written/read, not the invoices.pdf_object_key column's meaning.
"""

import io
from pathlib import Path
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

_STORAGE_DIR = Path(__file__).resolve().parent.parent / "var" / "invoice_pdfs"


def generate_invoice_pdf(
    invoice: dict,
    client_name: str,
    contract_title: str,
    milestone_title: Optional[str],
) -> bytes:
    buffer = io.BytesIO()
    doc = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4
    y = height - 50

    doc.setFont("Helvetica-Bold", 16)
    doc.drawString(50, y, "Dreamers-Media Pacific")
    y -= 30

    doc.setFont("Helvetica-Bold", 14)
    doc.drawString(50, y, f"Invoice {invoice['invoice_number']}")
    y -= 22

    doc.setFont("Helvetica", 10)
    issued_at = invoice.get("issued_at")
    doc.drawString(50, y, f"Issued: {issued_at if issued_at else 'DRAFT -- not yet issued'}")
    y -= 15
    if invoice.get("due_date"):
        doc.drawString(50, y, f"Due: {invoice['due_date']}")
        y -= 15

    y -= 15
    doc.setFont("Helvetica-Bold", 11)
    doc.drawString(50, y, "Bill to:")
    y -= 15
    doc.setFont("Helvetica", 10)
    doc.drawString(50, y, client_name)

    y -= 30
    doc.setFont("Helvetica-Bold", 11)
    doc.drawString(50, y, "For:")
    y -= 15
    doc.setFont("Helvetica", 10)
    doc.drawString(50, y, contract_title)
    if milestone_title:
        y -= 15
        doc.drawString(50, y, f"Milestone: {milestone_title}")

    y -= 40
    doc.setFont("Helvetica", 10)
    doc.drawString(50, y, f"Subtotal: {invoice['currency_code']} {invoice['subtotal_amount']}")
    y -= 15
    doc.drawString(50, y, f"Tax: {invoice['currency_code']} {invoice['tax_amount']}")
    y -= 20
    doc.setFont("Helvetica-Bold", 12)
    doc.drawString(50, y, f"Total: {invoice['currency_code']} {invoice['total_amount']}")

    doc.showPage()
    doc.save()
    return buffer.getvalue()


def store_invoice_pdf(invoice_id: str, pdf_bytes: bytes) -> str:
    """Returns the object key (relative path) to store in
    invoices.pdf_object_key."""
    _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    object_key = f"{invoice_id}.pdf"
    (_STORAGE_DIR / object_key).write_bytes(pdf_bytes)
    return object_key


def read_invoice_pdf(object_key: str) -> bytes:
    return (_STORAGE_DIR / object_key).read_bytes()
