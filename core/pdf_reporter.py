from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import ScanResult
from .reporter import seal_report


def save_pdf(result: ScanResult, output_path: str, case_name: str = ""):
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.pdfgen import canvas  # type: ignore
    except Exception as e:
        raise RuntimeError(f"reportlab is required for PDF generation: {e}")

    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(p), pagesize=A4)
    w, h = A4

    y = h - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Digital Forensic Analysis Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Case: {case_name or '-'}")
    y -= 14
    c.drawString(40, y, f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}")
    y -= 14
    c.drawString(40, y, f"Source: {result.source_path}")
    y -= 24

    s = result.summary()
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Summary")
    y -= 16
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Files found: {s['files_found']}")
    y -= 14
    c.drawString(40, y, f"Bytes scanned: {s['bytes_scanned']:,}")
    y -= 14
    c.drawString(40, y, f"Duration: {s['duration_seconds']} seconds")
    y -= 14
    if result.source_hash:
        c.drawString(40, y, f"SHA256: {result.source_hash.sha256}")
        y -= 18

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Recovered Files")
    y -= 16
    c.setFont("Helvetica", 9)
    for cf in result.carved_files[:100]:
        line = f"#{cf.id} {cf.type_name} off=0x{cf.start_offset:X} size={cf.size} conf={cf.confidence:.2f} status={cf.recovery_status}"
        c.drawString(40, y, line[:145])
        y -= 12
        if y < 60:
            c.showPage()
            y = h - 50
            c.setFont("Helvetica", 9)

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(40, 30, "This report is generated for authorized forensic investigation only.")
    c.save()
    seal_report(p)


def sign_pdf(
    input_pdf_path: str,
    output_pdf_path: str,
    cert_pem_path: str,
    key_pem_path: str,
    key_passphrase: Optional[str] = None,
):
    """
    Apply detached CMS signature using pyHanko.
    Requires pyHanko + cryptography stack.
    """
    try:
        from pyhanko.sign import signers  # type: ignore
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # type: ignore
        from pyhanko.sign.fields import SigFieldSpec, append_signature_field  # type: ignore
        from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata, PdfSigner  # type: ignore
    except Exception as e:
        raise RuntimeError(f"pyHanko is required for PDF signing: {e}")

    signer = signers.SimpleSigner.load(
        key_file=key_pem_path,
        cert_file=cert_pem_path,
        key_passphrase=(key_passphrase.encode("utf-8") if key_passphrase else None),
    )

    with open(input_pdf_path, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf)
        append_signature_field(writer, SigFieldSpec(sig_field_name="Signature1"))
        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        with open(output_pdf_path, "wb") as outf:
            pdf_signer.sign_pdf(writer, output=outf)

