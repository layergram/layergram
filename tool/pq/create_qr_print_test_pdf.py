#!/usr/bin/env python3
"""Create the one-page, actual-size Layergram v3 QR print test."""

from __future__ import annotations

import hashlib
from pathlib import Path

import qrcode
from qrcode.constants import ERROR_CORRECT_M
from qrcode.util import MODE_8BIT_BYTE, QRData
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output/pdf/layergram-v3-qr-business-card-print-test.pdf"
QR_PNG = ROOT / "tmp/pdfs/layergram-v3-max-identity-export-1024.png"

QR_SIZES_MM = (50, 45, 40, 35, 30, 25)
QR_QUIET_ZONE_MODULES = 4
BUSINESS_CARD_WIDTH_MM = 85.60
BUSINESS_CARD_HEIGHT_MM = 53.98


def build_maximum_v3_identity() -> bytes:
    """Mirror buildPhysicalQrHarnessPayload() from the Flutter camera gate."""
    name = "Physical QR camera gate".ljust(32, "X").encode("utf-8")
    x25519_public_key = bytes(range(1, 33))
    ml_kem_768_public_key = bytes((index % 251) + 1 for index in range(1184))
    body = (
        b"LG3"
        + bytes((1, 0, len(name)))
        + x25519_public_key
        + ml_kem_768_public_key
        + name
    )
    checksum = hashlib.sha384(body).digest()[:16]
    encoded = body + checksum
    assert len(encoded) == 1270
    return encoded


def build_qr_matrix(payload: bytes) -> tuple[list[list[bool]], int]:
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=1,
        border=QR_QUIET_ZONE_MODULES,
    )
    qr.add_data(QRData(payload, mode=MODE_8BIT_BYTE), optimize=0)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    assert qr.version == 30, f"Expected QR version 30, got {qr.version}"
    assert len(matrix) == 145 and all(len(row) == 145 for row in matrix)
    return matrix, qr.version


def draw_qr(
    pdf: canvas.Canvas,
    qr_png: ImageReader,
    x_mm: float,
    y_mm: float,
    size_mm: float,
) -> None:
    x = x_mm * mm
    y = y_mm * mm
    side = size_mm * mm
    pdf.drawImage(
        qr_png,
        x,
        y,
        width=side,
        height=side,
        preserveAspectRatio=True,
        anchor="c",
    )


def label(pdf: canvas.Canvas, number: int, size_mm: int, x_mm: float, y_mm: float) -> None:
    pdf.setFillColor(HexColor("#102F49"))
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(x_mm * mm, y_mm * mm, f"{number}.  {size_mm} mm")


def create_pdf() -> None:
    payload = build_maximum_v3_identity()
    matrix, version = build_qr_matrix(payload)
    qr_png = ImageReader(str(QR_PNG))
    assert qr_png.getSize() == (1024, 1024), qr_png.getSize()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    page_width, page_height = A4
    pdf = canvas.Canvas(
        str(OUTPUT),
        pagesize=A4,
        pageCompression=1,
        invariant=1,
    )
    pdf.setTitle("Layergram v3 - prova di stampa QR per biglietto da visita")
    pdf.setAuthor("Layergram")
    pdf.setSubject(
        "QR PNG v3 da 1270 byte, 1024 px, logo 20%, correzione M, versione 30, in scala reale"
    )

    navy = HexColor("#102F49")
    cyan = HexColor("#1FC7D4")
    muted = HexColor("#52606D")
    guide = Color(0.45, 0.50, 0.55, alpha=0.8)

    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(12 * mm, page_height - 15 * mm, "Layergram v3 - prova QR stampati")
    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 8.5)
    pdf.drawString(
        12 * mm,
        page_height - 21 * mm,
        "Stampa al 100% / dimensioni reali. Disattiva 'Adatta alla pagina'.",
    )
    pdf.drawString(
        12 * mm,
        page_height - 26 * mm,
        f"Stesso PNG esportato dall'app: 1024 px - {len(payload)} byte - QR v{version} - ECC M - logo 20%.",
    )

    # QR 1: maximum practical square inside an ISO/IEC 7810 ID-1 card outline.
    card_x = 12.0
    card_y = 211.0
    pdf.setStrokeColor(guide)
    pdf.setLineWidth(0.25 * mm)
    pdf.setDash(1.2 * mm, 1.2 * mm)
    pdf.roundRect(
        card_x * mm,
        card_y * mm,
        BUSINESS_CARD_WIDTH_MM * mm,
        BUSINESS_CARD_HEIGHT_MM * mm,
        2.5 * mm,
        stroke=1,
        fill=0,
    )
    pdf.setDash()
    draw_qr(pdf, qr_png, card_x + 2.0, card_y + 1.99, 50)
    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawString((card_x + 59) * mm, (card_y + 34) * mm, "1")
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString((card_x + 56) * mm, (card_y + 26) * mm, "QR 50 mm")
    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawString((card_x + 56) * mm, (card_y + 20) * mm, "Tessera reale")
    pdf.drawString((card_x + 56) * mm, (card_y + 16) * mm, "85,6 x 54 mm")
    pdf.setFillColor(HexColor("#B42318"))
    pdf.setFont("Helvetica-Bold", 5.8)
    pdf.drawString((card_x + 56) * mm, (card_y + 8) * mm, "IDENTITA DI TEST")

    # QR 2, top right.
    label(pdf, 2, 45, 147.5, 264.0)
    draw_qr(pdf, qr_png, 147.5, 216.0, 45)

    # QR 3-5, middle row.
    label(pdf, 3, 40, 16.0, 188.0)
    draw_qr(pdf, qr_png, 16.0, 144.0, 40)
    label(pdf, 4, 35, 87.5, 188.0)
    draw_qr(pdf, qr_png, 87.5, 147.0, 35)
    label(pdf, 5, 30, 155.0, 188.0)
    draw_qr(pdf, qr_png, 155.0, 149.5, 30)

    # QR 6 and scale check.
    label(pdf, 6, 25, 20.0, 111.0)
    draw_qr(pdf, qr_png, 20.0, 82.5, 25)

    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 9)
    pdf.drawString(65 * mm, 106 * mm, "Controllo scala di stampa")
    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 7.5)
    pdf.drawString(65 * mm, 101 * mm, "Il rettangolo qui sotto deve misurare 50 x 10 mm.")
    pdf.setStrokeColor(cyan)
    pdf.setLineWidth(0.5 * mm)
    pdf.rect(65 * mm, 86 * mm, 50 * mm, 10 * mm, stroke=1, fill=0)
    pdf.setFillColor(navy)
    pdf.setFont("Helvetica-Bold", 7)
    pdf.drawCentredString(90 * mm, 89.2 * mm, "50 mm")

    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 7.2)
    instructions = (
        "Prova ogni numero 3 volte con iPhone e Android. Segna il piu piccolo letto",
        "subito e senza errori da entrambi: quello sara il minimo operativo rilevato.",
        "Non aggiungere questo contatto: il payload e sintetico e serve solo al test.",
    )
    for index, line in enumerate(instructions):
        pdf.drawString(65 * mm, (79 - index * 4.3) * mm, line)

    pdf.setStrokeColor(HexColor("#D7DEE5"))
    pdf.setLineWidth(0.2 * mm)
    pdf.line(12 * mm, 18 * mm, (page_width / mm - 12) * mm, 18 * mm)
    pdf.setFillColor(muted)
    pdf.setFont("Helvetica", 6.5)
    pdf.drawString(
        12 * mm,
        13 * mm,
        "Tutti i QR includono il payload pubblico completo e statico; nessun dato privato o mnemonic.",
    )
    pdf.drawRightString(
        (page_width / mm - 12) * mm,
        13 * mm,
        "Layergram v3 print gate",
    )

    pdf.showPage()
    pdf.save()
    print(f"created={OUTPUT}")
    print(f"payload_bytes={len(payload)} qr_version={version} matrix_modules={len(matrix)}")


if __name__ == "__main__":
    create_pdf()
