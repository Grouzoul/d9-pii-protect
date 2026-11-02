"""Image redaction — Presidio Image Redactor + our analyzer (FR by default) + Tesseract OCR.

Unlike text/documents (REVERSIBLE marker-based encryption), image redaction is DESTRUCTIVE:
PII regions are masked with rectangles. The stored file stays intact — the agent receives a
redacted copy on the fly, while an authorized human downloads the original (decided by d9 RBAC).

╔══════════════════════════════════════════════════════════════════════════╗
║  OCR language  ->  env PII_OCR_LANG  (default 'fra', package tesseract-ocr-fra)   ║
║  PII detection = the SAME French analyzer as text (analyzer.engine()).      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import io, os
from presidio_image_redactor import ImageRedactorEngine, ImageAnalyzerEngine
from PIL import Image

import analyzer

OCR_LANG = os.environ.get("PII_OCR_LANG", "fra")
FILL = (0, 0, 0)  # redaction color

_redactor = None
def _engine():
    global _redactor
    if _redactor is None:
        # Plug OUR French AnalyzerEngine (NER + regex) into the Presidio redactor.
        iae = ImageAnalyzerEngine(analyzer_engine=analyzer.engine())
        _redactor = ImageRedactorEngine(image_analyzer_engine=iae)
    return _redactor

def warmup():
    _engine()

def _redact_one(img):
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    return _engine().redact(img, fill=FILL, language="fr", ocr_kwargs={"lang": OCR_LANG})

def redact_image(data: bytes) -> bytes:
    img = Image.open(io.BytesIO(data))
    fmt = (img.format or "PNG").upper()
    red = _redact_one(img)
    out = io.BytesIO()
    # JPEG does not support alpha
    if fmt in ("JPG", "JPEG") and red.mode == "RGBA":
        red = red.convert("RGB")
    red.save(out, format="JPEG" if fmt == "JPG" else fmt)
    return out.getvalue()

def redact_pdf(data: bytes) -> bytes:
    """PDF redaction: each page -> image -> OCR redaction -> reassembled PDF (rasterized, PII masked)."""
    from pdf2image import convert_from_bytes
    pages = convert_from_bytes(data, dpi=150)
    red = [_redact_one(p).convert("RGB") for p in pages]
    out = io.BytesIO()
    red[0].save(out, format="PDF", save_all=True, append_images=red[1:])
    return out.getvalue()
