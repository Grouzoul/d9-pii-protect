"""Caviardage d'images — Presidio Image Redactor + NOTRE analyzer FR + Tesseract OCR.

Contrairement au texte/documents (chiffrement RÉVERSIBLE par marqueurs), le caviardage d'image est
DESTRUCTIF : on masque les zones PII par des rectangles. Le fichier stocké reste intact — l'agent
reçoit une copie caviardée à la volée, l'humain autorisé télécharge l'original (décidé par le RBAC d9).

╔══════════════════════════════════════════════════════════════════════════╗
║  Langue de l'OCR  ->  env PII_OCR_LANG  (défaut 'fra', paquet tesseract-ocr-fra)  ║
║  Détection des PII = le MÊME analyzer FR que le texte (analyzer.engine()).  ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import io, os
from presidio_image_redactor import ImageRedactorEngine, ImageAnalyzerEngine
from PIL import Image

import analyzer

OCR_LANG = os.environ.get("PII_OCR_LANG", "fra")
FILL = (0, 0, 0)  # couleur du caviardage

_redactor = None
def _engine():
    global _redactor
    if _redactor is None:
        # On branche NOTRE AnalyzerEngine FR (NER + regex) dans le redactor Presidio.
        iae = ImageAnalyzerEngine(analyzer_engine=analyzer.engine())
        _redactor = ImageRedactorEngine(image_analyzer_engine=iae)
    return _redactor

def warmup():
    _engine()

def redact_image(data: bytes) -> bytes:
    img = Image.open(io.BytesIO(data))
    fmt = (img.format or "PNG").upper()
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    red = _engine().redact(img, fill=FILL, language="fr", ocr_kwargs={"lang": OCR_LANG})
    out = io.BytesIO()
    # JPEG ne gère pas l'alpha
    if fmt in ("JPG", "JPEG") and red.mode == "RGBA":
        red = red.convert("RGB")
    red.save(out, format="JPEG" if fmt == "JPG" else fmt)
    return out.getvalue()
