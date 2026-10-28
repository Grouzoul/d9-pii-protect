#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Écluse engine — brique d'anonymisation gouvernée (POC).

- Détection PII FR via Presidio/Anonym-IA (service :5005, modèle CamemBERT FR, FR_NIR, etc.)
- Chiffrement RÉVERSIBLE in-place AES-256-GCM (authentifié, nonce aléatoire -> pas de fuite d'égalité)
- Marqueurs auto-porteurs : chaque PII devient  [[ECLUSE:<ENTITY>:<b64>]]
  -> l'agent voit le type + un ciphertext ; un porteur de clé rehydrate n'importe où, sans map externe.

Endpoints:
  POST /anonymize   {"text": "...", "language":"fr"}  -> {"text": "...", "count": N, "entities":[...]}
  POST /rehydrate   {"text": "...(avec marqueurs)"}   -> {"text": "...", "count": N}
  GET  /health
"""
import base64, io, json, os, re, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ANALYZER_URL = os.environ.get("PII_ANALYZER_URL") or os.environ.get("ECLUSE_ANALYZER_URL", "http://localhost:5005/analyze")
LANG         = os.environ.get("ECLUSE_LANG", "fr")
THRESHOLD    = float(os.environ.get("ECLUSE_THRESHOLD", "0.4"))
PORT         = int(os.environ.get("ECLUSE_PORT", "8077"))
# Clé démo 32 octets (AES-256). EN PROD : custody gouvernée (KMS/HSM), rotation, accès RBAC+audit.
KEY = (os.environ.get("PII_PROTECT_KEY") or os.environ.get("ECLUSE_KEY") or "demo-key-change-me-0123456789abc").encode()[:32].ljust(32, b"0")
_aes = AESGCM(KEY)

MARKER_RE = re.compile(r"\[\[PII:([A-Z_]+):([A-Za-z0-9_\-]+={0,2})\]\]")

# --- Recognizers FR customs (ce qu'Anonym-IA n'a pas : SIREN/SIRET + dates textuelles) ---
_MOIS = "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre"
_DATE_FR_RE = re.compile(rf"\b\d{{1,2}}(?:er)?\s+(?:{_MOIS})(?:\s+\d{{4}})?\b", re.IGNORECASE)
_DIGIT_RUN_RE = re.compile(r"\d[\d ]{7,}\d")
_NIR_RE = re.compile(r"\b[12](?:[ .]?\d){14}\b")  # NIR FR : 15 chiffres (1/2 + 14), séparateurs tolérés

def _luhn(s):
    d = [int(c) for c in s if c.isdigit()]
    tot = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9: x -= 9
        tot += x
    return len(d) > 0 and tot % 10 == 0

def custom_fr_spans(text):
    out = []
    for m in _DATE_FR_RE.finditer(text):
        out.append((m.start(), m.end(), "DATE_FR"))
    for m in _NIR_RE.finditer(text):
        out.append((m.start(), m.end(), "FR_NIR"))
    for m in _DIGIT_RUN_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) == 9 and _luhn(digits):
            out.append((m.start(), m.end(), "SIREN"))
        elif len(digits) == 14 and _luhn(digits):
            out.append((m.start(), m.end(), "SIRET"))
    return out

def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())

def _enc(plain: str) -> str:
    nonce = os.urandom(12)
    ct = _aes.encrypt(nonce, plain.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()

def _dec(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode())
    return _aes.decrypt(raw[:12], raw[12:], None).decode()

def detect(text, language):
    # 1) PII via Presidio/Anonym-IA (FR : noms, FR_NIR, IBAN, téléphone, email, lieu...)
    raw = []
    for r in _post(ANALYZER_URL, {"text": text, "language": language}):
        if r.get("score", 1.0) >= THRESHOLD:
            raw.append((r["start"], r["end"], r["entity_type"]))
    # 2) + recognizers FR customs (SIREN/SIRET Luhn, dates textuelles)
    raw += custom_fr_spans(text)
    # 3) normalisation des bords (le NER déborde parfois d'un point)
    norm = []
    for s, e, t in raw:
        while e > s and not text[e-1].isalnum():
            e -= 1
        while s < e and not text[s].isalnum():
            s += 1
        if e - s >= 2:
            norm.append((s, e, t))
    # 4) dédoublonnage des chevauchements : on garde le plus long, par ordre de début
    norm.sort(key=lambda x: (x[0], -(x[1]-x[0])))
    kept, last_end = [], -1
    for s, e, t in norm:
        if s >= last_end:
            kept.append((s, e, t)); last_end = e
    return kept

def anonymize(text, language):
    spans = detect(text, language)
    out, entities = text, []
    for s, e, t in sorted(spans, key=lambda x: x[0], reverse=True):  # de droite à gauche
        token = _enc(text[s:e])
        out = out[:s] + f"[[PII:{t}:{token}]]" + out[e:]
        entities.append(t)
    return out, list(reversed(entities))

def rehydrate(text):
    n = 0
    def repl(m):
        nonlocal n
        try:
            v = _dec(m.group(2)); n += 1; return v
        except Exception:
            return m.group(0)
    return MARKER_RE.sub(repl, text), n

# ---- Documents TEXTE (réversible) : .txt/.md/.csv/.json + .docx ----
def _docx_transform(data, fn):
    from docx import Document
    d = Document(io.BytesIO(data))
    def paras(doc):
        for p in doc.paragraphs:
            yield p
        for t in doc.tables:
            for row in t.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        yield p
    for p in paras(d):
        if p.text.strip():
            new = fn(p.text)
            if new != p.text:
                runs = list(p.runs)
                for r in runs:
                    r.text = ""
                if runs:
                    runs[0].text = new
                else:
                    p.add_run(new)
    out = io.BytesIO(); d.save(out); return out.getvalue()

def process_doc(filename, data, mode):
    """mode = 'anonymize' | 'rehydrate'. Documents TEXTE uniquement (réversible)."""
    ext = (filename or "").lower().rsplit(".", 1)[-1]
    fn = (lambda t: anonymize(t, LANG)[0]) if mode == "anonymize" else (lambda t: rehydrate(t)[0])
    if ext == "docx":
        return _docx_transform(data, fn)
    # défaut : texte brut (.txt/.md/.csv/.json/…)
    return fn(data.decode("utf-8", "replace")).encode("utf-8")

class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/health": self._send(200, {"status": "ok", "engine": "ecluse"})
        else: self._send(404, {"error": "not found"})
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            text = body.get("text", "")
            if self.path == "/anonymize":
                out, ents = anonymize(text, body.get("language", LANG))
                self._send(200, {"text": out, "count": len(ents), "entities": ents})
            elif self.path == "/rehydrate":
                out, c = rehydrate(text)
                self._send(200, {"text": out, "count": c})
            elif self.path in ("/anonymize-doc", "/rehydrate-doc"):
                mode = "anonymize" if self.path == "/anonymize-doc" else "rehydrate"
                raw = base64.b64decode(body.get("content_b64", ""))
                out = process_doc(body.get("filename", ""), raw, mode)
                self._send(200, {"filename": body.get("filename", ""),
                                 "content_b64": base64.b64encode(out).decode()})
            else:
                self._send(404, {"error": "not found"})
        except Exception as ex:
            self._send(500, {"error": str(ex)})

if __name__ == "__main__":
    print(f"Écluse engine on :{PORT}  (analyzer={ANALYZER_URL}, lang={LANG}, seuil={THRESHOLD})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
