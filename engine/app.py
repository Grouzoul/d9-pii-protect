#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Governed PII anonymization engine (sidecar) — embedded French Presidio.

  detection = Presidio (analyzer.py): FR NER Anonym-IA + regex/checksum recognizers + context scoring
  reversible encryption = AES-256-GCM in-place, markers [[PII:TYPE:b64]] (crypto.py)

Endpoints (JSON):
  POST /anonymize      {text}                  -> {text, count, entities}   (encrypt detected PII)
  POST /encrypt        {text}                  -> {text, count}             (encrypt the WHOLE value, 1 marker)
  POST /rehydrate      {text}                  -> {text, count}
  POST /anonymize-doc  {filename, content_b64} -> {filename, content_b64}   (.txt/.md/.csv/.json/.docx)
  POST /rehydrate-doc  {filename, content_b64} -> {filename, content_b64}
  POST /redact-image   {filename, content_b64} -> {filename, content_b64}   (OCR redaction, destructive)
  POST /redact-pdf     {filename, content_b64} -> {filename, content_b64}   (PDF -> redacted pages, destructive)
  POST /detect         {text}                  -> {spans:[{start,end,type,text}]}
  GET  /health

Config (env): PII_PROTECT_KEY, PII_NER_MODEL, PII_NER_THRESHOLD, PORT.
"""
import base64, io, json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import crypto, analyzer, ner, image_redact

PORT = int(os.environ.get("PORT", "8077"))
# Optional shared secret: if set, every POST must carry header X-Engine-Token = this value. Defense in depth
# so that even within the network, only the extension (which sets the same env) can reach the engine.
ENGINE_TOKEN = os.environ.get("PII_PROTECT_ENGINE_TOKEN")
MAX_BODY = int(os.environ.get("PII_MAX_BODY", str(64 * 1024 * 1024)))  # reject oversized bodies (DoS)

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CHOOSE WHAT GETS ENCRYPTED (by PII TYPE)                                  ║
# ║  Default: everything detected is encrypted (secure-by-default).            ║
# ║    PII_PROTECT_ENTITIES = "NOM_PERSONNE,PRENOM_PERSONNE,NUM_SECURITE..."    ║
# ║        -> allow-list: ONLY these types are encrypted (the rest stays clear) ║
# ║    PII_PROTECT_SKIP = "VILLE,DATE,CODE_POSTAL"                              ║
# ║        -> deny-list: these types stay in clear (everything else encrypted)  ║
# ║  (field-level filtering is done in the extension via PII_PROTECT_FIELDS)     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def _types_env(name):
    return {t.strip().upper() for t in os.environ.get(name, "").split(",") if t.strip()}
ONLY_TYPES = _types_env("PII_PROTECT_ENTITIES")   # empty = no restriction
SKIP_TYPES = _types_env("PII_PROTECT_SKIP")

def _should_encrypt(entity_type):
    if ONLY_TYPES and entity_type not in ONLY_TYPES:
        return False
    return entity_type not in SKIP_TYPES

def anonymize(text):
    spans = [sp for sp in analyzer.detect(text) if _should_encrypt(sp[2])]
    out, entities = text, []
    for s, e, t in sorted(spans, key=lambda x: x[0], reverse=True):
        out = out[:s] + crypto.marker(t, text[s:e]) + out[e:]
        entities.append(t)
    return out, list(reversed(entities))

# ---------------------------------------------------------------- text documents
def _docx_transform(data, fn):
    from docx import Document
    d = Document(io.BytesIO(data))
    def paras(doc):
        for p in doc.paragraphs: yield p
        for t in doc.tables:
            for row in t.rows:
                for cell in row.cells:
                    for p in cell.paragraphs: yield p
    for p in paras(d):
        if p.text.strip():
            new = fn(p.text)
            if new != p.text:
                runs = list(p.runs)
                for r in runs: r.text = ""
                if runs: runs[0].text = new
                else: p.add_run(new)
    out = io.BytesIO(); d.save(out); return out.getvalue()

def process_doc(filename, data, mode):
    ext = (filename or "").lower().rsplit(".", 1)[-1]
    fn = (lambda t: anonymize(t)[0]) if mode == "anonymize" else (lambda t: crypto.rehydrate(t)[0])
    if ext == "docx":
        return _docx_transform(data, fn)
    return fn(data.decode("utf-8", "replace")).encode("utf-8")

# ---------------------------------------------------------------- POST routes
# Each handler receives the body (JSON dict) and returns a dict (serialized as a 200 response).
def _file_op(body, fn):
    """Transform a base64 file -> base64 file, keeping the name."""
    out = fn(base64.b64decode(body.get("content_b64", "")))
    return {"filename": body.get("filename", ""), "content_b64": base64.b64encode(out).decode()}

def _anonymize(b):
    out, ents = anonymize(b.get("text", ""))
    return {"text": out, "count": len(ents), "entities": ents}

def _encrypt(b):
    # Encrypt the WHOLE value into one marker (e.g. a filename: protect everything, not per-PII).
    t = b.get("text", "")
    return {"text": crypto.marker("TEXT", t) if t else t, "count": 1 if t else 0}

def _rehydrate(b):
    out, c = crypto.rehydrate(b.get("text", ""))
    return {"text": out, "count": c}

def _detect(b):
    t = b.get("text", "")
    return {"spans": [{"start": s, "end": e, "type": ty, "text": t[s:e]} for s, e, ty in analyzer.detect(t)]}

POST_ROUTES = {
    "/anonymize":     _anonymize,
    "/encrypt":       _encrypt,
    "/rehydrate":     _rehydrate,
    "/detect":        _detect,
    "/anonymize-doc": lambda b: _file_op(b, lambda d: process_doc(b.get("filename", ""), d, "anonymize")),
    "/rehydrate-doc": lambda b: _file_op(b, lambda d: process_doc(b.get("filename", ""), d, "rehydrate")),
    "/redact-image":  lambda b: _file_op(b, image_redact.redact_image),
    "/redact-pdf":    lambda b: _file_op(b, image_redact.redact_pdf),
}

# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "model": ner.MODEL})
        else:
            self._send(404, {"error": "not found"})
    def do_POST(self):
        if ENGINE_TOKEN and self.headers.get("X-Engine-Token") != ENGINE_TOKEN:
            return self._send(401, {"error": "unauthorized"})
        handler = POST_ROUTES.get(self.path)
        if handler is None:
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_BODY:
            return self._send(413, {"error": "payload too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            self._send(200, handler(body))
        except Exception as ex:
            print(f"[engine] 500 on {self.path}: {ex}", file=sys.stderr, flush=True)  # log internally…
            self._send(500, {"error": "internal error"})                               # …don't echo details

if __name__ == "__main__":
    print("Loading Presidio + the NER model…", flush=True)
    analyzer.warmup()
    print(f"PII engine ready on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
