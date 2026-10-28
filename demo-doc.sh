#!/usr/bin/env bash
# Démo d9 PII Protect — documents texte (.docx/.txt) : tokenisation RÉVERSIBLE (round-trip complet).
# (Les images/PDF scannés relèvent du caviardage destructif — autre mode.)
set -euo pipefail
PY=/Users/grouzoul/code/ecluse-poc/venv/bin/python
command -v "$PY" >/dev/null || PY=python3
curl -s -m4 localhost:8077/health >/dev/null || { echo "engine down — relancer l'engine (voir README)"; exit 1; }

"$PY" - <<'PY'
import base64, io, json, urllib.request
from docx import Document
def post(p,o):
    r=urllib.request.Request("http://localhost:8077"+p,data=json.dumps(o).encode(),headers={"Content-Type":"application/json"})
    return json.loads(urllib.request.urlopen(r,timeout=60).read())
def dtext(b): d=Document(io.BytesIO(b)); return "\n".join(x.text for x in d.paragraphs)
def b64(b): return base64.b64encode(b).decode()
bar="─"*58

# --- .docx ---
d=Document()
d.add_paragraph("Compte rendu — client Jean Dupont")
d.add_paragraph("NIR : 1 85 05 78 006 084 36 — IBAN FR7630006000011234567890189")
d.add_paragraph("Contact : jean.dupont@example.fr, 06 12 34 56 78")
buf=io.BytesIO(); d.save(buf); orig=buf.getvalue()
print(f"\n\033[1m{bar}\033[0m\n📄  DOCUMENT .docx — ORIGINAL (vu par un humain)\n\033[1m{bar}\033[0m")
print(dtext(orig))
a=post("/anonymize-doc",{"filename":"cr.docx","content_b64":b64(orig)})
print(f"\n\033[1m{bar}\033[0m\n🤖  LE MÊME .docx — VU PAR L'AGENT (PII tokenisées, réversible)\n\033[1m{bar}\033[0m")
print(dtext(base64.b64decode(a["content_b64"])))
r=post("/rehydrate-doc",{"filename":"cr.docx","content_b64":a["content_b64"]})
print(f"\n\033[1m{bar}\033[0m\n🔓  APRÈS REHYDRATE (humain autorisé, porteur de clé)\n\033[1m{bar}\033[0m")
rt=dtext(base64.b64decode(r["content_b64"]))
print(rt)
print("\n→ round-trip .docx identique à l'original :", rt==dtext(orig))

# --- .txt ---
t="Ticket: Sophie Lemaire (NIR 2 91 12 75 116 207 11) à Lyon, tél 07.88.99.00.11."
a=post("/anonymize-doc",{"filename":"n.txt","content_b64":b64(t.encode())})
at=base64.b64decode(a["content_b64"]).decode()
r=post("/rehydrate-doc",{"filename":"n.txt","content_b64":a["content_b64"]})
print(f"\n\033[1m{bar}\033[0m\n📝  .txt agent :\033[0m", at)
print("→ round-trip .txt identique :", base64.b64decode(r["content_b64"]).decode()==t)
PY
