#!/usr/bin/env bash
# Démo d9 PII Protect — téléchargement de fichier (/assets) : même document d9,
# l'humain récupère l'original, l'agent une version tokenisée réversible.
set -euo pipefail
PY=/Users/grouzoul/code/ecluse-poc/venv/bin/python
command -v "$PY" >/dev/null || PY=python3
curl -s -m4 localhost:8077/health >/dev/null || { echo "engine down — relancer l'engine"; exit 1; }

"$PY" - <<'PY'
import json, io, urllib.request, urllib.error
from docx import Document
B="http://localhost:8060"; bar="─"*58
def login(e,p):
    r=urllib.request.Request(B+"/auth/login",data=json.dumps({"email":e,"password":p}).encode(),headers={"Content-Type":"application/json"})
    return json.loads(urllib.request.urlopen(r).read())["data"]["access_token"]
adm=login("admin@ecluse.io","ecluse-admin"); agt=login("agent@ecluse.io","agent-pwd")

# upload d'un .docx avec PII
d=Document()
d.add_paragraph("Compte rendu — client Jean Dupont")
d.add_paragraph("NIR : 1 85 05 78 006 084 36 — IBAN FR7630006000011234567890189")
d.add_paragraph("Contact : jean.dupont@example.fr, 06 12 34 56 78")
buf=io.BytesIO(); d.save(buf); raw=buf.getvalue()
bnd="----b"
body=(f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"compte-rendu.docx\"\r\n"
      "Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n").encode()+raw+f"\r\n--{bnd}--\r\n".encode()
req=urllib.request.Request(B+"/files",data=body,headers={"Authorization":"Bearer "+adm,"Content-Type":f"multipart/form-data; boundary={bnd}"})
fid=json.loads(urllib.request.urlopen(req).read())["data"]["id"]
print(f"Document 'compte-rendu.docx' uploadé (id {fid[:8]}…)")

def dl(tok):
    r=urllib.request.Request(B+f"/assets/{fid}"); r.add_header("Authorization","Bearer "+tok)
    data=urllib.request.urlopen(r).read()
    return "\n".join("  "+p.text for p in Document(io.BytesIO(data)).paragraphs)

print(f"\n\033[1m{bar}\033[0m\n👤  TÉLÉCHARGÉ PAR UN HUMAIN (admin)\n\033[1m{bar}\033[0m")
print(dl(adm))
print(f"\n\033[1m{bar}\033[0m\n🤖  LE MÊME FICHIER, TÉLÉCHARGÉ PAR L'AGENT IA\n\033[1m{bar}\033[0m")
print(dl(agt))
print(f"\n\033[1m{bar}\033[0m")
print("Même document, même URL /assets. L'agent ne reçoit jamais la PII en clair ;")
print("un humain autorisé (porteur de clé) peut rehydrater. Round-trip réversible.")
PY
