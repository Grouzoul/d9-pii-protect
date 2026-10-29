#!/usr/bin/env bash
# Démo d9 PII Protect — secure-by-default sur toutes les entités accessibles à un agent.
# Prérequis : la stack deploy/ tournante (docker compose up -d) + seed_ecluse.py exécuté.
# N'utilise que l'API publique de d9 (:8055) et python3. Aucune dépendance machine.
set -euo pipefail
B="${D9_URL:-http://localhost:8055}"
hr(){ printf '\n\033[1;35m== %s ==\033[0m\n' "$1"; }

tok(){ curl -s -X POST "$B/auth/login" -H 'Content-Type: application/json' -d "$1" \
       | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"; }
ADM=$(tok '{"email":"admin@ecluse.io","password":"ecluse-admin"}')
AGT=$(tok '{"email":"agent@ecluse.io","password":"agent-pwd"}')
DIR="$(cd "$(dirname "$0")" && pwd)"

hr "1) CHAMP TEXTE  (tickets.note, type 'text' — protégé sans aucune config)"
echo "HUMAIN :"; curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $ADM" \
  | python3 -c "import sys,json;print('  '+json.load(sys.stdin)['data']['note'])"
echo "AGENT  :"; curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $AGT" \
  | python3 -c "import sys,json;n=json.load(sys.stdin)['data']['note'];print('  '+('[chiffré] ' if '[[PII:' in n else '[CLAIR!] ')+n)"

hr "2) DOCUMENT TEXTE  (samples/dossier.txt via /assets)"
FID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@$DIR/samples/dossier.txt;type=text/plain" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
echo "HUMAIN télécharge :"; curl -s "$B/assets/$FID" -H "Authorization: Bearer $ADM" | sed 's/^/  /'
echo "AGENT télécharge  :"; curl -s "$B/assets/$FID" -H "Authorization: Bearer $AGT" | sed 's/^/  /'

hr "3) IMAGE  (samples/carte-identite.png via /assets — caviardage OCR)"
IID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@$DIR/samples/carte-identite.png;type=image/png" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
curl -s "$B/assets/$IID" -H "Authorization: Bearer $ADM" -o /tmp/piiprotect_humain.png
curl -s "$B/assets/$IID" -H "Authorization: Bearer $AGT" -o /tmp/piiprotect_agent.png
echo "  HUMAIN  -> /tmp/piiprotect_humain.png (original, $(wc -c </tmp/piiprotect_humain.png) o)"
echo "  AGENT   -> /tmp/piiprotect_agent.png  (caviardé, $(wc -c </tmp/piiprotect_agent.png) o)"
echo "  Ouvrez les deux pour voir les zones PII masquées côté agent."

hr "4) TYPE NON PRIS EN CHARGE  (.bin — refus fail-closed)"
printf 'binaire avec Jean Dupont NIR 1 85 05 78 006 084 36' > /tmp/piiprotect.bin
XID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@/tmp/piiprotect.bin;type=application/octet-stream" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
echo "  HUMAIN : HTTP $(curl -s -o /dev/null -w '%{http_code}' "$B/assets/$XID" -H "Authorization: Bearer $ADM")  (200 attendu)"
echo "  AGENT  : HTTP $(curl -s -o /dev/null -w '%{http_code}' "$B/assets/$XID" -H "Authorization: Bearer $AGT")  (415 = refus attendu)"

hr "5) ROUND-TRIP ÉCRITURE  (l'agent réécrit avec des marqueurs -> déchiffrés avant stockage)"
NOTE=$(curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $AGT" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['note'])")
curl -s -X PATCH "$B/items/tickets/1" -H "Authorization: Bearer $AGT" -H 'Content-Type: application/json' \
  -d "$(python3 -c "import json,sys;print(json.dumps({'note':sys.argv[1]+' [traité par agent]'}))" "$NOTE")" >/dev/null
echo "Relecture HUMAIN après écriture agent :"
curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $ADM" \
  | python3 -c "import sys,json;n=json.load(sys.stdin)['data']['note'];print('  '+('[clair restauré ✓] ' if '[[PII:' not in n and 'Jean Dupont' in n else '[ANOMALIE] ')+n)"
echo
printf '\033[1;32mDémo terminée.\033[0m Humain = clair partout ; agent = jamais de PII en clair.\n'
