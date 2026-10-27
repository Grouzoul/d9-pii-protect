#!/usr/bin/env bash
# Démo Écluse — acte "round-trip" : l'agent travaille sur la donnée sans jamais voir le clair.
set -euo pipefail
D9=http://localhost:8060
PY=/Users/grouzoul/code/ecluse-poc/venv/bin/python
command -v "$PY" >/dev/null || PY=python3
bar(){ printf '\n\033[1m%s\033[0m\n' "────────────────────────────────────────────────────────"; }

tok(){ curl -s -X POST $D9/auth/login -H 'Content-Type: application/json' -d "$1" | $PY -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"; }
AGT=$(tok '{"email":"agent@ecluse.io","password":"agent-pwd"}')
ADM=$(tok '{"email":"admin@ecluse.io","password":"ecluse-admin"}')

bar; echo "1) L'AGENT IA lit le ticket #1 — il ne reçoit que du chiffré :"; bar
CIPHER=$(curl -s "$D9/items/tickets/1?fields=note" -H "Authorization: Bearer $AGT" | $PY -c "import sys,json;print(json.load(sys.stdin)['data']['note'])")
echo "   ${CIPHER:0:110}…"

bar; echo "2) L'AGENT met à jour le ticket (change le statut, renvoie la note chiffrée)."; bar
BODY=$($PY -c "import json;print(json.dumps({'note':'''$CIPHER''','statut':'traité par agent IA'}))")
curl -s -X PATCH "$D9/items/tickets/1" -H "Authorization: Bearer $AGT" -H 'Content-Type: application/json' -d "$BODY" -o /dev/null -w "   PATCH agent → HTTP %{http_code}\n"

bar; echo "3) L'HUMAIN relit — la vraie PII est intacte, le travail de l'agent est bien là :"; bar
curl -s "$D9/items/tickets/1?fields=note,statut" -H "Authorization: Bearer $ADM" | $PY -c "import sys,json;d=json.load(sys.stdin)['data'];print('   note  :',d['note']);print('   statut:',d['statut'])"
echo
echo "→ L'agent a lu, raisonné et réécrit SANS jamais voir une seule donnée personnelle. Zéro corruption."
