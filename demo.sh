#!/usr/bin/env bash
# Démo Écluse — la brique manquante : anonymisation gouvernée des PII pour les agents IA, DANS d9.
# Usage : bash demo.sh
set -euo pipefail
D9=http://localhost:8060
ENGINE=http://localhost:8077
PY=/Users/grouzoul/code/ecluse-poc/venv/bin/python
command -v "$PY" >/dev/null || PY=python3

bar(){ printf '\n\033[1m%s\033[0m\n' "────────────────────────────────────────────────────────"; }

echo "### Santé des briques"
printf "  Engine Écluse : "; curl -s -m4 $ENGINE/health >/dev/null && echo "OK ($ENGINE)" || { echo "DOWN — relancer l'engine (voir README)"; exit 1; }
printf "  d9            : "; curl -s -m4 $D9/server/health >/dev/null && echo "OK ($D9)" || { echo "DOWN"; exit 1; }

tok(){ curl -s -X POST $D9/auth/login -H 'Content-Type: application/json' -d "$1" | $PY -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"; }
ADM=$(tok '{"email":"admin@ecluse.io","password":"ecluse-admin"}')
AGT=$(tok '{"email":"agent@ecluse.io","password":"agent-pwd"}')

show(){ curl -s "$D9/items/tickets?fields=objet,note" -H "Authorization: Bearer $1" \
  | $PY -c "import sys,json;[print('• '+i['objet']+'\n  '+i['note']+'\n') for i in json.load(sys.stdin)['data']]"; }

bar; echo "👤  CE QUE VOIT UN HUMAIN (rôle admin) — PII en clair"; bar; show "$ADM"
bar; echo "🤖  CE QUE VOIT UN AGENT IA (rôle agent) — PII chiffrées in-place par Écluse"; bar; show "$AGT"
bar
echo "Même base, même API, même requête. d9 gère QUI accède (RBAC) ;"
echo "Écluse gère le CONTENU PII des champs texte libre que le RBAC champ ne voit pas."
echo "Chiffrement AES-256-GCM réversible : un humain autorisé (porteur de clé) ré-identifie, sous audit."
