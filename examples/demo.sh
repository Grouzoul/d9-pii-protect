#!/usr/bin/env bash
# d9 PII Protect demo — secure-by-default across every entity an agent can access.
# Prerequisites: the deploy/ stack running (docker compose up -d) + seed.py executed.
# Uses only d9's public API (:8055) and python3. No machine-specific dependency.
set -euo pipefail
B="${D9_URL:-http://localhost:8055}"
hr(){ printf '\n\033[1;35m== %s ==\033[0m\n' "$1"; }

tok(){ curl -s -X POST "$B/auth/login" -H 'Content-Type: application/json' -d "$1" \
       | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"; }
ADM=$(tok '{"email":"admin@example.com","password":"admin-pwd"}')
AGT=$(tok '{"email":"agent@example.com","password":"agent-pwd"}')
DIR="$(cd "$(dirname "$0")" && pwd)"

hr "1) TEXT FIELD  (tickets.note, type 'text' — protected with no config)"
echo "HUMAN:"; curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $ADM" \
  | python3 -c "import sys,json;print('  '+json.load(sys.stdin)['data']['note'])"
echo "AGENT:"; curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $AGT" \
  | python3 -c "import sys,json;n=json.load(sys.stdin)['data']['note'];print('  '+('[encrypted] ' if '[[PII:' in n else '[CLEAR!] ')+n)"

hr "2) TEXT DOCUMENT  (samples/dossier.txt via /assets)"
FID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@$DIR/samples/dossier.txt;type=text/plain" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
echo "HUMAN downloads:"; curl -s "$B/assets/$FID" -H "Authorization: Bearer $ADM" | sed 's/^/  /'
echo "AGENT downloads:"; curl -s "$B/assets/$FID" -H "Authorization: Bearer $AGT" | sed 's/^/  /'

hr "3) IMAGE  (samples/carte-identite.png via /assets — OCR redaction)"
IID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@$DIR/samples/carte-identite.png;type=image/png" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
curl -s "$B/assets/$IID" -H "Authorization: Bearer $ADM" -o /tmp/piiprotect_human.png
curl -s "$B/assets/$IID" -H "Authorization: Bearer $AGT" -o /tmp/piiprotect_agent.png
echo "  HUMAN  -> /tmp/piiprotect_human.png (original, $(wc -c </tmp/piiprotect_human.png) bytes)"
echo "  AGENT  -> /tmp/piiprotect_agent.png (redacted, $(wc -c </tmp/piiprotect_agent.png) bytes)"
echo "  Open both to see the PII regions masked on the agent's copy."

hr "4) UNSUPPORTED TYPE  (.bin — fail-closed refusal)"
printf 'binary with Jean Dupont NIR 1 85 05 78 006 084 36' > /tmp/piiprotect.bin
XID=$(curl -s -X POST "$B/files" -H "Authorization: Bearer $ADM" -F "file=@/tmp/piiprotect.bin;type=application/octet-stream" \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['id'])")
echo "  HUMAN: HTTP $(curl -s -o /dev/null -w '%{http_code}' "$B/assets/$XID" -H "Authorization: Bearer $ADM")  (expected 200)"
echo "  AGENT: HTTP $(curl -s -o /dev/null -w '%{http_code}' "$B/assets/$XID" -H "Authorization: Bearer $AGT")  (expected 415 = refused)"

hr "5) WRITE ROUND-TRIP  (the agent writes back markers -> decrypted before storage)"
NOTE=$(curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $AGT" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['note'])")
curl -s -X PATCH "$B/items/tickets/1" -H "Authorization: Bearer $AGT" -H 'Content-Type: application/json' \
  -d "$(python3 -c "import json,sys;print(json.dumps({'note':sys.argv[1]+' [processed by agent]'}))" "$NOTE")" >/dev/null
echo "HUMAN re-reads after the agent's write:"
curl -s "$B/items/tickets/1?fields=note" -H "Authorization: Bearer $ADM" \
  | python3 -c "import sys,json;n=json.load(sys.stdin)['data']['note'];print('  '+('[clear restored OK] ' if '[[PII:' not in n and 'Jean Dupont' in n else '[ANOMALY] ')+n)"
echo
printf '\033[1;32mDemo done.\033[0m Human = clear everywhere; agent = never any PII in clear.\n'
