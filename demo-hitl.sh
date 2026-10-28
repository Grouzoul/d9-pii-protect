#!/usr/bin/env bash
# Démo d9 PII Protect — validation humaine (HITL) sur action sensible.
# Un agent qui modifie un ticket est bloqué tant qu'un humain n'a pas approuvé (lien cliquable par email).
set -euo pipefail
PY=python3
curl -s -m4 localhost:8060/server/health >/dev/null || { echo "d9 down"; exit 1; }

"$PY" - <<'PY'
import json, re, time, urllib.request, urllib.error
B="http://localhost:8060"; MP="http://localhost:8025"; bar="─"*58
def login(e,p):
    r=urllib.request.Request(B+"/auth/login",data=json.dumps({"email":e,"password":p}).encode(),headers={"Content-Type":"application/json"})
    return json.loads(urllib.request.urlopen(r).read())["data"]["access_token"]
def patch(tok,path,body):
    r=urllib.request.Request(B+path,data=json.dumps(body).encode(),method="PATCH")
    r.add_header("Authorization","Bearer "+tok); r.add_header("Content-Type","application/json")
    try:
        with urllib.request.urlopen(r) as x: return x.status,""
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())["errors"][0]["message"]
agt=login("agent@ecluse.io","agent-pwd")

print(f"\n\033[1m{bar}\033[0m\n🤖  L'AGENT tente une action sensible (modifier un ticket)\n\033[1m{bar}\033[0m")
st,msg=patch(agt,"/items/tickets/1",{"statut":"traité par agent IA"})
print(f"   → HTTP {st} — BLOQUÉ : {msg}")

time.sleep(1)
msgs=json.loads(urllib.request.urlopen(MP+"/api/v1/messages").read())["messages"]
html=json.loads(urllib.request.urlopen(MP+f"/api/v1/message/{msgs[0]['ID']}").read())["HTML"]
link=re.search(r'(http://localhost:8060/pii-protect/approve\?token=[0-9a-f-]+&d=approve)', html).group(1)
print(f"\n\033[1m{bar}\033[0m\n📧  Un email de validation part vers l'humain (boîte Mailpit → http://localhost:8025)\n\033[1m{bar}\033[0m")
print("   Lien « Approuver » :", link)

print(f"\n\033[1m{bar}\033[0m\n👤  L'HUMAIN clique le lien → approuve\n\033[1m{bar}\033[0m")
print("   →", urllib.request.urlopen(link).status, "(page de confirmation)")

print(f"\n\033[1m{bar}\033[0m\n🤖  L'AGENT réessaie\n\033[1m{bar}\033[0m")
st,msg=patch(agt,"/items/tickets/1",{"statut":"traité par agent IA"})
print(f"   → HTTP {st} — l'action passe ✅")
print(f"\n{bar}\nValidation humaine = garde-fou dans l'extension, sur les actions configurées (ici : modifier un ticket).")
print("Email aujourd'hui ; Slack/Teams/2FA = même point d'extension (notify).")
PY
