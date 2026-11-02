#!/usr/bin/env python3
"""Seed the PII Protect demo on the dedicated d9 (:8055).
Collection tickets (note field = free text with FR PII), agent role + agent user,
boolean field `is_agent` on roles (the toggle the extension reads) enabled on the agent role.
Secure-by-default: no field config to write — the extension protects every `text` field.
(The sample ticket data is kept in French on purpose, to exercise the French PII engine.)"""
import json, urllib.request, urllib.error

BASE = "http://localhost:8055"
ADMIN = ("admin@example.com", "ecluse-admin")
AGENT = ("agent@example.com", "agent-pwd")

def login(email, pwd):
    req = urllib.request.Request(f"{BASE}/auth/login",
        data=json.dumps({"email": email, "password": pwd}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req).read())["data"]["access_token"]

def api(method, path, token, body=None):
    req = urllib.request.Request(f"{BASE}{path}",
        data=(json.dumps(body).encode() if body is not None else None), method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode(); return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode()}") from None

# Sample tickets — French on purpose (realistic data for the FR PII engine).
TICKETS = [
    {"objet": "Remboursement contesté",
     "note": "Le client Jean Dupont (NIR 1 85 05 78 006 084 36) conteste un prélèvement de 149€ sur son IBAN FR7630006000011234567890189. Le rappeler au 06 12 34 56 78."},
    {"objet": "Changement d'adresse",
     "note": "Mme Sophie Lemaire, domiciliée 12 rue des Lilas à Lyon, demande la mise à jour de son dossier. Email de contact : sophie.lemaire@example.fr."},
    {"objet": "Litige facturation entreprise",
     "note": "La société Durand SARL (SIRET 552 100 554 00005) conteste la facture émise le 14 mars 2025. Référent : Pierre-Yves Martin, joignable au 07.88.99.00.11."},
]

def main():
    t = login(*ADMIN); print("admin OK")

    cols = {c["collection"] for c in api("GET", "/collections", t)["data"]}
    if "tickets" not in cols:
        api("POST", "/collections", t, {
            "collection": "tickets", "schema": {},
            "meta": {"icon": "support_agent", "note": "Support tickets — the note field holds free text with PII."},
            "fields": [
                {"field": "id", "type": "integer", "meta": {"hidden": True, "readonly": True},
                 "schema": {"is_primary_key": True, "has_auto_increment": True}},
                {"field": "objet", "type": "string", "meta": {"interface": "input"}},
                {"field": "note", "type": "text", "meta": {"interface": "input-multiline",
                 "note": "Free text — may contain names, NIR, IBAN, SIREN… (field-level RBAC is blind here)."}},
                {"field": "statut", "type": "string", "meta": {"interface": "input"}},
            ],
        }); print("+ tickets collection")
    else:
        print("= tickets collection exists")

    # The toggle the extension reads: boolean field `is_agent` on roles (the only UI addition).
    role_fields = {f["field"] for f in api("GET", "/fields/directus_roles", t)["data"]}
    if "is_agent" not in role_fields:
        api("POST", "/fields/directus_roles", t, {
            "field": "is_agent", "type": "boolean",
            "meta": {"interface": "boolean", "special": ["cast-boolean"],
                     "note": "Filter/anonymize PII for this role (AI agents)."},
            "schema": {"default_value": False},
        }); print("+ is_agent field on directus_roles")
    else:
        print("= is_agent field exists")

    roles = {r["name"]: r["id"] for r in api("GET", "/roles", t)["data"]}
    if "agent" in roles:
        role_id = roles["agent"]; print("= agent role exists")
    else:
        role_id = api("POST", "/roles", t, {"name": "agent", "admin_access": False,
            "app_access": True, "description": "AI agent — reads tickets (PII content anonymized by PII Protect)."})["data"]["id"]
        print("+ agent role", role_id)
    # Enable the is_agent toggle on the agent role.
    api("PATCH", f"/roles/{role_id}", t, {"is_agent": True}); print("  is_agent = true")

    def perm(collection, action, fields):
        q = f"/permissions?filter[role][_eq]={role_id}&filter[collection][_eq]={collection}&filter[action][_eq]={action}"
        if api("GET", q, t)["data"]: return
        api("POST", "/permissions", t, {"role": role_id, "collection": collection,
            "action": action, "fields": fields, "permissions": {}, "validation": {}})
        print(f"  + perm {collection}:{action}")
    perm("tickets", "read", ["*"])
    perm("tickets", "update", ["note", "statut"])
    perm("directus_files", "read", ["*"])    # download documents (/assets)
    perm("directus_files", "create", ["*"])  # re-upload a document (write round-trip)
    perm("directus_files", "update", ["*"])

    users = api("GET", f"/users?filter[email][_eq]={AGENT[0]}&fields=id", t)["data"]
    if not users:
        api("POST", "/users", t, {"email": AGENT[0], "password": AGENT[1], "role": role_id,
            "status": "active", "provider": "default", "first_name": "Agent", "last_name": "IA"})
        print("+ agent user", AGENT[0])
    else:
        print("= agent user exists")

    existing = api("GET", "/items/tickets?limit=1", t)["data"]
    if not existing:
        for rec in TICKETS:
            rec = dict(rec); rec["statut"] = "open"
            api("POST", "/items/tickets", t, rec)
        print(f"+ {len(TICKETS)} tickets seeded")
    else:
        print("= tickets already present")

    print("\nSeed done. Agent role =", role_id, "(is_agent active). Secure-by-default: no field to configure.")

if __name__ == "__main__":
    main()
