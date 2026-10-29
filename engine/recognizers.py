"""Recognizers REGEX pour Presidio (PatternRecognizer + validation checksum).

╔══════════════════════════════════════════════════════════════════════════╗
║  AJOUTER UN RECOGNIZER REGEX ICI                                          ║
║  • sans checksum : ajoute une ligne à SIMPLE  (ENTITÉ, regex, score, contexte)║
║  • avec checksum : ajoute un _Checksum(...)  dans build_recognizers()       ║
║  Le « contexte » = mots qui, s'ils sont proches, montent le score (Presidio).║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import re
from presidio_analyzer import PatternRecognizer, Pattern

LANG = "fr"

def luhn(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9: x -= 9
        t += x
    return len(d) > 0 and t % 10 == 0

def iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not (15 <= len(s) <= 34): return False
    s = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in s)) % 97 == 1
    except Exception:
        return False

def _ndig(s): return sum(c.isdigit() for c in s)

_MOIS = "janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre"

# --- Recognizers SANS checksum : (ENTITÉ, regex, score, [mots de contexte]) ---
# NB : on réutilise le VOCABULAIRE DE TYPES du modèle NER (voir ner.py LABELS) pour qu'il n'y ait
# qu'UNE liste de types à connaître (ex. PII_PROTECT_SKIP=DATE couvre toutes les dates). Si tu
# changes de modèle NER, aligne ces noms sur son jeu d'entités.
SIMPLE = [
    ("EMAIL",     r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0.9, ["email", "mail", "contact"]),
    ("TELEPHONE", r"(?:\+33|0)[\s.]?\d(?:[\s.]?\d\d){4}", 0.6, ["tel", "téléphone", "appeler", "joindre", "portable"]),
    ("IP",        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.6, ["ip", "serveur", "adresse"]),
    ("NUM_SECURITE_SOCIALE", r"\b[12](?:[ .]?\d){14}\b", 0.7, ["nir", "sécurité sociale", "sécu", "assuré", "sociale"]),
    ("DATE",      rf"\b\d{{1,2}}(?:er)?\s+(?:{_MOIS})(?:\s+\d{{4}})?\b", 0.6, ["né", "née", "le", "date"]),
    ("DATE",      r"\b\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}\b", 0.5, []),
]

class _Checksum(PatternRecognizer):
    def __init__(self, entity, regex, score, context, validator):
        self._validator = validator
        super().__init__(supported_entity=entity, supported_language=LANG,
                         patterns=[Pattern(entity.lower(), regex, score)], context=context)
    def validate_result(self, pattern_text):
        return self._validator(pattern_text)

def build_recognizers():
    recs = [PatternRecognizer(supported_entity=e, supported_language=LANG,
                              patterns=[Pattern(e.lower(), rx, sc)], context=ctx or None)
            for (e, rx, sc, ctx) in SIMPLE]
    # --- Recognizers AVEC checksum ---
    recs += [
        _Checksum("SIREN", r"\b\d{3} ?\d{3} ?\d{3}\b", 0.3, ["siren", "société", "entreprise", "immatricul"],
                  lambda t: _ndig(t) == 9 and luhn(t)),
        _Checksum("SIRET", r"\b\d{3} ?\d{3} ?\d{3} ?\d{5}\b", 0.3, ["siret", "établissement", "société"],
                  lambda t: _ndig(t) == 14 and luhn(t)),
        _Checksum("IBAN_CODE", r"\b[A-Z]{2}\d{2}[0-9A-Z ]{10,34}\b", 0.3, ["iban", "virement", "compte", "bancaire"],
                  iban_ok),
        _Checksum("CREDIT_CARD", r"\b(?:\d[ -]?){13,19}\b", 0.3, ["carte", "cb", "paiement", "visa", "mastercard"],
                  lambda t: _ndig(t) not in (9, 14) and luhn(t)),
    ]
    return recs
