"""NER FR (transformers) exposé comme recognizer Presidio.

╔══════════════════════════════════════════════════════════════════════════╗
║  CHANGER LE MODÈLE NER ICI  ->  env PII_NER_MODEL  (voir MODELS.md)        ║
║  Défaut : Anonym-IA (CamemBERT PII FR). Chargé une fois au démarrage.       ║
║  Si tu changes de modèle : adapte LABELS à son jeu d'entités.              ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import os
from presidio_analyzer import EntityRecognizer, RecognizerResult

MODEL = os.environ.get("PII_NER_MODEL", "Anonym-IA/V2-camembert-ner-pii-french")
THRESHOLD = float(os.environ.get("PII_NER_THRESHOLD", "0.4"))

# Jeu de labels du modèle (Anonym-IA). À ADAPTER si on change de modèle.
LABELS = [
    "ACCOUNTNUMBER", "AGE", "AMOUNT", "BITCOINADDRESS", "CODE_POSTAL", "COUNTRY", "CREDITCARD",
    "CURRENCY", "DATE", "DOB", "EMAIL", "ETHEREUMADDRESS", "EYECOLOR", "GENDER", "HEIGHT", "IBAN",
    "IP", "JOBAREA", "JOBTITLE", "JOBTYPE", "MAC", "NOM_PERSONNE", "NOM_SOCIETE", "NOM_VOIE",
    "NUMERO_VOIE", "NUM_DOSSIER", "NUM_SECURITE_SOCIALE", "PASSWORD", "PRENOM_PERSONNE",
    "REF_CADASTRALE", "SECONDARYADDRESS", "STATE", "TELEPHONE", "TIME", "URL", "USERAGENT",
    "USERNAME", "VEHICLEVIN", "VEHICLEVRM", "VILLE",
]

class NerRecognizer(EntityRecognizer):
    def __init__(self):
        from transformers import pipeline
        self.pipe = pipeline("token-classification", model=MODEL, aggregation_strategy="simple")
        super().__init__(supported_entities=LABELS, supported_language="fr", name="ner")
    def load(self):
        pass
    def analyze(self, text, entities, nlp_artifacts=None):
        return [RecognizerResult(entity_type=r["entity_group"], start=int(r["start"]), end=int(r["end"]),
                                 score=float(r["score"]))
                for r in self.pipe(text) if float(r.get("score", 1.0)) >= THRESHOLD]
