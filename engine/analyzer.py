"""Orchestration Presidio (FR) : tokenizer spaCy blank + NER (Anonym-IA) + recognizers regex.

On réutilise Presidio pour ce qu'il fait de mieux (registry de recognizers, scoring contextuel,
résolution des recognizers) et on garde NOTRE chiffrement (crypto.py) pour l'anonymisation.
"""
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine

import recognizers
import ner

class _BlankFR(SpacyNlpEngine):
    """Tokenizer spaCy FR vide — Presidio a besoin d'un NLP engine, mais le NER
    vient d'Anonym-IA : pas besoin du gros modèle anglais."""
    def __init__(self):
        super().__init__()
        self.nlp = {"fr": spacy.blank("fr")}

_engine = None
def engine():
    global _engine
    if _engine is None:
        e = AnalyzerEngine(nlp_engine=_BlankFR(), supported_languages=["fr"])
        e.registry.add_recognizer(ner.NerRecognizer())
        for r in recognizers.build_recognizers():
            e.registry.add_recognizer(r)
        _engine = e
    return _engine

def warmup():
    engine()

def detect(text):
    """Retourne [(start, end, ENTITÉ)] — dédoublonné par score (le plus haut gagne sur chevauchement)."""
    results = engine().analyze(text=text, language="fr")
    results = sorted(results, key=lambda r: (-r.score, -(r.end - r.start)))
    kept = []
    for r in results:
        if any(r.start < k.end and k.start < r.end for k in kept):  # chevauche un span déjà gardé
            continue
        kept.append(r)
    kept.sort(key=lambda r: r.start)
    out = []
    for r in kept:
        s, e, t = r.start, r.end, r.entity_type
        while e > s and not text[e - 1].isalnum(): e -= 1
        while s < e and not text[s].isalnum(): s += 1
        if e - s >= 2:
            out.append((s, e, t))
    return out
