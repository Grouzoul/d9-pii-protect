"""French NER exposed as a Presidio recognizer.

╔══════════════════════════════════════════════════════════════════════════╗
║  CHANGE THE NER MODEL HERE  ->  env PII_NER_MODEL  (see MODELS.md)         ║
║  Default: Anonym-IA (CamemBERT PII FR).                                     ║
║  Backend (env PII_NER_BACKEND):                                             ║
║    "onnx"  (default) -> ONNX Runtime, no PyTorch at runtime. The model is   ║
║              exported to ONNX at build time and baked at PII_NER_ONNX_DIR.   ║
║              ~30% faster on CPU, identical detections.          ║
║    "torch" -> transformers/PyTorch pipeline (requires torch in the image).  ║
║  If you switch models: adapt LABELS to its entity set.                      ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import os
from presidio_analyzer import EntityRecognizer, RecognizerResult

MODEL = os.environ.get("PII_NER_MODEL", "Anonym-IA/V2-camembert-ner-pii-french")
BACKEND = os.environ.get("PII_NER_BACKEND", "onnx")       # onnx | torch
ONNX_DIR = os.environ.get("PII_NER_ONNX_DIR", "/models/onnx")
THRESHOLD = float(os.environ.get("PII_NER_THRESHOLD", "0.4"))
# A transformer NER has a bounded window; a long text (a contract…) would silently be TRUNCATED and
# the PII past the window would leak. So we run the NER over sliding CHAR windows (with overlap) and
# re-base the offsets. ~1500 chars ≈ 450 tokens: safely inside the model window AND ONNX's fast zone.
# (Regex/checksum recognizers already run on the whole text, so structured IDs are covered regardless.)
MAX_CHARS = int(os.environ.get("PII_NER_MAX_CHARS", "1500"))
OVERLAP = int(os.environ.get("PII_NER_OVERLAP", "120"))

# Entity set of the model (Anonym-IA). ADAPT this if you switch models.
LABELS = [
    "ACCOUNTNUMBER", "AGE", "AMOUNT", "BITCOINADDRESS", "CODE_POSTAL", "COUNTRY", "CREDITCARD",
    "CURRENCY", "DATE", "DOB", "EMAIL", "ETHEREUMADDRESS", "EYECOLOR", "GENDER", "HEIGHT", "IBAN",
    "IP", "JOBAREA", "JOBTITLE", "JOBTYPE", "MAC", "NOM_PERSONNE", "NOM_SOCIETE", "NOM_VOIE",
    "NUMERO_VOIE", "NUM_DOSSIER", "NUM_SECURITE_SOCIALE", "PASSWORD", "PRENOM_PERSONNE",
    "REF_CADASTRALE", "SECONDARYADDRESS", "STATE", "TELEPHONE", "TIME", "URL", "USERAGENT",
    "USERNAME", "VEHICLEVIN", "VEHICLEVRM", "VILLE",
]

def _build_pipeline():
    from transformers import AutoTokenizer, pipeline
    if BACKEND == "onnx":
        import onnxruntime as ort
        from optimum.onnxruntime import ORTModelForTokenClassification
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL   # pure win
        # Threads: 0 = let ONNX Runtime decide. On heterogeneous CPUs (e.g. Apple perf+efficiency cores)
        # capping to the PHYSICAL/performance-core count is faster than using every vCPU (avoids oversubscription).
        threads = int(os.environ.get("PII_NER_ONNX_THREADS", "0"))
        if threads > 0:
            so.intra_op_num_threads = threads
        src = ONNX_DIR                                   # model + tokenizer baked here
        model = ORTModelForTokenClassification.from_pretrained(src, session_options=so)
    else:
        from transformers import AutoModelForTokenClassification
        src = MODEL
        model = AutoModelForTokenClassification.from_pretrained(MODEL)
    tok = AutoTokenizer.from_pretrained(src)
    return pipeline("token-classification", model=model, tokenizer=tok, aggregation_strategy="simple")

def _windows(text):
    """Yield (offset, chunk) over the text, each <= MAX_CHARS, with OVERLAP, breaking on whitespace
    to avoid cutting an entity. Short texts yield a single (0, text) window -> identical to no chunking."""
    if len(text) <= MAX_CHARS:
        yield 0, text
        return
    i = 0
    while i < len(text):
        end = min(i + MAX_CHARS, len(text))
        if end < len(text):
            sp = text.rfind(" ", i + MAX_CHARS - 300, end)   # prefer a whitespace break near the end
            if sp > i:
                end = sp
        yield i, text[i:end]
        if end >= len(text):
            break
        i = end - OVERLAP                                     # overlap so entities on a boundary are caught

class NerRecognizer(EntityRecognizer):
    def __init__(self):
        self.pipe = _build_pipeline()
        super().__init__(supported_entities=LABELS, supported_language="fr", name="ner")
    def load(self):
        pass
    def analyze(self, text, entities, nlp_artifacts=None):
        # Run the NER over sliding windows and re-base offsets (duplicates from overlap are deduped upstream).
        out = []
        for off, chunk in _windows(text):
            for r in self.pipe(chunk):
                if float(r.get("score", 1.0)) >= THRESHOLD:
                    out.append(RecognizerResult(entity_type=r["entity_group"],
                                                start=off + int(r["start"]), end=off + int(r["end"]),
                                                score=float(r["score"])))
        return out
