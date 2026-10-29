# Moteur d'anonymisation PII (sidecar) — auto-suffisant, NER FR en interne.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/models \
    TRANSFORMERS_CACHE=/models \
    PORT=8077

WORKDIR /engine

RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# torch CPU (bien plus léger que la version GPU par défaut)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py crypto.py recognizers.py ner.py ./

# Modèle NER baké dans l'image -> démarrage hors-ligne, pas de téléchargement au runtime.
ARG PII_NER_MODEL=Anonym-IA/V2-camembert-ner-pii-french
ENV PII_NER_MODEL=${PII_NER_MODEL}
RUN python -c "from transformers import pipeline; pipeline('token-classification', model='${PII_NER_MODEL}', aggregation_strategy='simple')"

EXPOSE 8077
# PII_PROTECT_KEY DOIT être fourni au run (secret / KMS). Pas de clé par défaut en prod.
CMD ["python", "app.py"]
