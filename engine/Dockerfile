# PII anonymization engine (sidecar) — self-contained, FR NER embedded.
# The NER model is exported to ONNX at build time and served via ONNX Runtime (~30% faster on CPU,
# identical detections). torch stays (optimum depends on it + does the export) but the torch model
# cache is dropped after export, so image size stays ~flat.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HF_HOME=/models \
    TRANSFORMERS_CACHE=/models \
    PORT=8077 \
    PII_NER_BACKEND=onnx \
    PII_NER_ONNX_DIR=/models/onnx

WORKDIR /engine

# build-essential + Tesseract OCR FR + poppler (PDF rendering for redaction). No libGL: opencv-python-headless.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential tesseract-ocr tesseract-ocr-fra libglib2.0-0 poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# torch CPU (needed by optimum for the ONNX export; much lighter than the default GPU build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    # presidio-image-redactor pulls opencv-python (GUI/libGL); replace it with the headless variant (server).
    && pip uninstall -y opencv-python opencv-contrib-python 2>/dev/null; \
    pip install --no-cache-dir opencv-python-headless

# Export the NER model to ONNX (+ tokenizer) and bake it. Then drop the torch model cache to keep size flat.
ARG PII_NER_MODEL=Anonym-IA/V2-camembert-ner-pii-french
ENV PII_NER_MODEL=${PII_NER_MODEL}
RUN python -c "import sys; m=sys.argv[1]; \
from optimum.onnxruntime import ORTModelForTokenClassification as M; from transformers import AutoTokenizer as T; \
M.from_pretrained(m, export=True).save_pretrained('/models/onnx'); T.from_pretrained(m).save_pretrained('/models/onnx')" "$PII_NER_MODEL" \
    && rm -rf /models/hub

# Source code last: editing a .py only invalidates this layer (fast rebuild).
COPY app.py analyzer.py crypto.py recognizers.py ner.py image_redact.py ./

EXPOSE 8077
# PII_PROTECT_KEY MUST be provided at run time (secret / KMS). No default key in production.
CMD ["python", "app.py"]
