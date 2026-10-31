# NER / PII models by language — switching directory

The engine loads **one Hugging Face NER model** via the **`PII_NER_MODEL`** env variable.
To change language or quality, just point it at another model (see `ner.py`).

> ⚠️ Each model has **its own label set**. When switching models, check/adjust the entity set
> (see `ner.py`, the `LABELS` list). Starting from a **PII** model (not a general-purpose NER)
> gives better results on personal data.

## 🇫🇷 French (default)
| Model | Use | Link |
|---|---|---|
| **Anonym-IA/V2-camembert-ner-pii-french** *(default)* | FR PII, ~40 types (NIR, IBAN, cadastre…) | https://huggingface.co/Anonym-IA/V2-camembert-ner-pii-french |
| Jean-Baptiste/camembert-ner | General-purpose FR NER (PER/LOC/ORG) | https://huggingface.co/Jean-Baptiste/camembert-ner |
| cmarkea/distilcamembert-base-ner | Lighter/faster FR NER | https://huggingface.co/cmarkea/distilcamembert-base-ner |

## 🌍 Multilingual (incl. FR)
| Model | Use | Link |
|---|---|---|
| Davlan/xlm-roberta-base-ner-hrl | NER, 10 languages (PER/ORG/LOC) | https://huggingface.co/Davlan/xlm-roberta-base-ner-hrl |
| Babelscape/wikineural-multilingual-ner | NER, 9 languages | https://huggingface.co/Babelscape/wikineural-multilingual-ner |
| **urchade/gliner_multi_pii-v1** | **Multilingual zero-shot PII** (free-form types) | https://huggingface.co/urchade/gliner_multi_pii-v1 |
| lakshyakh93/deberta_finetuned_pii | Multilingual PII (ai4privacy dataset) | https://huggingface.co/lakshyakh93/deberta_finetuned_pii |

## 🇬🇧 English
| Model | Use | Link |
|---|---|---|
| dslim/bert-base-NER | EN NER (PER/ORG/LOC/MISC) | https://huggingface.co/dslim/bert-base-NER |
| Jean-Baptiste/roberta-large-ner-english | Robust EN NER | https://huggingface.co/Jean-Baptiste/roberta-large-ner-english |

## 🇩🇪 / 🇪🇸 / 🇮🇹 (starting points)
| Language | Model | Link |
|---|---|---|
| DE | fhswf/bert_de_ner | https://huggingface.co/fhswf/bert_de_ner |
| ES | mrm8488/bert-spanish-cased-finetuned-ner | https://huggingface.co/mrm8488/bert-spanish-cased-finetuned-ner |
| IT | osiria/bert-italian-cased-ner | https://huggingface.co/osiria/bert-italian-cased-ner |

> Links = **starting points to verify/compare on Hugging Face**. For PII detection (vs general-purpose
> NER), prefer "pii" / ai4privacy / GLiNER-PII models.
> The **structured identifiers** part (IBAN, credit card, NIR, SIREN…) is covered by **regex +
> checksum** (`recognizers.py`), independently of the NER language.
