# Modèles NER / PII par langue — répertoire de bascule

Le moteur charge **un modèle NER Hugging Face** via la variable d'env **`PII_NER_MODEL`**.
Pour changer de langue ou de qualité, il suffit de pointer sur un autre modèle (voir `ner.py`).

> ⚠️ Chaque modèle a **son propre jeu de labels**. En changeant de modèle, vérifier/ajuster le
> mapping des entités (cf. `ner.py`, section « MAPPING »). Partir d'un modèle **PII** (pas un NER
> généraliste) donne de meilleurs résultats sur les données personnelles.

## 🇫🇷 Français (défaut)
| Modèle | Usage | Lien |
|---|---|---|
| **Anonym-IA/V2-camembert-ner-pii-french** *(défaut)* | PII FR, ~40 types (NIR, IBAN, cadastre…) | https://huggingface.co/Anonym-IA/V2-camembert-ner-pii-french |
| Jean-Baptiste/camembert-ner | NER généraliste FR (PER/LOC/ORG) | https://huggingface.co/Jean-Baptiste/camembert-ner |
| cmarkea/distilcamembert-base-ner | NER FR plus léger/rapide | https://huggingface.co/cmarkea/distilcamembert-base-ner |

## 🌍 Multilingue (dont FR)
| Modèle | Usage | Lien |
|---|---|---|
| Davlan/xlm-roberta-base-ner-hrl | NER 10 langues (PER/ORG/LOC) | https://huggingface.co/Davlan/xlm-roberta-base-ner-hrl |
| Babelscape/wikineural-multilingual-ner | NER 9 langues | https://huggingface.co/Babelscape/wikineural-multilingual-ner |
| **urchade/gliner_multi_pii-v1** | **PII zero-shot multilingue** (types libres) | https://huggingface.co/urchade/gliner_multi_pii-v1 |
| lakshyakh93/deberta_finetuned_pii | PII multilingue (jeu ai4privacy) | https://huggingface.co/lakshyakh93/deberta_finetuned_pii |

## 🇬🇧 Anglais
| Modèle | Usage | Lien |
|---|---|---|
| dslim/bert-base-NER | NER EN (PER/ORG/LOC/MISC) | https://huggingface.co/dslim/bert-base-NER |
| Jean-Baptiste/roberta-large-ner-english | NER EN robuste | https://huggingface.co/Jean-Baptiste/roberta-large-ner-english |

## 🇩🇪 / 🇪🇸 / 🇮🇹 (points de départ)
| Langue | Modèle | Lien |
|---|---|---|
| DE | fhswf/bert_de_ner | https://huggingface.co/fhswf/bert_de_ner |
| ES | mrm8488/bert-spanish-cased-finetuned-ner | https://huggingface.co/mrm8488/bert-spanish-cased-finetuned-ner |
| IT | osiria/bert-italian-cased-ner | https://huggingface.co/osiria/bert-italian-cased-ner |

> Liens = **points de départ à vérifier/comparer sur Hugging Face**. Pour la détection de PII
> (vs NER généraliste), privilégier les modèles « pii » / ai4privacy / GLiNER-PII.
> La partie **identifiants structurés** (IBAN, CB, NIR, SIREN…) est couverte par les **regex +
> checksum** (`recognizers.py`), indépendamment de la langue du NER.
