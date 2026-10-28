#!/usr/bin/env python3
"""Génère docs/comparator.html — 2 parties interactives :
  1) Humain vs Agent (vraies détections FR bakées)
  2) Notre moteur vs Presidio (EN) vs Hoop/Alcatraz (détections réelles des 3)."""
import json, os, urllib.request

OURS = "http://localhost:8077/detect"
PRESIDIO = "http://localhost:5002/analyze"
SCR = "/private/tmp/claude-501/-Users-grouzoul/30d1e382-b23f-42ef-978c-98cb42925b90/scratchpad"
OUT = os.path.join(os.path.dirname(__file__), "docs", "comparator.html")

def ours_detect(text):
    req = urllib.request.Request(OURS, data=json.dumps({"text": text}).encode(), headers={"Content-Type": "application/json"})
    return [{"start": s["start"], "end": s["end"], "type": s["type"]} for s in json.loads(urllib.request.urlopen(req, timeout=60).read())["spans"]]

def presidio_detect(text):
    req = urllib.request.Request(PRESIDIO, data=json.dumps({"text": text, "language": "en"}).encode(), headers={"Content-Type": "application/json"})
    res = json.loads(urllib.request.urlopen(req, timeout=60).read())
    return [{"start": r["start"], "end": r["end"], "type": r["entity_type"]} for r in res if r.get("score", 1) >= 0.4]

# ---------- Partie 1 : humain vs agent ----------
EXAMPLES = [
    "Le client Jean Dupont conteste un prélèvement sur son IBAN FR7630006000011234567890189, son NIR 1 85 05 78 006 084 36. Le rappeler au 06 12 34 56 78.",
    "Sophie Lemaire habite au 12 rue des Lilas à Lyon. Email de contact : sophie.lemaire@example.fr.",
    "Société Durand SARL, SIRET 552 100 554 00005, facture émise le 14 mars 2025. Référent : Pierre-Yves Martin au 07.88.99.00.11.",
]
def segment(text, spans):
    spans = sorted(spans, key=lambda s: s["start"]); segs, pos = [], 0
    for s in spans:
        if s["start"] < pos: continue
        if s["start"] > pos: segs.append({"t": text[pos:s["start"]]})
        segs.append({"p": s["type"], "v": text[s["start"]:s["end"]]}); pos = s["end"]
    if pos < len(text): segs.append({"t": text[pos:]})
    return segs
DATA = json.dumps([segment(t, ours_detect(t)) for t in EXAMPLES], ensure_ascii=False)

# ---------- Partie 2 : 3 moteurs ----------
COMPARE_SENTS = json.load(open(os.path.join(SCR, "adetect", "sents.json")))
ALCA = json.load(open(os.path.join(SCR, "adetect", "alcatraz_out.json")))
def overlaps(a, b): return a["start"] < b["end"] and b["start"] < a["end"]
def build_compare():
    out = []
    for i, t in enumerate(COMPARE_SENTS):
        o, p, a = ours_detect(t), presidio_detect(t), ALCA[i]["spans"]
        allsp = sorted(o + p + a, key=lambda s: s["start"])
        union = []
        for s in allsp:
            if union and s["start"] < union[-1]["end"]:
                union[-1]["end"] = max(union[-1]["end"], s["end"])
            else:
                union.append({"start": s["start"], "end": s["end"]})
        spans = []
        for u in union:
            lab = None
            for src in (o, p, a):
                for s in src:
                    if overlaps(s, u): lab = s["type"]; break
                if lab: break
            spans.append({"label": lab or "PII", "v": t[u["start"]:u["end"]]})
        caught = lambda eng: [any(overlaps(s, u) for s in eng) for u in union]
        out.append({"text": t, "spans": spans, "caught": {"ours": caught(o), "presidio": caught(p), "alcatraz": caught(a)}})
    return out
COMPARE = json.dumps(build_compare(), ensure_ascii=False)

HTML = r"""<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>d9 PII Protect — Voyez vous-même</title>
<style>
  :root{--violet:#6644FF;--violet-d:#4422dd;--violet-l:#a594ff;--violet-soft:#efecfe;--mint:#1f9e82;--mint-bright:#2ecda7;--clay:#A84B38;
    --bg:#f3f2fb;--surface:#fff;--ink:#272339;--dim:#6f6990;--line:#e4e1f2;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
  .wrap{max-width:880px;margin:0 auto;padding:40px 22px 90px}
  .kick{font-weight:650;font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--violet);margin:0 0 10px}
  h1{font-size:clamp(30px,6vw,46px);line-height:1.05;letter-spacing:-.03em;font-weight:820;margin:0}
  .lead{font-size:19px;color:var(--dim);max-width:42em;margin:16px 0 0}
  h2{font-size:24px;letter-spacing:-.02em;margin:52px 0 6px;font-weight:780}
  .sec-sub{color:var(--dim);margin:0 0 14px;font-size:16px}
  .toggle{position:sticky;top:12px;z-index:5;display:inline-flex;background:var(--surface);border:1px solid var(--line);border-radius:100px;padding:5px;margin:20px 0 8px;box-shadow:0 6px 24px rgba(40,35,57,.08)}
  .toggle button{border:0;background:none;cursor:pointer;font-family:var(--sans);font-weight:700;font-size:15px;color:var(--dim);padding:10px 20px;border-radius:100px;display:flex;gap:8px;align-items:center}
  .toggle button.on.human{background:var(--ink);color:#fff}
  .toggle button.on.agent{background:var(--violet);color:#fff;box-shadow:0 3px 0 var(--violet-d)}
  .state{font-family:var(--mono);font-size:12px;color:var(--dim);margin:4px 0 0}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin:14px 0;font-size:18px;line-height:1.75}
  .card .meta{font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);margin-bottom:8px}
  .pii{display:inline-flex;align-items:center;gap:5px;background:var(--violet);color:#fff;border-radius:7px;padding:1px 9px;font-size:.82em;font-weight:650;white-space:nowrap}
  .pii .lock{font-size:.85em}
  .clear-pii{background:#fff4d6;border-radius:5px;padding:0 3px;box-shadow:inset 0 -2px 0 #ffd87a}
  .leak{color:var(--clay);font-weight:650;text-decoration:underline wavy var(--clay);text-underline-offset:3px}
  textarea{width:100%;min-height:90px;border:1px solid var(--line);border-radius:12px;padding:14px 16px;font-family:var(--sans);font-size:16px;resize:vertical;background:var(--surface);color:var(--ink)}
  textarea:focus{outline:2px solid var(--violet);outline-offset:2px}
  .note{border-left:3px solid var(--mint-bright);background:var(--surface);border-radius:0 11px 11px 0;padding:10px 16px;margin:12px 0;font-size:14px;color:var(--dim)}
  /* part 2 */
  .ctabs{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 14px}
  .ctab{border:1px solid var(--line);background:var(--surface);border-radius:100px;padding:7px 15px;cursor:pointer;font-family:var(--sans);font-weight:600;font-size:14px;color:var(--dim)}
  .ctab.on{background:var(--violet-soft);border-color:var(--violet);color:var(--violet)}
  .erow{border:1px solid var(--line);border-radius:14px;padding:14px 18px;margin:10px 0;background:var(--surface)}
  .erow.eng-ours{border-color:var(--violet);background:var(--violet-soft)}
  .ehead{font-weight:720;font-size:14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
  .escore{font-family:var(--mono);font-size:12px;color:var(--dim)}
  .eng-ours .escore{color:var(--mint)}
  .ebody{font-size:16.5px;line-height:1.7}
  /* bars */
  .bars{margin:16px 0;display:flex;flex-direction:column;gap:12px}
  .bar{display:grid;grid-template-columns:200px 1fr auto;align-items:center;gap:14px}
  .bar .n{font-weight:650;font-size:15px}.bar .n small{display:block;color:var(--dim);font-weight:500;font-size:12px}
  .bar .tk{height:22px;border-radius:7px;background:var(--violet-soft);overflow:hidden}
  .bar .fl{height:100%;border-radius:7px}.bar .vv{font-family:var(--mono);font-weight:700;font-variant-numeric:tabular-nums}
  footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--line);font-family:var(--mono);font-size:12px;color:var(--dim)}
  footer a{color:var(--violet)}
  @media(max-width:560px){.bar{grid-template-columns:110px 1fr auto}}
</style></head>
<body><div class="wrap">
  <p class="kick">d9 PII Protect · démonstration</p>
  <h1>Voyez vous-même.</h1>
  <p class="lead">Deux démonstrations interactives : ce que voit un agent IA de vos données, et ce que les différents moteurs de détection savent (ou non) repérer en français.</p>

  <h2>1 · La même donnée, vue par un humain et par un agent</h2>
  <p class="sec-sub">Basculez le sélecteur : l'agent ne voit jamais les données personnelles en clair.</p>
  <div class="toggle" role="tablist">
    <button id="bHuman" class="human" onclick="setMode('human')">👤 Humain</button>
    <button id="bAgent" class="agent" onclick="setMode('agent')">🤖 Agent IA</button>
  </div>
  <p class="state" id="state"></p>
  <div id="examples"></div>

  <h3 style="margin:26px 0 8px;font-size:18px">Testez le vôtre</h3>
  <p class="sec-sub">Collez un texte (nom, NIR, IBAN, email, téléphone, SIREN…).</p>
  <textarea id="ta" oninput="renderTest()">Jean Dupont, NIR 1 85 05 78 006 084 36, IBAN FR7630006000011234567890189, tél 06 12 34 56 78, SIREN 552 100 554.</textarea>
  <div class="card" id="testOut" style="margin-top:12px"></div>
  <div class="note">Détection ici <strong>côté navigateur</strong> (regex) pour la démo. Le vrai moteur FR — noms, lieux, NIR… via CamemBERT / Anonym-IA — tourne côté serveur, avec chiffrement réversible.</div>

  <h2>2 · Notre moteur vs les autres</h2>
  <p class="sec-sub">Mêmes phrases, trois moteurs. Le <span class="leak">rouge souligné</span> = donnée personnelle <strong>laissée en clair</strong> (fuite) ; le <span class="pii"><span class="lock">🔒</span>chip</span> = détectée.</p>
  <div id="compare"></div>
  <div class="note">Détections réelles : notre moteur (FR), Microsoft Presidio (anglais par défaut), Hoop/Alcatraz (défaut). Corpus FR.</div>

  <h2>Le score, en un chiffre</h2>
  <p class="sec-sub">Rappel mesuré sur un corpus FR identique (46 données personnelles).</p>
  <div class="bars">
    <div class="bar"><div class="n">Hoop · Alcatraz<small>défaut</small></div><div class="tk"><div class="fl" style="width:35%;background:var(--clay)"></div></div><div class="vv">0,35</div></div>
    <div class="bar"><div class="n">Presidio<small>anglais</small></div><div class="tk"><div class="fl" style="width:87%;background:var(--violet-l)"></div></div><div class="vv">0,87</div></div>
    <div class="bar"><div class="n" style="color:var(--violet)">d9 PII Protect<small>FR-first</small></div><div class="tk"><div class="fl" style="width:100%;background:var(--mint-bright)"></div></div><div class="vv" style="color:var(--mint)">1,00</div></div>
  </div>
  <p class="sec-sub" style="font-size:15px">Identifiants français (NIR, SIREN, SIRET) : les autres <b style="color:var(--clay)">0</b>, nous <b style="color:var(--mint)">26/26</b>.</p>
  <div class="note" style="border-left-color:var(--violet)">Cadres de référence : <strong>OWASP Top 10 for LLM Applications 2025</strong> (LLM02 — Sensitive Information Disclosure) &amp; <strong>RGPD</strong> (minimisation, art. 5.1.c).</div>

  <footer>d9 PII Protect · <a href="./index.html">documentation</a> · <a href="./slides.html">deck</a> — Par La Webcapsule · support@webcapsule.io</footer>
</div>
<script>
var EXAMPLES=__DATA__, COMPARE=__COMPARE__;
var LABELS={PERSON:"Nom",PRENOM_PERSONNE:"Prénom",NOM_PERSONNE:"Nom",LOCATION:"Lieu",NOM_VOIE:"Adresse",NUMERO_VOIE:"Adresse",VILLE:"Ville",CODE_POSTAL:"Code postal",COUNTRY:"Pays",
  FR_NIR:"NIR",NUM_SECURITE_SOCIALE:"NIR",IBAN_CODE:"IBAN",IBAN:"IBAN",PHONE_NUMBER:"Téléphone",TELEPHONE:"Téléphone",EMAIL_ADDRESS:"Email",EMAIL:"Email",
  SIREN:"SIREN",SIRET:"SIRET",CREDIT_CARD:"Carte",DATE_FR:"Date",DATE:"Date",DATE_TIME:"Date",IP_ADDRESS:"IP",IP:"IP",ORGANIZATION:"Société",NOM_SOCIETE:"Société",URL:"URL",US_DRIVER_LICENSE:"Permis US"};
function lab(t){return LABELS[t]||t;}
function esc(s){return s.replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
var mode='human';
function chip(l){return '<span class="pii"><span class="lock">🔒</span>'+lab(l)+'</span>';}
function renderSegs(segs){return segs.map(function(s){
  if(s.t!==undefined)return esc(s.t);
  return mode==='agent'?chip(s.p):'<span class="clear-pii">'+esc(s.v)+'</span>';}).join('');}
function renderExamples(){document.getElementById('examples').innerHTML=EXAMPLES.map(function(segs,i){
  return '<div class="card"><div class="meta">Fiche #'+(i+1)+'</div>'+renderSegs(segs)+'</div>';}).join('');}
function setMode(m){mode=m;
  document.getElementById('bHuman').className='human'+(m==='human'?' on':'');
  document.getElementById('bAgent').className='agent'+(m==='agent'?' on':'');
  document.getElementById('state').textContent=m==='human'?'Vue humaine — données en clair.':'Vue agent — données personnelles chiffrées, jamais exposées au modèle.';
  renderExamples();renderTest();}

/* part 2 */
var ENGINES=[["ours","d9 PII Protect"],["presidio","Presidio (anglais)"],["alcatraz","Hoop · Alcatraz"]];
var cIdx=0;
function renderCompareRow(ex,key){var caught=ex.caught[key],text=ex.text,pos=0,html='';
  ex.spans.forEach(function(sp,i){var s=text.indexOf(sp.v,pos);if(s<0)s=pos;html+=esc(text.slice(pos,s));
    html+=caught[i]?chip(sp.label):'<span class="leak">'+esc(sp.v)+'</span>';pos=s+sp.v.length;});
  html+=esc(text.slice(pos));return html;}
function renderCompare(){var ex=COMPARE[cIdx];
  var tabs=COMPARE.map(function(_,i){return '<button class="ctab'+(i===cIdx?' on':'')+'" onclick="cIdx='+i+';renderCompare()">Exemple '+(i+1)+'</button>';}).join('');
  var rows=ENGINES.map(function(e){var caught=ex.caught[e[0]],n=caught.filter(Boolean).length,tot=caught.length;
    return '<div class="erow '+(e[0]==='ours'?'eng-ours':'')+'"><div class="ehead"><span>'+e[1]+'</span><span class="escore">'+n+'/'+tot+' détectés</span></div><div class="ebody">'+renderCompareRow(ex,e[0])+'</div></div>';}).join('');
  document.getElementById('compare').innerHTML='<div class="ctabs">'+tabs+'</div>'+rows;}

/* détecteur navigateur (regex) pour « testez le vôtre » */
var PRENOMS=("jean marie pierre paul jacques michel andré philippe rené louis sophie claire camille nathalie fatima aïcha mohammed kevin lucas thomas élodie nicolas julien yanis abdoulaye pierre-yves aicha andre rene elodie").split(" ");
function luhn(s){var d=s.replace(/\D/g,'').split('').map(Number),t=0;for(var i=d.length-1,j=0;i>=0;i--,j++){var x=d[i];if(j%2===1){x*=2;if(x>9)x-=9;}t+=x;}return d.length>0&&t%10===0;}
function detectClient(text){var marks=[];function add(s,e,p){marks.push([s,e,p]);}var re,m;
  re=/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;while((m=re.exec(text)))add(m.index,re.lastIndex,'EMAIL');
  re=/\b[A-Z]{2}\d{2}[0-9A-Z]{10,30}\b/g;while((m=re.exec(text)))add(m.index,re.lastIndex,'IBAN');
  re=/\b[12](?:[ .]?\d){14}\b/g;while((m=re.exec(text)))add(m.index,re.lastIndex,'FR_NIR');
  re=/(?:\+33|0)[\s.]?\d(?:[\s.]?\d\d){4}/g;while((m=re.exec(text)))add(m.index,re.lastIndex,'PHONE_NUMBER');
  re=/\b\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4}\b/g;while((m=re.exec(text)))add(m.index,re.lastIndex,'DATE');
  re=/\b\d{1,2}(?:er)?\s+(?:janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre)(?:\s+\d{4})?\b/gi;while((m=re.exec(text)))add(m.index,re.lastIndex,'DATE_FR');
  re=/\d[\d ]{7,}\d/g;while((m=re.exec(text))){var dg=m[0].replace(/\D/g,'');if(dg.length===9&&luhn(dg))add(m.index,re.lastIndex,'SIREN');else if(dg.length===14&&luhn(dg))add(m.index,re.lastIndex,'SIRET');else if(dg.length>=13&&dg.length<=19&&luhn(dg))add(m.index,re.lastIndex,'CREDIT_CARD');}
  re=/\b([A-ZÉÈÀÂÎÏ][a-zà-ÿ'’-]+)(?:\s+([A-ZÉÈÀÂÎÏ][a-zà-ÿ'’-]+))?\b/g;while((m=re.exec(text))){if(PRENOMS.indexOf(m[1].toLowerCase())>=0)add(m.index,m.index+m[0].length,'PERSON');}
  marks.sort(function(a,b){return a[0]-b[0]||b[1]-a[1];});
  var segs=[],pos=0;for(var i=0;i<marks.length;i++){var k=marks[i];if(k[0]<pos)continue;if(k[0]>pos)segs.push({t:text.slice(pos,k[0])});segs.push({p:k[2],v:text.slice(k[0],k[1])});pos=k[1];}
  if(pos<text.length)segs.push({t:text.slice(pos)});return segs;}
function renderTest(){var t=document.getElementById('ta').value;
  document.getElementById('testOut').innerHTML=t?renderSegs(detectClient(t)):'<span style="color:var(--dim)">…</span>';}

setMode('agent');renderCompare();
</script></body></html>
"""

with open(OUT, "w") as f:
    f.write(HTML.replace("__DATA__", DATA).replace("__COMPARE__", COMPARE))
print("écrit:", OUT)

# données partagées (consommées aussi par le deck slides.html)
DATAJS = os.path.join(os.path.dirname(__file__), "docs", "pii-data.js")
with open(DATAJS, "w") as f:
    f.write("window.PII_EXAMPLES=" + DATA + ";\nwindow.PII_COMPARE=" + COMPARE + ";\n")
print("écrit:", DATAJS)
