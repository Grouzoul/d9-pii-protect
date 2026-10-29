/**
 * directus-extension-pii-protect — intégration 1-clic du moteur d'anonymisation dans d9.
 *
 * Rôle marqué « Agent IA » (champ booléen `is_agent` sur le rôle) :
 *   - items.read            : chiffre les PII des champs TEXTE LIBRE (secure-by-default) via le moteur sidecar
 *   - items.create/update   : rehydrate les marqueurs [[PII:...]] avant écriture
 *   - GET /assets/:pk        : SECURE-BY-DEFAULT sur TOUT fichier accessible à l'agent —
 *                              docs texte (.txt/.docx…) anonymisés, images caviardées (OCR),
 *                              type non pris en charge = refus fail-closed (rien ne fuit)
 *   - files.upload           : rehydrate un document ré-uploadé par un agent (round-trip)
 *
 * Tout est piloté par VARIABLES D'ENVIRONNEMENT (aucune dépendance à un environnement précis) :
 *   PII_PROTECT_ENGINE_URL   URL du moteur sidecar (défaut http://host.docker.internal:8077)
 *   PII_PROTECT_FIELDS       "*" ou absent = tous les champs de type `text` (défaut sécurisé) ;
 *                            JSON {"collection":["champ",...]} pour restreindre explicitement.
 *   Désignation « agent »    = toggle `is_agent` sur le rôle (modèle de données, dynamique).
 *
 * Pas de logs custom : l'activity log natif de d9 trace déjà tout.
 */
import { defineHook } from '@directus/extensions-sdk';
import { Readable } from 'node:stream';

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
// Auto-appel de d9 sur son port interne (configurable via l'env PORT de Directus, défaut 8055). Jamais en dur.
const SELF = 'http://127.0.0.1:' + (process.env.PORT || '8055');
// Types de fichiers traités par type de contenu. Hors de ces listes -> refus fail-closed (secure-by-default).
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];
const IMAGE_DOCS = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'tif', 'webp'];

// Config des champs : JSON explicite, sinon secure-by-default (tous les champs `text`).
let FIELDS_MAP: Record<string, string[]> | null = null;
if (process.env.PII_PROTECT_FIELDS && process.env.PII_PROTECT_FIELDS !== '*') {
  try { FIELDS_MAP = JSON.parse(process.env.PII_PROTECT_FIELDS); } catch { FIELDS_MAP = null; }
}

// Métadonnées de fichier porteuses de PII (le NOM d'un objet stocké, pas que son contenu).
const FILE_META_FIELDS = ['filename_download', 'title', 'description'];

function freeTextFields(schema: any, collection: string): string[] {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  // secure-by-default : tous les champs de type `text` (texte libre), là où le RBAC-champ est aveugle.
  try {
    const fields = schema?.collections?.[collection]?.fields || {};
    const texts = Object.values(fields).filter((f: any) => f.type === 'text').map((f: any) => f.field);
    // directus_files : on protège aussi le nom/titre/description (métadonnées string souvent pleines de PII).
    if (collection === 'directus_files') return Array.from(new Set([...texts, ...FILE_META_FIELDS]));
    return texts;
  } catch { return []; }
}

const roleCache = new Map<string, { v: boolean; at: number }>();
async function isAgentRole(database: any, roleId?: string): Promise<boolean> {
  if (!roleId) return false;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10000) return hit.v;
  let v = false;
  try {
    const row = await database('directus_roles').select('is_agent').where({ id: roleId }).first();
    v = !!(row && row.is_agent);
  } catch { v = false; }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

async function call(path: '/anonymize' | '/rehydrate', text: string): Promise<string> {
  const r = await fetch(ENGINE + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return ((await r.json()) as { text: string }).text;
}

async function bufferStream(stream: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

export default defineHook(({ filter, init, action }, { logger, database, services, getSchema }: any) => {
  // -------- LECTURE : anonymisation des champs texte libre pour les rôles agents --------
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    const role = ctx?.accountability?.role;
    if (!(await isAgentRole(ctx?.database, role))) return payload;
    const fields = freeTextFields(ctx?.schema, meta.collection);
    if (!fields.length || !Array.isArray(payload)) return payload;
    for (const item of payload) {
      if (!item) continue;
      for (const f of fields) {
        if (typeof item[f] === 'string' && item[f]) {
          try { item[f] = await call('/anonymize', item[f]); }
          catch (e: any) { logger.warn('[pii-protect] anonymize indispo: ' + e.message); item[f] = '[protégé — indisponible]'; } // fail-closed
        }
      }
    }
    return payload;
  });

  // -------- ÉCRITURE : rehydrate les marqueurs avant persistance --------
  const rehydrate = async (payload: any, meta: any, ctx: any) => {
    if (!payload) return payload;
    const fields = freeTextFields(ctx?.schema, meta.collection);
    for (const f of fields) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await call('/rehydrate', payload[f]); }
        catch (e: any) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  // -------- FICHIERS : secure-by-default sur TOUT fichier accessible à un agent --------
  init('routes.before', ({ app }: any) => {
    // MÉTADONNÉES de fichier : d9 n'émet PAS `items.read` pour directus_files -> on intercepte la route /files
    // pour anonymiser le NOM/titre/description (le « nom de l'objet stocké », pas que son contenu).
    const anonFileMeta = async (o: any) => {
      if (!o || typeof o !== 'object') return;
      for (const f of FILE_META_FIELDS) {
        if (typeof o[f] === 'string' && o[f]) {
          try { o[f] = await call('/anonymize', o[f]); }
          catch { o[f] = '[protégé — indisponible]'; } // fail-closed
        }
      }
    };
    const filesHandler = async (req: any, res: any, next: any) => {
      if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // interne -> brut
      let agent = false;
      try { agent = await isAgentRole(database, req.accountability?.role); } catch { agent = false; }
      if (!agent) return next(); // humain -> brut
      try {
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
          headers: { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' },
        });
        if (!orig.ok) return res.status(orig.status && orig.status !== 200 ? orig.status : 502).json({ errors: [{ message: 'protégé — accès refusé' }] });
        const json: any = await orig.json();
        if (Array.isArray(json?.data)) for (const it of json.data) await anonFileMeta(it);
        else await anonFileMeta(json?.data);
        return res.json(json);
      } catch (e: any) {
        logger.warn('[pii-protect] /files (agent, fail-closed): ' + e.message);
        return res.status(503).json({ errors: [{ message: 'protégé — indisponible' }] });
      }
    };
    app.get('/files', filesHandler);
    app.get('/files/:pk', filesHandler);

    app.get('/assets/:pk', async (req: any, res: any, next: any) => {
      if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // requête interne -> original
      // Déterminer le rôle AVANT le try : un humain passe toujours (next), un agent est TOUJOURS fail-closed.
      let agent = false;
      try { agent = await isAgentRole(database, req.accountability?.role); } catch { agent = false; }
      if (!agent) return next(); // humain -> original (RBAC d9 décide)
      try {
        // Re-fetch interne de l'original. On transmet TOUTES les creds (header, cookie ; le token en query
        // est déjà dans originalUrl) pour authentifier comme l'a fait l'UI — sinon on ne doit PAS retomber
        // sur le clair.
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
          headers: {
            authorization: req.headers.authorization || '',
            cookie: req.headers.cookie || '',
          },
        });
        if (!orig.ok) {
          // L'agent n'a pas pu lire l'original (perm/erreur) -> propager le refus, JAMAIS le clair (fail-closed).
          return res.status(orig.status && orig.status !== 200 ? orig.status : 502)
                    .send('[protégé — accès refusé]');
        }
        const ctype = orig.headers.get('content-type') || 'application/octet-stream';
        const cdisp = orig.headers.get('content-disposition') || '';
        const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp);
        const name = decodeURIComponent((m && m[1]) || String(req.params.pk));
        const ext = name.toLowerCase().split('.').pop() || '';
        const buf = Buffer.from(await orig.arrayBuffer());
        // Routage par type. Inconnu (binaire…) -> refus fail-closed : on ne laisse RIEN fuir.
        const endpoint = TEXT_DOCS.includes(ext) ? '/anonymize-doc'
                       : IMAGE_DOCS.includes(ext) ? '/redact-image'
                       : ext === 'pdf' ? '/redact-pdf'
                       : null;
        if (!endpoint) {
          return res.status(415).send('[protégé — type de fichier non pris en charge]'); // secure-by-default
        }
        const r = await fetch(ENGINE + endpoint, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
        });
        if (!r.ok) throw new Error('engine HTTP ' + r.status);
        const out = Buffer.from(((await r.json()) as { content_b64: string }).content_b64, 'base64');
        res.setHeader('content-type', ctype);
        if (cdisp) res.setHeader('content-disposition', cdisp);
        return res.send(out);
      } catch (e: any) {
        logger.warn('[pii-protect] /assets (agent, fail-closed): ' + e.message);
        return res.status(503).send('[protégé — moteur indisponible]'); // fail-closed, jamais next()->clair
      }
    });
  });

  // -------- UPLOAD : rehydrate un document ré-uploadé par un agent (round-trip fichier) --------
  action('files.upload', async (meta: any, ctx: any) => {
    try {
      if (!(await isAgentRole(database, ctx?.accountability?.role))) return; // upload humain/système -> inchangé (garde anti-récursion)
      const key = (meta && (meta.key || (meta.payload && meta.payload.id))) || meta;
      if (!key || typeof key !== 'string') return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = (file && (file.filename_download || file.filename_disk)) || '';
      if (!TEXT_DOCS.includes(name.toLowerCase().split('.').pop())) return;
      const assets = new services.AssetsService({ schema, accountability: sys });
      const asset = await assets.getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const r = await fetch(ENGINE + '/rehydrate-doc', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
      });
      if (!r.ok) throw new Error('engine HTTP ' + r.status);
      const clear = Buffer.from(((await r.json()) as { content_b64: string }).content_b64, 'base64');
      if (clear.equals(buf)) return;
      await files.uploadOne(Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title }, key);
      logger.info('[pii-protect] document ré-uploadé rehydraté (' + name + ')');
    } catch (e: any) {
      logger.warn('[pii-protect] files.upload: ' + e.message);
    }
  });

  logger.info('[pii-protect] hook chargé (engine ' + ENGINE + ')');
});
