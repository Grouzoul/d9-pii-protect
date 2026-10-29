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
// Types de fichiers traités par type de contenu. Hors de ces listes -> refus fail-closed (secure-by-default).
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];
const IMAGE_DOCS = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'tif', 'webp'];

// Config des champs : JSON explicite, sinon secure-by-default (tous les champs `text`).
let FIELDS_MAP: Record<string, string[]> | null = null;
if (process.env.PII_PROTECT_FIELDS && process.env.PII_PROTECT_FIELDS !== '*') {
  try { FIELDS_MAP = JSON.parse(process.env.PII_PROTECT_FIELDS); } catch { FIELDS_MAP = null; }
}

function freeTextFields(schema: any, collection: string): string[] {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  // secure-by-default : tous les champs de type `text` (texte libre), là où le RBAC-champ est aveugle.
  try {
    const fields = schema?.collections?.[collection]?.fields || {};
    return Object.values(fields).filter((f: any) => f.type === 'text').map((f: any) => f.field);
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

  // -------- FICHIERS : documents texte tokenisés pour les rôles agents --------
  init('routes.before', ({ app }: any) => {
    app.get('/assets/:pk', async (req: any, res: any, next: any) => {
      try {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // requête interne -> original
        if (!(await isAgentRole(database, req.accountability?.role))) return next();   // humain -> original
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch('http://127.0.0.1:8055' + req.originalUrl + sep + 'ecluse_bypass=1',
          { headers: { authorization: req.headers.authorization || '' } });
        if (!orig.ok) return next();
        const ctype = orig.headers.get('content-type') || 'application/octet-stream';
        const cdisp = orig.headers.get('content-disposition') || '';
        const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp);
        const name = decodeURIComponent((m && m[1]) || String(req.params.pk));
        const ext = name.toLowerCase().split('.').pop() || '';
        const buf = Buffer.from(await orig.arrayBuffer());
        // Routage par type de contenu. Inconnu (PDF, binaire…) -> refus fail-closed : on ne laisse RIEN fuir.
        const endpoint = TEXT_DOCS.includes(ext) ? '/anonymize-doc'
                       : IMAGE_DOCS.includes(ext) ? '/redact-image'
                       : null;
        if (!endpoint) {
          return res.status(415).send('[protégé — type de fichier non pris en charge]'); // secure-by-default
        }
        let out: Buffer;
        try {
          const r = await fetch(ENGINE + endpoint, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
          });
          if (!r.ok) throw new Error('engine HTTP ' + r.status);
          out = Buffer.from(((await r.json()) as { content_b64: string }).content_b64, 'base64');
        } catch (e: any) {
          logger.warn('[pii-protect] /assets ' + endpoint + ' indispo: ' + e.message);
          return res.status(503).send('[protégé — moteur indisponible]'); // fail-closed
        }
        res.setHeader('content-type', ctype);
        if (cdisp) res.setHeader('content-disposition', cdisp);
        return res.send(out);
      } catch (e: any) {
        logger.warn('[pii-protect] /assets: ' + e.message);
        return next();
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
