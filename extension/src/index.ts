/**
 * directus-extension-pii-protect — intègre le moteur d'anonymisation PII dans d9, par rôle.
 *
 * Pour un rôle marqué « agent » (booléen is_agent sur le rôle) :
 *   items.read           → chiffre les PII des champs texte libre (secure-by-default)
 *   items.create/update  → rehydrate les marqueurs [[PII:…]] avant écriture
 *   GET /assets/:pk       → docs texte anonymisés, images/PDF caviardés, type inconnu refusé (fail-closed)
 *   GET /files[/:pk]      → nom/titre/description des fichiers chiffrés (d9 n'émet pas items.read pour eux)
 *   files.upload          → rehydrate un document ré-uploadé par un agent (round-trip)
 *
 * Piloté par l'environnement — aucun couplage à un environnement précis :
 *   PII_PROTECT_ENGINE_URL  URL du moteur sidecar (défaut http://host.docker.internal:8077)
 *   PII_PROTECT_FIELDS      JSON {collection:[champs]} pour restreindre ; vide/"*" = tous les champs `text`
 *   PORT                    port interne de d9, pour l'auto-appel (défaut 8055)
 * Pas de logs custom : l'audit natif de d9 trace déjà les accès.
 */
import { Readable } from 'node:stream';

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
const SELF = 'http://127.0.0.1:' + (process.env.PORT || '8055'); // d9 s'auto-appelle sur son port interne

// Extension de fichier → endpoint moteur. Absente = type non pris en charge → refus fail-closed.
const FILE_ROUTE: Record<string, string> = {
  txt: '/anonymize-doc', md: '/anonymize-doc', csv: '/anonymize-doc', json: '/anonymize-doc', docx: '/anonymize-doc',
  png: '/redact-image', jpg: '/redact-image', jpeg: '/redact-image', gif: '/redact-image',
  bmp: '/redact-image', tiff: '/redact-image', tif: '/redact-image', webp: '/redact-image',
  pdf: '/redact-pdf',
};
// Métadonnées de fichier porteuses de PII (le NOM de l'objet, pas que son contenu) → chiffrées en entier.
const FILE_META = ['filename_download', 'title', 'description'];

// Restriction explicite par collection, sinon secure-by-default (tous les champs de type `text`).
let FIELDS_MAP: Record<string, string[]> | null = null;
const _pf = process.env.PII_PROTECT_FIELDS;
if (_pf && _pf !== '*') { try { FIELDS_MAP = JSON.parse(_pf); } catch { /* secure-by-default */ } }

const ext = (name: string) => name.toLowerCase().split('.').pop() || '';

function textFields(schema: any, collection: string): string[] {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  const fields = schema?.collections?.[collection]?.fields || {};
  return Object.values(fields).filter((f: any) => f?.type === 'text').map((f: any) => f.field);
}

// Cache court du booléen is_agent par rôle (évite une requête DB par item lu).
const roleCache = new Map<string, { v: boolean; at: number }>();
async function isAgent(database: any, roleId?: string): Promise<boolean> {
  if (!roleId) return false;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10_000) return hit.v;
  let v = false;
  try { v = !!(await database('directus_roles').select('is_agent').where({ id: roleId }).first())?.is_agent; } catch { /* défaut: non-agent */ }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

// Appels moteur : texte (→ texte) et fichier (→ fichier). Lèvent si le moteur répond en erreur (→ fail-closed amont).
async function post(path: string, payload: object): Promise<any> {
  const r = await fetch(ENGINE + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return r.json();
}
const callText = async (path: string, text: string): Promise<string> => (await post(path, { text })).text;
const callFile = async (path: string, filename: string, buf: Buffer): Promise<Buffer> =>
  Buffer.from((await post(path, { filename, content_b64: buf.toString('base64') })).content_b64, 'base64');

async function bufferStream(stream: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

export default ({ filter, init, action }: any, { logger, database, services, getSchema }: any) => {
  // ---- LECTURE : chiffrer les champs texte libre des rôles agents ----
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    if (!Array.isArray(payload) || !(await isAgent(ctx?.database, ctx?.accountability?.role))) return payload;
    const fields = textFields(ctx?.schema, meta.collection);
    for (const item of payload) for (const f of fields) {
      if (typeof item?.[f] === 'string' && item[f]) {
        try { item[f] = await callText('/anonymize', item[f]); }
        catch (e: any) { logger.warn('[pii-protect] anonymize: ' + e.message); item[f] = '[protégé — indisponible]'; } // fail-closed
      }
    }
    return payload;
  });

  // ---- ÉCRITURE : rehydrater les marqueurs avant persistance ----
  const rehydrate = async (payload: any, meta: any, ctx: any) => {
    for (const f of payload ? textFields(ctx?.schema, meta.collection) : []) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try { payload[f] = await callText('/rehydrate', payload[f]); } catch (e: any) { logger.warn('[pii-protect] rehydrate: ' + e.message); }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  // ---- FICHIERS : garde commune des routes ----
  init('routes.before', ({ app }: any) => {
    // Enveloppe toute la logique transverse : requête interne / humain → brut (next) ; agent → re-fetch de
    // l'original avec SES creds puis `handle` ; toute erreur (accès refusé, moteur KO) → `deny` (jamais de clair).
    const guard = (deny: (res: any, code: number) => any, handle: (orig: Response, req: any, res: any) => Promise<any>) =>
      async (req: any, res: any, next: any) => {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next(); // re-fetch interne → brut
        let agent = false;
        try { agent = await isAgent(database, req.accountability?.role); } catch { /* non-agent */ }
        if (!agent) return next(); // humain → brut (le RBAC d9 décide de l'accès)
        try {
          const sep = req.originalUrl.includes('?') ? '&' : '?';
          const orig = await fetch(SELF + req.originalUrl + sep + 'ecluse_bypass=1', {
            headers: { authorization: req.headers.authorization || '', cookie: req.headers.cookie || '' },
          });
          if (!orig.ok) return deny(res, orig.status > 200 ? orig.status : 502); // perm/erreur en amont
          await handle(orig, req, res);
        } catch (e: any) {
          logger.warn('[pii-protect] ' + req.path + ' (fail-closed): ' + e.message);
          deny(res, 503);
        }
      };
    const denyText = (res: any, code: number) => res.status(code).send('[protégé]');
    const denyJson = (res: any, code: number) => res.status(code).json({ errors: [{ message: 'protégé' }] });

    // Métadonnées : d9 n'émet pas items.read pour directus_files → on chiffre nom/titre/description ici.
    app.get(['/files', '/files/:pk'], guard(denyJson, async (orig: Response, _req: any, res: any) => {
      const json: any = await orig.json();
      const rows = Array.isArray(json?.data) ? json.data : [json?.data];
      for (const row of rows) for (const f of (row ? FILE_META : [])) {
        if (typeof row[f] === 'string' && row[f]) row[f] = await callText('/encrypt', row[f]); // nom ENTIER chiffré, réversible
      }
      res.json(json);
    }));

    // Contenu : doc texte anonymisé / image|PDF caviardé / type inconnu refusé.
    app.get('/assets/:pk', guard(denyText, async (orig: Response, req: any, res: any) => {
      const cdisp = orig.headers.get('content-disposition') || '';
      const name = decodeURIComponent(/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp)?.[1] || String(req.params.pk));
      const endpoint = FILE_ROUTE[ext(name)];
      if (!endpoint) return res.status(415).send('[protégé — type non pris en charge]'); // secure-by-default
      const out = await callFile(endpoint, name, Buffer.from(await orig.arrayBuffer()));
      res.setHeader('content-type', orig.headers.get('content-type') || 'application/octet-stream');
      if (cdisp) res.setHeader('content-disposition', cdisp);
      res.send(out);
    }));
  });

  // ---- UPLOAD : rehydrater un document ré-uploadé par un agent (round-trip réversible, docs texte seulement) ----
  action('files.upload', async (meta: any, ctx: any) => {
    try {
      if (!(await isAgent(database, ctx?.accountability?.role))) return;
      const key = meta?.key || meta?.payload?.id || meta;
      if (typeof key !== 'string') return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = file?.filename_download || file?.filename_disk || '';
      if (FILE_ROUTE[ext(name)] !== '/anonymize-doc') return; // images/PDF = caviardage destructif, pas de round-trip
      const asset = await new services.AssetsService({ schema, accountability: sys }).getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const clear = await callFile('/rehydrate-doc', name, buf);
      if (clear.equals(buf)) return; // rien à restaurer
      await files.uploadOne(Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title }, key);
      logger.info('[pii-protect] document rehydraté au ré-upload (' + name + ')');
    } catch (e: any) { logger.warn('[pii-protect] files.upload: ' + e.message); }
  });

  logger.info('[pii-protect] chargé (moteur ' + ENGINE + ')');
};
