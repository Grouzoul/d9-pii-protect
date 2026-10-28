/**
 * directus-extension-pii-protect — hook d'anonymisation gouvernée des PII pour agents IA.
 *
 * Rôle marqué « Agent IA » (champ `is_agent`) → :
 *   - items.read            : chiffre les PII des champs texte libre (moteur FR, AES-256-GCM, marqueurs [[PII:]])
 *   - items.create/update   : rehydrate les marqueurs avant écriture
 *   - items.update sensible  : validation humaine (HITL) requise (lien d'approbation par email)
 *   - GET /assets/:pk        : documents texte (.txt/.docx…) tokenisés réversiblement (+ rehydrate au ré-upload via files.upload)
 * Repli rôle : ecluse.config.json > agentRoleIds.
 */
import { defineHook } from '@directus/extensions-sdk';
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';

const CONFIG_PATH = '/directus/extensions/ecluse.config.json';
const TEXT_DOCS = ['txt', 'md', 'csv', 'json', 'docx'];

interface PiiConfig {
  engine: string;
  agentRoleIds?: string[];
  fields: Record<string, string[]>;
  approvals?: Record<string, string[]>;
  approvalEmail?: string;
  baseUrl?: string;
}

let _cfg: PiiConfig | null = null;
let _at = 0;
function cfg(): PiiConfig {
  if (_cfg && Date.now() - _at < 2000) return _cfg;
  try {
    _cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as PiiConfig;
  } catch {
    _cfg = { engine: 'http://host.docker.internal:8077', agentRoleIds: [], fields: {} };
  }
  _at = Date.now();
  return _cfg;
}

const roleCache = new Map<string, { v: boolean; at: number }>();
async function isAgentRole(database: any, roleId?: string): Promise<boolean> {
  if (!roleId) return false;
  const c = cfg();
  if (Array.isArray(c.agentRoleIds) && c.agentRoleIds.includes(roleId)) return true;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 10000) return hit.v;
  let v = false;
  try {
    const row = await database('directus_roles').select('is_agent').where({ id: roleId }).first();
    v = !!(row && row.is_agent);
  } catch {
    v = false;
  }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}

async function call(engine: string, path: '/anonymize' | '/rehydrate', text: string): Promise<string> {
  const r = await fetch(engine + path, {
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

export default defineHook(({ filter, init, action }, { logger, database, services, getSchema, exceptions }: any) => {
  // -------- LECTURE : anonymisation des champs texte pour les rôles agents --------
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    const c = cfg();
    const role = ctx?.accountability?.role;
    if (!(await isAgentRole(ctx?.database, role))) return payload;
    const fields = c.fields?.[meta.collection];
    if (!fields || !Array.isArray(payload)) return payload;
    for (const item of payload) {
      if (!item) continue;
      for (const f of fields) {
        if (typeof item[f] === 'string' && item[f]) {
          try {
            item[f] = await call(c.engine, '/anonymize', item[f]);
          } catch (e: any) {
            logger.warn('[pii-protect] anonymize indispo: ' + e.message);
            item[f] = '[protégé — indisponible]';
          }
        }
      }
    }
    return payload;
  });

  // -------- ÉCRITURE : rehydrate les marqueurs avant persistance --------
  const rehydrate = async (payload: any, meta: any) => {
    const c = cfg();
    const fields = c.fields?.[meta.collection];
    if (!fields || !payload) return payload;
    for (const f of fields) {
      if (typeof payload[f] === 'string' && payload[f].includes('[[PII:')) {
        try {
          payload[f] = await call(c.engine, '/rehydrate', payload[f]);
        } catch (e: any) {
          logger.warn('[pii-protect] rehydrate: ' + e.message);
        }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);

  // -------- VALIDATION HUMAINE (HITL) sur actions sensibles --------
  async function approvalsSvc() {
    return new services.ItemsService('pii_approvals', { schema: await getSchema(), accountability: { admin: true, role: null } });
  }
  async function notify(c: PiiConfig, info: any) {
    // POINT D'EXTENSION : email aujourd'hui ; Slack / Teams / webhook demain (même signature).
    const base = c.baseUrl || 'http://localhost:8060';
    const approve = base + '/pii-protect/approve?token=' + info.token + '&d=approve';
    const deny = base + '/pii-protect/approve?token=' + info.token + '&d=deny';
    const html =
      '<p>Un <b>agent IA</b> demande à <b>modifier</b> ' + info.target_collection + ' #' + info.target_item + '.</p>'
      + '<p style="margin:18px 0">'
      + '<a href="' + approve + '" style="background:#1f9e82;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">✅ Approuver</a>'
      + '&nbsp;&nbsp;<a href="' + deny + '" style="background:#A84B38;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">⛔ Refuser</a></p>'
      + '<p style="color:#888;font-size:12px">d9 PII Protect · réf ' + info.id + '</p>';
    try {
      const mail = new services.MailService({ schema: await getSchema(), accountability: { admin: true } });
      await mail.send({ to: c.approvalEmail, subject: 'Validation requise — ' + info.target_collection + ' #' + info.target_item, html });
      logger.info('[pii-protect] email de validation envoyé (réf ' + info.id + ')');
    } catch (e: any) {
      logger.warn('[pii-protect] notif indispo: ' + e.message + ' | lien: ' + approve);
    }
  }
  const onUpdate = async (payload: any, meta: any, ctx: any) => {
    const c = cfg();
    const role = ctx?.accountability?.role;
    const sensitive = c.approvals?.[meta.collection]?.includes('update');
    if (sensitive && role && (await isAgentRole(ctx?.database, role))) {
      const keys = meta.keys || (meta.key != null ? [meta.key] : []);
      const item = keys.length ? String(keys[0]) : '*';
      const svc = await approvalsSvc();
      const approved = await svc.readByQuery({ filter: { status: { _eq: 'approved' }, target_collection: { _eq: meta.collection }, target_item: { _eq: item }, agent_role: { _eq: role } }, sort: ['-id'], limit: 1 });
      if (approved && approved.length) {
        await svc.updateOne(approved[0].id, { status: 'used' });
      } else {
        const token = globalThis.crypto.randomUUID();
        const id = await svc.createOne({ status: 'pending', kind: 'update', target_collection: meta.collection, target_item: item, agent_role: role, token });
        await notify(c, { id, token, target_collection: meta.collection, target_item: item });
        const msg = 'Validation humaine requise : une demande d’approbation a été envoyée. Réessaie une fois approuvée (réf ' + id + ').';
        if (exceptions?.InvalidPayloadException) throw new exceptions.InvalidPayloadException(msg);
        if (exceptions?.ForbiddenException) throw new exceptions.ForbiddenException(msg);
        throw new Error(msg);
      }
    }
    return rehydrate(payload, meta);
  };
  filter('items.update', onUpdate);

  // -------- FICHIERS : documents texte tokenisés pour les rôles agents --------
  init('routes.before', ({ app }: any) => {
    app.get('/assets/:pk', async (req: any, res: any, next: any) => {
      try {
        if (req.query.ecluse_bypass || req.headers['x-ecluse-bypass']) return next();
        const role = req.accountability?.role;
        if (!(await isAgentRole(database, role))) return next();
        const sep = req.originalUrl.includes('?') ? '&' : '?';
        const orig = await fetch('http://127.0.0.1:8055' + req.originalUrl + sep + 'ecluse_bypass=1',
          { headers: { authorization: req.headers.authorization || '' } });
        if (!orig.ok) return next();
        const ctype = orig.headers.get('content-type') || 'application/octet-stream';
        const cdisp = orig.headers.get('content-disposition') || '';
        const m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp);
        const name = decodeURIComponent((m && m[1]) || String(req.params.pk));
        const ext = name.toLowerCase().split('.').pop();
        const buf = Buffer.from(await orig.arrayBuffer());
        if (!TEXT_DOCS.includes(ext!)) {
          res.setHeader('content-type', ctype);
          if (cdisp) res.setHeader('content-disposition', cdisp);
          return res.send(buf);
        }
        let out: Buffer;
        try {
          const r = await fetch(cfg().engine + '/anonymize-doc', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
          });
          if (!r.ok) throw new Error('engine HTTP ' + r.status);
          out = Buffer.from(((await r.json()) as { content_b64: string }).content_b64, 'base64');
        } catch (e: any) {
          logger.warn('[pii-protect] /assets doc indispo: ' + e.message);
          return res.status(503).send('[protégé — anonymiseur indisponible]');
        }
        res.setHeader('content-type', ctype);
        if (cdisp) res.setHeader('content-disposition', cdisp);
        return res.send(out);
      } catch (e: any) {
        logger.warn('[pii-protect] /assets: ' + e.message);
        return next();
      }
    });

    // lien cliquable d'approbation (HITL) — ouvert depuis l'email
    app.get('/pii-protect/approve', async (req: any, res: any) => {
      try {
        const token = req.query.token;
        const decision = req.query.d === 'deny' ? 'denied' : 'approved';
        if (!token) return res.status(400).send('token manquant');
        const svc = new services.ItemsService('pii_approvals', { schema: await getSchema(), accountability: { admin: true, role: null } });
        const found = await svc.readByQuery({ filter: { token: { _eq: token } }, limit: 1 });
        const a = found && found[0];
        if (!a) return res.status(404).send('Demande introuvable ou expirée.');
        if (a.status === 'pending') await svc.updateOne(a.id, { status: decision });
        const ok = decision === 'approved';
        res.setHeader('content-type', 'text/html; charset=utf-8');
        res.send('<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;max-width:460px;margin:80px auto;text-align:center">'
          + '<div style="font-size:52px">' + (ok ? '✅' : '⛔') + '</div>'
          + '<h2>' + (ok ? 'Action approuvée' : 'Action refusée') + '</h2>'
          + '<p style="color:#555">' + a.target_collection + ' #' + a.target_item + ' — l’agent peut ' + (ok ? 'maintenant procéder.' : 'ne pas procéder.') + '</p>'
          + '<p style="color:#aaa;font-size:12px">d9 PII Protect</p></body>');
      } catch (e: any) {
        logger.warn('[pii-protect] approve: ' + e.message);
        res.status(500).send('erreur');
      }
    });
  });

  // -------- UPLOAD : rehydrate un document ré-uploadé par un agent (round-trip fichier) --------
  action('files.upload', async (meta: any, ctx: any) => {
    try {
      const role = ctx?.accountability?.role;
      if (!(await isAgentRole(database, role))) return;
      const key = (meta && (meta.key || (meta.payload && meta.payload.id))) || meta;
      if (!key || typeof key !== 'string') return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = (file && (file.filename_download || file.filename_disk)) || '';
      const ext = name.toLowerCase().split('.').pop();
      if (!TEXT_DOCS.includes(ext)) return;
      const assets = new services.AssetsService({ schema, accountability: sys });
      const asset = await assets.getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const r = await fetch(cfg().engine + '/rehydrate-doc', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename: name, content_b64: buf.toString('base64') }),
      });
      if (!r.ok) throw new Error('engine HTTP ' + r.status);
      const clear = Buffer.from(((await r.json()) as { content_b64: string }).content_b64, 'base64');
      if (clear.equals(buf)) return;
      await files.uploadOne(Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title }, key);
      logger.info('[pii-protect] document ré-uploadé par un agent -> rehydraté (' + name + ')');
    } catch (e: any) {
      logger.warn('[pii-protect] files.upload rehydrate: ' + e.message);
    }
  });

  logger.info('[pii-protect] hook chargé');
});
