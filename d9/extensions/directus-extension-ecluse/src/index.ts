/**
 * directus-extension-pii-protect — hook d'anonymisation gouvernée des PII pour agents IA.
 *
 * Un rôle marqué « Agent IA » (champ `is_agent` sur le rôle d9) passe par l'anonymiseur :
 *   - items.read          → chiffre les PII des champs texte libre (moteur FR, AES-256-GCM)
 *   - items.create/update → rehydrate les marqueurs [[PII:...]] avant écriture en base
 *
 * Repli : rôles listés dans ecluse.config.json > agentRoleIds.
 */
import { defineHook } from '@directus/extensions-sdk';
import { readFileSync } from 'node:fs';

const CONFIG_PATH = '/directus/extensions/ecluse.config.json';

interface PiiConfig {
  engine: string;
  agentRoleIds?: string[];
  fields: Record<string, string[]>;
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

// cache rôle -> is_agent (flag porté par le rôle d9)
const roleCache = new Map<string, { v: boolean; at: number }>();
async function isAgentRole(database: any, roleId?: string): Promise<boolean> {
  if (!roleId) return false;
  const c = cfg();
  if (Array.isArray(c.agentRoleIds) && c.agentRoleIds.includes(roleId)) return true; // repli config
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
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return ((await r.json()) as { text: string }).text;
}

export default defineHook(({ filter }, { logger }) => {
  // -------- LECTURE : anonymisation pour les rôles agents --------
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
          // fail-closed : si l'engine est indisponible, on NE laisse PAS fuir le clair.
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
  filter('items.update', rehydrate);

  logger.info('[pii-protect] hook chargé');
});
