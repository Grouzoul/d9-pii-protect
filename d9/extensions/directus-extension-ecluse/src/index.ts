/**
 * directus-extension-ecluse — hook d'anonymisation gouvernée des PII pour agents IA.
 *
 * Pour un utilisateur de rôle « agent » :
 *   - items.read          → anonymise (chiffre) les PII des champs texte libre via l'engine Écluse
 *   - items.create/update → rehydrate les marqueurs [[ECLUSE:...]] avant écriture en base
 *
 * d9 gère le RBAC (qui accède à quoi) ; l'extension gère le CONTENU PII des champs
 * texte libre que le RBAC au champ/ligne ne peut pas voir.
 */
import { defineHook } from '@directus/extensions-sdk';
import { readFileSync } from 'node:fs';

const CONFIG_PATH = '/directus/extensions/ecluse.config.json';

interface EcluseConfig {
  engine: string;
  agentRoleIds: string[];
  fields: Record<string, string[]>;
}

let _cfg: EcluseConfig | null = null;
let _at = 0;
function cfg(): EcluseConfig {
  if (_cfg && Date.now() - _at < 2000) return _cfg;
  try {
    _cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as EcluseConfig;
  } catch {
    _cfg = { engine: 'http://host.docker.internal:8077', agentRoleIds: [], fields: {} };
  }
  _at = Date.now();
  return _cfg;
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
  // -------- LECTURE : anonymisation pour les agents --------
  filter('items.read', async (payload: any, meta: any, ctx: any) => {
    const c = cfg();
    const role = ctx?.accountability?.role;
    if (!role || !c.agentRoleIds.includes(role)) return payload;
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
            logger.warn('[ecluse] anonymize indispo: ' + e.message);
            item[f] = '[protégé — Écluse indisponible]';
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
      if (typeof payload[f] === 'string' && payload[f].includes('[[ECLUSE:')) {
        try {
          payload[f] = await call(c.engine, '/rehydrate', payload[f]);
        } catch (e: any) {
          logger.warn('[ecluse] rehydrate: ' + e.message);
        }
      }
    }
    return payload;
  };
  filter('items.create', rehydrate);
  filter('items.update', rehydrate);

  logger.info('[ecluse] hook chargé');
});
