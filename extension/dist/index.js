import { Readable } from "node:stream";
import { randomUUID } from "node:crypto";
const ENGINE = process.env.PII_PROTECT_ENGINE_URL || "http://host.docker.internal:8077";
const ENGINE_TOKEN = process.env.PII_PROTECT_ENGINE_TOKEN;
const SELF = "http://127.0.0.1:" + (process.env.PORT || "8055");
const BYPASS = randomUUID();
const FILE_ROUTE = {
  txt: "/anonymize-doc",
  md: "/anonymize-doc",
  csv: "/anonymize-doc",
  json: "/anonymize-doc",
  docx: "/anonymize-doc",
  png: "/redact-image",
  jpg: "/redact-image",
  jpeg: "/redact-image",
  gif: "/redact-image",
  bmp: "/redact-image",
  tiff: "/redact-image",
  tif: "/redact-image",
  webp: "/redact-image",
  pdf: "/redact-pdf"
};
const FILE_META = ["filename_download", "title", "description"];
let FIELDS_MAP = null;
const _pf = process.env.PII_PROTECT_FIELDS;
if (_pf && _pf !== "*") {
  try {
    FIELDS_MAP = JSON.parse(_pf);
  } catch {
  }
}
const ext = (name) => name.toLowerCase().split(".").pop() || "";
function textFields(schema, collection) {
  if (FIELDS_MAP) return FIELDS_MAP[collection] || [];
  const fields = schema?.collections?.[collection]?.fields || {};
  return Object.values(fields).filter((f) => f?.type === "text").map((f) => f.field);
}
function toList(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v;
  try {
    const j = JSON.parse(v);
    if (Array.isArray(j)) return j;
  } catch {
  }
  return String(v).split(",").map((s) => s.trim()).filter(Boolean);
}
const roleCache = /* @__PURE__ */ new Map();
async function roleConfig(database, roleId) {
  if (!roleId) return { all: false, cols: /* @__PURE__ */ new Set(), at: 0 };
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 3e3) return hit;
  let all = false, cols = /* @__PURE__ */ new Set();
  try {
    const row = await database("directus_roles").select("pii_encrypt_all", "pii_encrypt_collections").where({ id: roleId }).first();
    all = !!row?.pii_encrypt_all;
    cols = new Set(toList(row?.pii_encrypt_collections));
  } catch {
  }
  const cfg = { all, cols, at: Date.now() };
  roleCache.set(roleId, cfg);
  return cfg;
}
const anonymizes = (cfg, collection) => cfg.all || cfg.cols.has(collection);
const anonymizesFiles = (cfg) => cfg.all || cfg.cols.has("directus_files");
async function post(path, payload) {
  const headers = { "content-type": "application/json" };
  if (ENGINE_TOKEN) headers["x-engine-token"] = ENGINE_TOKEN;
  const r = await fetch(ENGINE + path, { method: "POST", headers, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error("engine HTTP " + r.status);
  return r.json();
}
const callText = async (path, text) => (await post(path, { text })).text;
const callFile = async (path, filename, buf) => Buffer.from((await post(path, { filename, content_b64: buf.toString("base64") })).content_b64, "base64");
async function bufferStream(stream) {
  const chunks = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}
var index_default = ({ filter, init, action }, { logger, database, services, getSchema }) => {
  init("app.after", async () => {
    try {
      const schema = await getSchema();
      const fieldsSvc = new services.FieldsService({ schema, accountability: { admin: true, role: null } });
      const have = new Set((await fieldsSvc.readAll("directus_roles")).map((f) => f.field));
      const choices = Object.keys(schema.collections || {}).filter((c) => c === "directus_files" || !c.startsWith("directus_")).sort().map((c) => ({ text: c, value: c }));
      if (!have.has("pii_encrypt_all")) {
        await fieldsSvc.createField("directus_roles", {
          field: "pii_encrypt_all",
          type: "boolean",
          meta: {
            interface: "boolean",
            special: ["cast-boolean"],
            width: "full",
            options: { label: "Encrypt all collections for this role" },
            note: "Shortcut: anonymize PII everywhere. Turn OFF to pick collections below."
          },
          schema: { default_value: false }
        });
      }
      const colMeta = {
        interface: "select-multiple-checkbox",
        special: ["cast-json"],
        width: "full",
        options: { choices },
        note: "Collections to anonymize for this role.",
        conditions: [{ name: "Hidden when encrypt-all is on", rule: { pii_encrypt_all: { _eq: true } }, hidden: true }]
      };
      if (!have.has("pii_encrypt_collections"))
        await fieldsSvc.createField("directus_roles", { field: "pii_encrypt_collections", type: "json", meta: colMeta });
      else
        await fieldsSvc.updateField("directus_roles", { field: "pii_encrypt_collections", meta: colMeta });
      logger.info("[pii-protect] role config fields ready");
    } catch (e) {
      logger.warn("[pii-protect] role config setup skipped: " + e.message);
    }
  });
  const encryptItemFields = async (schema, collection, item) => {
    if (collection === "directus_files") {
      for (const f of FILE_META) if (typeof item[f] === "string" && item[f]) {
        try {
          item[f] = await callText("/encrypt", item[f]);
        } catch {
          item[f] = "[protected]";
        }
      }
    } else {
      for (const f of textFields(schema, collection)) if (typeof item[f] === "string" && item[f]) {
        try {
          item[f] = await callText("/anonymize", item[f]);
        } catch (e) {
          logger.warn("[pii-protect] anonymize: " + e.message);
          item[f] = "[protected \u2014 unavailable]";
        }
      }
    }
  };
  const anonItem = async (cfg, schema, collection, item, depth) => {
    if (!item || typeof item !== "object" || depth > 6) return;
    if (anonymizes(cfg, collection)) await encryptItemFields(schema, collection, item);
    for (const rel of schema?.relations || []) {
      if (rel.collection === collection && rel.related_collection && rel.field in item) {
        const v = item[rel.field];
        if (Array.isArray(v)) {
          for (const x of v) await anonItem(cfg, schema, rel.related_collection, x, depth + 1);
        } else if (v && typeof v === "object") await anonItem(cfg, schema, rel.related_collection, v, depth + 1);
      }
      const of = rel.meta?.one_field;
      if (rel.related_collection === collection && of && of in item) {
        const v = item[of];
        if (Array.isArray(v)) {
          for (const x of v) await anonItem(cfg, schema, rel.collection, x, depth + 1);
        } else if (v && typeof v === "object") await anonItem(cfg, schema, rel.collection, v, depth + 1);
      }
    }
  };
  filter("items.read", async (payload, meta, ctx) => {
    if (!payload) return payload;
    const cfg = await roleConfig(ctx?.database, ctx?.accountability?.role);
    const items = Array.isArray(payload) ? payload : [payload];
    for (const it of items) await anonItem(cfg, ctx?.schema, meta.collection, it, 0);
    return payload;
  });
  const rehydrate = async (payload, meta, ctx) => {
    if (!payload) return payload;
    const cfg = await roleConfig(ctx?.database, ctx?.accountability?.role);
    if (!anonymizes(cfg, meta.collection)) return payload;
    for (const f of textFields(ctx?.schema, meta.collection)) {
      if (typeof payload[f] === "string" && payload[f].includes("[[PII:")) {
        try {
          payload[f] = await callText("/rehydrate", payload[f]);
        } catch (e) {
          logger.warn("[pii-protect] rehydrate: " + e.message);
        }
      }
    }
    return payload;
  };
  filter("items.create", rehydrate);
  filter("items.update", rehydrate);
  init("routes.before", ({ app }) => {
    const guard = (deny, handle) => async (req, res, next) => {
      if (req.headers["x-pii-bypass"] === BYPASS) return next();
      let on = false;
      try {
        on = anonymizesFiles(await roleConfig(database, req.accountability?.role));
      } catch {
      }
      if (!on) return next();
      try {
        const orig = await fetch(SELF + req.originalUrl, {
          headers: { authorization: req.headers.authorization || "", cookie: req.headers.cookie || "", "x-pii-bypass": BYPASS }
        });
        if (!orig.ok) return deny(res, orig.status > 200 ? orig.status : 502);
        await handle(orig, req, res);
      } catch (e) {
        logger.warn("[pii-protect] " + req.path + " (fail-closed): " + e.message);
        deny(res, 503);
      }
    };
    const denyJson = (res, code) => res.status(code).json({ errors: [{ message: "protected" }] });
    app.get(["/files", "/files/:pk"], guard(denyJson, async (orig, _req, res) => {
      const json = await orig.json();
      const rows = Array.isArray(json?.data) ? json.data : [json?.data];
      for (const row of rows) for (const f of row ? FILE_META : []) {
        if (typeof row[f] === "string" && row[f]) row[f] = await callText("/encrypt", row[f]);
      }
      res.setHeader("cache-control", "no-store");
      res.json(json);
    }));
    app.get("/assets/:pk", async (req, res, next) => {
      let on = false;
      try {
        on = anonymizesFiles(await roleConfig(database, req.accountability?.role));
      } catch {
      }
      if (!on) return next();
      try {
        const assets = new services.AssetsService({ schema: await getSchema(), accountability: req.accountability });
        const { stream, file } = await assets.getAsset(req.params.pk, {});
        const name = file?.filename_download || String(req.params.pk);
        const endpoint = FILE_ROUTE[ext(name)];
        if (!endpoint) return res.status(415).send("[protected \u2014 unsupported file type]");
        const out = await callFile(endpoint, name, await bufferStream(stream));
        res.setHeader("content-type", file?.type || "application/octet-stream");
        res.setHeader("cache-control", "no-store");
        res.setHeader("content-disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(await callText("/encrypt", name)));
        res.send(out);
      } catch (e) {
        logger.warn("[pii-protect] /assets (fail-closed): " + e.message);
        res.status(503).send("[protected \u2014 unavailable]");
      }
    });
  });
  action("files.upload", async (meta, ctx) => {
    try {
      if (!anonymizesFiles(await roleConfig(database, ctx?.accountability?.role))) return;
      const key = meta?.key || meta?.payload?.id || meta;
      if (typeof key !== "string") return;
      const schema = await getSchema();
      const sys = { admin: true, role: null };
      const files = new services.FilesService({ schema, accountability: sys });
      const file = await files.readOne(key);
      const name = file?.filename_download || file?.filename_disk || "";
      if (FILE_ROUTE[ext(name)] !== "/anonymize-doc") return;
      const asset = await new services.AssetsService({ schema, accountability: sys }).getAsset(key, {});
      const buf = await bufferStream(asset.stream || asset);
      const clear = await callFile("/rehydrate-doc", name, buf);
      if (clear.equals(buf)) return;
      await files.uploadOne(
        Readable.from(clear),
        { type: file.type, filename_download: file.filename_download, storage: file.storage, title: file.title },
        key
      );
      logger.info("[pii-protect] document rehydrated on re-upload (" + name + ")");
    } catch (e) {
      logger.warn("[pii-protect] files.upload: " + e.message);
    }
  });
  logger.info("[pii-protect] loaded (engine " + ENGINE + ")");
};
export {
  index_default as default
};
