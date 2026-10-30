import { Readable } from "node:stream";
const ENGINE = process.env.PII_PROTECT_ENGINE_URL || "http://host.docker.internal:8077";
const SELF = "http://127.0.0.1:" + (process.env.PORT || "8055");
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
const roleCache = /* @__PURE__ */ new Map();
async function isAgent(database, roleId) {
  if (!roleId) return false;
  const hit = roleCache.get(roleId);
  if (hit && Date.now() - hit.at < 1e4) return hit.v;
  let v = false;
  try {
    v = !!(await database("directus_roles").select("is_agent").where({ id: roleId }).first())?.is_agent;
  } catch {
  }
  roleCache.set(roleId, { v, at: Date.now() });
  return v;
}
async function post(path, payload) {
  const r = await fetch(ENGINE + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
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
  filter("items.read", async (payload, meta, ctx) => {
    if (!Array.isArray(payload) || !await isAgent(ctx?.database, ctx?.accountability?.role)) return payload;
    const fields = textFields(ctx?.schema, meta.collection);
    for (const item of payload) for (const f of fields) {
      if (typeof item?.[f] === "string" && item[f]) {
        try {
          item[f] = await callText("/anonymize", item[f]);
        } catch (e) {
          logger.warn("[pii-protect] anonymize: " + e.message);
          item[f] = "[prot\xE9g\xE9 \u2014 indisponible]";
        }
      }
    }
    return payload;
  });
  const rehydrate = async (payload, meta, ctx) => {
    for (const f of payload ? textFields(ctx?.schema, meta.collection) : []) {
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
      if (req.query.ecluse_bypass || req.headers["x-ecluse-bypass"]) return next();
      let agent = false;
      try {
        agent = await isAgent(database, req.accountability?.role);
      } catch {
      }
      if (!agent) return next();
      try {
        const sep = req.originalUrl.includes("?") ? "&" : "?";
        const orig = await fetch(SELF + req.originalUrl + sep + "ecluse_bypass=1", {
          headers: { authorization: req.headers.authorization || "", cookie: req.headers.cookie || "" }
        });
        if (!orig.ok) return deny(res, orig.status > 200 ? orig.status : 502);
        await handle(orig, req, res);
      } catch (e) {
        logger.warn("[pii-protect] " + req.path + " (fail-closed): " + e.message);
        deny(res, 503);
      }
    };
    const denyText = (res, code) => res.status(code).send("[prot\xE9g\xE9]");
    const denyJson = (res, code) => res.status(code).json({ errors: [{ message: "prot\xE9g\xE9" }] });
    app.get(["/files", "/files/:pk"], guard(denyJson, async (orig, _req, res) => {
      const json = await orig.json();
      const rows = Array.isArray(json?.data) ? json.data : [json?.data];
      for (const row of rows) for (const f of row ? FILE_META : []) {
        if (typeof row[f] === "string" && row[f]) row[f] = await callText("/encrypt", row[f]);
      }
      res.json(json);
    }));
    app.get("/assets/:pk", guard(denyText, async (orig, req, res) => {
      const cdisp = orig.headers.get("content-disposition") || "";
      const name = decodeURIComponent(/filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cdisp)?.[1] || String(req.params.pk));
      const endpoint = FILE_ROUTE[ext(name)];
      if (!endpoint) return res.status(415).send("[prot\xE9g\xE9 \u2014 type non pris en charge]");
      const out = await callFile(endpoint, name, Buffer.from(await orig.arrayBuffer()));
      res.setHeader("content-type", orig.headers.get("content-type") || "application/octet-stream");
      if (cdisp) res.setHeader("content-disposition", cdisp);
      res.send(out);
    }));
  });
  action("files.upload", async (meta, ctx) => {
    try {
      if (!await isAgent(database, ctx?.accountability?.role)) return;
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
      logger.info("[pii-protect] document rehydrat\xE9 au r\xE9-upload (" + name + ")");
    } catch (e) {
      logger.warn("[pii-protect] files.upload: " + e.message);
    }
  });
  logger.info("[pii-protect] charg\xE9 (moteur " + ENGINE + ")");
};
export {
  index_default as default
};
