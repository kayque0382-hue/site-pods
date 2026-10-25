const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PROD = process.env.NODE_ENV === "production";
const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "products.json");
const WHATSAPP = (process.env.WHATSAPP || "").replace(/\D/g, "");
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const CATEGORIES = ["Descartáveis", "Recarregáveis", "Refis"];

/* ---------- credenciais do administrador ---------- */
let ADMIN_HASH = process.env.ADMIN_PASSWORD_HASH;
if (!ADMIN_HASH && process.env.ADMIN_PASSWORD) ADMIN_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
if (!ADMIN_HASH) {
  console.error("Defina ADMIN_PASSWORD (ou ADMIN_PASSWORD_HASH) antes de iniciar o servidor.");
  process.exit(1);
}
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  if (PROD) { console.error("Defina SESSION_SECRET em produção."); process.exit(1); }
  SECRET = crypto.randomBytes(32).toString("hex");
}

/* ---------- armazenamento em arquivo JSON ---------- */
function readProducts() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, "utf8")); } catch (e) { return []; }
}
function writeProducts(list) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
if (!fs.existsSync(DATA_FILE)) {
  const seed = path.join(__dirname, "data", "products.json");
  if (fs.existsSync(seed) && seed !== DATA_FILE) writeProducts(JSON.parse(fs.readFileSync(seed, "utf8")));
  else writeProducts([]);
}

/* ---------- validação ---------- */
function str(v, max) { return typeof v === "string" ? v.trim().slice(0, max) : ""; }
function clean(b) {
  const out = {
    name: str(b.name, 60),
    cat: str(b.cat, 30),
    note: str(b.note, 120),
    puffs: str(b.puffs, 30),
    nic: str(b.nic, 20),
    price: Math.round(Number(b.price) * 100) / 100,
    color: str(b.color, 7),
    tag: str(b.tag, 20),
    available: b.available !== false
  };
  if (out.name.length < 2) return { error: "Informe o nome do produto." };
  if (!CATEGORIES.includes(out.cat)) return { error: "Categoria inválida." };
  if (!Number.isFinite(out.price) || out.price <= 0 || out.price > 99999) return { error: "Informe um preço válido." };
  if (!/^#[0-9a-f]{6}$/i.test(out.color)) return { error: "Cor inválida." };
  return { value: out };
}

/* ---------- app ---------- */
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'");
  next();
});

app.use(express.json({ limit: "20kb" }));
app.use(session({
  name: "sid",
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: PROD, maxAge: 8 * 60 * 60 * 1000 }
}));

/* Bloqueia requisições de escrita vindas de outro site */
app.use((req, res, next) => {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    const origin = req.get("origin");
    if (origin) {
      let host = "";
      try { host = new URL(origin).host; } catch (e) {}
      if (host !== req.get("host")) return res.status(403).json({ error: "Origem não permitida." });
    }
    if (!req.is("application/json")) return res.status(415).json({ error: "Conteúdo inválido." });
  }
  next();
});

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin === true) return next();
  res.status(401).json({ error: "Faça login para continuar." });
}

/* ---------- limite de tentativas de login ---------- */
const attempts = new Map();
const MAX_TRIES = 5, LOCK_MS = 15 * 60 * 1000;
function locked(ip) {
  const a = attempts.get(ip);
  return a && a.count >= MAX_TRIES && Date.now() - a.last < LOCK_MS;
}
function fail(ip) {
  const a = attempts.get(ip);
  if (!a || Date.now() - a.last >= LOCK_MS) attempts.set(ip, { count: 1, last: Date.now() });
  else { a.count++; a.last = Date.now(); }
}
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/* ---------- rotas públicas ---------- */
app.get("/api/config", (req, res) => res.json({ whatsapp: WHATSAPP }));
app.get("/api/products", (req, res) => res.json(readProducts()));

/* ---------- área do administrador ---------- */
app.get("/admin", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const page = req.session && req.session.admin ? "admin.html" : "login.html";
  res.sendFile(path.join(__dirname, "views", page));
});

app.post("/admin/login", async (req, res) => {
  const ip = req.ip;
  if (locked(ip)) return res.status(429).json({ error: "Muitas tentativas. Tente de novo em 15 minutos." });
  const user = str(req.body.user, 80);
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const okUser = safeEqual(user, ADMIN_USER);
  const okPass = await bcrypt.compare(password, ADMIN_HASH);
  if (!(okUser && okPass)) { fail(ip); return res.status(401).json({ error: "Usuário ou senha incorretos." }); }
  attempts.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Erro ao entrar." });
    req.session.admin = true;
    res.json({ ok: true });
  });
});

app.post("/admin/logout", (req, res) => {
  req.session.destroy(() => { res.clearCookie("sid"); res.json({ ok: true }); });
});

app.get("/api/admin/categories", requireAdmin, (req, res) => res.json(CATEGORIES));

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const r = clean(req.body || {});
  if (r.error) return res.status(400).json({ error: r.error });
  const list = readProducts();
  const item = Object.assign({ id: crypto.randomUUID() }, r.value);
  list.push(item);
  writeProducts(list);
  res.status(201).json(item);
});

app.put("/api/admin/products/:id", requireAdmin, (req, res) => {
  const r = clean(req.body || {});
  if (r.error) return res.status(400).json({ error: r.error });
  const list = readProducts();
  const i = list.findIndex(p => String(p.id) === req.params.id);
  if (i < 0) return res.status(404).json({ error: "Produto não encontrado." });
  list[i] = Object.assign({ id: list[i].id }, r.value);
  writeProducts(list);
  res.json(list[i]);
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const list = readProducts();
  const next = list.filter(p => String(p.id) !== req.params.id);
  if (next.length === list.length) return res.status(404).json({ error: "Produto não encontrado." });
  writeProducts(next);
  res.json({ ok: true });
});

/* ---------- arquivos públicos ---------- */
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));
app.use((req, res) => res.status(404).send("Página não encontrada."));

app.listen(PORT, () => console.log("Névoa Pods no ar na porta " + PORT));
