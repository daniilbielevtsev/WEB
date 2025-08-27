// server.js
import express from "express";
import cors from "cors";
import { Database } from "sqlite-async";
import rateLimit from "express-rate-limit";

const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ORIGIN || "*"; // при деплое лучше указать конкретный домен
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "change-me";

const app = express();
app.use(cors({ origin: ORIGIN }));
app.use(express.json({ limit: "32kb" }));

// Анти-спам: 10 запросов/мин с одного IP на POST
const postLimiter = rateLimit({ windowMs: 60_000, max: 10 });

function esc(s = "") {
  return s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        c
      ])
  );
}

// Инициализация БД
let db;
(async () => {
  db = await Database.open("comments.db");
  await db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post TEXT NOT NULL,
    name TEXT NOT NULL,
    website TEXT,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip TEXT,
    user_agent TEXT,
    approved INTEGER NOT NULL DEFAULT 1
  )`);
})();

// Получить комментарии (только approved)
app.get("/api/comments", async (req, res) => {
  try {
    const post = String(req.query.post || "/");
    const page = Math.max(1, parseInt(String(req.query.page || "1"), 10));
    const limit = Math.min(
      50,
      Math.max(1, parseInt(String(req.query.limit || "10"), 10))
    );
    const offset = (page - 1) * limit;

    const total = (
      await db.get(
        `SELECT COUNT(*) as c FROM comments WHERE post=? AND approved=1`,
        [post]
      )
    ).c;

    const rows = await db.all(
      `SELECT id, post, name, website, message, created_at FROM comments
       WHERE post=? AND approved=1 ORDER BY id DESC LIMIT ? OFFSET ?`,
      [post, limit, offset]
    );

    res.json({ items: rows, total, page, limit });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Создать комментарий
app.post("/api/comments", postLimiter, async (req, res) => {
  try {
    const { post, name, website, message, hp } = req.body || {};

    // honeypot
    if (hp) return res.status(400).json({ error: "Bot detected" });

    const nm = String(name || "").trim();
    const msg = String(message || "").trim();
    const web = String(website || "").trim() || null;
    const pst = String(post || "/").slice(0, 256);

    if (!nm || !msg)
      return res.status(400).json({ error: "name and message are required" });
    if (nm.length > 60) return res.status(400).json({ error: "name too long" });
    if (msg.length > 3000)
      return res.status(400).json({ error: "message too long" });
    if (web && !/^https?:\/\//i.test(web))
      return res.status(400).json({ error: "website must be http(s)" });

    const ip =
      req.headers["x-forwarded-for"]?.toString().split(",")[0] ||
      req.socket.remoteAddress ||
      "";
    const ua = String(req.headers["user-agent"] || "");

    // По умолчанию комментарии одобряются сразу, если нужна модерация → MODERATION_ENABLED=1
    const approved = Number(process.env.MODERATION_ENABLED ? 0 : 1);

    await db.run(
      `INSERT INTO comments (post, name, website, message, ip, user_agent, approved)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [pst, esc(nm), web, esc(msg), ip, ua, approved]
    );

    res.status(201).json({ ok: true, approved: !!approved });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Модерация: список всех (требует токен)
app.get("/api/admin/comments", async (req, res) => {
  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${ADMIN_TOKEN}`)
    return res.status(401).json({ error: "unauthorized" });

  const rows = await db.all(
    `SELECT * FROM comments ORDER BY id DESC LIMIT 500`
  );
  res.json({ items: rows });
});

// Модерация: approve
app.post("/api/admin/approve", async (req, res) => {
  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${ADMIN_TOKEN}`)
    return res.status(401).json({ error: "unauthorized" });

  const { id } = req.body || {};
  await db.run(`UPDATE comments SET approved=1 WHERE id=?`, [id]);
  res.json({ ok: true });
});

// Модерация: delete
app.post("/api/admin/delete", async (req, res) => {
  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${ADMIN_TOKEN}`)
    return res.status(401).json({ error: "unauthorized" });

  const { id } = req.body || {};
  await db.run(`DELETE FROM comments WHERE id=?`, [id]);
  res.json({ ok: true });
});

app.listen(PORT, () =>
  console.log(`API listening on http://localhost:${PORT}`)
);
