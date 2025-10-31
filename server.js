const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { Pool } = require("pg");

// ----- CONFIG -----
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_prod";
const PG_CONFIG = {
  // change according to your local Postgres setup
  user: process.env.PGUSER || "postgres",
  host: process.env.PGHOST || "localhost",
  database: process.env.PGDATABASE || "product_dashboard",
  password: process.env.PGPASSWORD || "Sarthak@2002", // change
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
};
// External GraphQL API (public)
const EXTERNAL_GRAPHQL = "https://graphqlzero.almansi.me/api";

const pool = new Pool(PG_CONFIG);

// ----- INIT DB (auto-create users table) -----
(async function initDb() {
  const createTableSQL = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `;
  try {
    await pool.query(createTableSQL);
    console.log("✅ users table ensured");
  } catch (err) {
    console.error("DB init error:", err);
  }
})();

// ----- APP SETUP -----
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ----- HELPERS -----
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

async function getUserByEmail(email) {
  const r = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  return r.rows[0];
}

async function createUser(email, hashedPassword) {
  const r = await pool.query(
    "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email, created_at",
    [email, hashedPassword]
  );
  return r.rows[0];
}

// ----- AUTH ROUTES -----

// Signup: create new user
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "email & password required" });

    const existing = await getUserByEmail(email);
    if (existing) return res.status(400).json({ error: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await createUser(email, hashed);
    return res.json({ success: true, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error("signup error:", err);
    res.status(500).json({ error: "server error during signup" });
  }
});

// Login: verify and return token
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "email & password required" });

    const user = await getUserByEmail(email);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = generateToken({ id: user.id, email: user.email });
    return res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "server error during login" });
  }
});

// ----- MIDDLEWARE: Authenticate JWT -----
function authenticateMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Authorization header required" });

  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ error: "Invalid Authorization format" });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

// ----- PROXY GraphQL (protected) -----
// The frontend sends GraphQL body to /api/graphql, backend checks token then forwards to EXTERNAL_GRAPHQL
app.post("/api/graphql", authenticateMiddleware, async (req, res) => {
  try {
    const body = req.body; // should contain { query, variables? }
    const r = await axios.post(EXTERNAL_GRAPHQL, body, {
      headers: { "Content-Type": "application/json" },
    });
    return res.json(r.data);
  } catch (err) {
    console.error("graphql proxy error:", err?.response?.data || err.message);
    res.status(500).json({ error: "failed to fetch external graphql" });
  }
});

// Optional: simple route to fetch products via GraphQL wrapper for convenience
app.get("/api/products", authenticateMiddleware, async (req, res) => {
  // Query photos (we will map these to products client-side)
  const query = `
    query {
      photos(options: { paginate: { page: 1, limit: 50 } }) {
        data { id title url thumbnailUrl }
      }
    }
  `;
  try {
    const r = await axios.post(EXTERNAL_GRAPHQL, { query }, { headers: { "Content-Type": "application/json" } });
    res.json(r.data);
  } catch (err) {
    console.error("products fetch error:", err?.response?.data || err.message);
    res.status(500).json({ error: "failed to fetch products" });
  }
});

// Health
app.get("/", (req, res) => res.send("Auth+GraphQL proxy server is up"));

// ----- START -----
app.listen(PORT, () => {
  console.log(`🚀 Backend listening on http://localhost:${PORT}`);
  console.log(`→ POST /api/auth/signup  (body: { email, password })`);
  console.log(`→ POST /api/auth/login   (body: { email, password })`);
  console.log(`→ POST /api/graphql      (protected, forwards to ${EXTERNAL_GRAPHQL})`);
});
