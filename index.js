require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// ======================
// Middlewares
// ======================
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ======================
// PostgreSQL connection
// ======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on("connect", (client) => {
  client.query("SET search_path TO public");
});

// Debug conexión DB
pool.query(`
  SELECT current_database() AS db,
         current_schema()   AS schema,
         current_user       AS user
`)
.then(r => console.log("DB INFO:", r.rows))
.catch(err => console.error("DB ERROR:", err));

// ======================
// Test endpoint
// ======================
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "PostgreSQL conectado correctamente - SeaConnector Backend",
      time: result.rows[0].now,
      dbInfo: "Tablas: users, reservations, experiences listas"
    });
  } catch (error) {
    console.error("Error de conexión:", error);
    res.status(500).json({ error: error.message });
  }
});

// ======================
// Register
// ======================
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan name, email o password" });
    }

    const existingUser = await pool.query(
      "SELECT id FROM public.users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO public.users (name, email, password_hash)
       VALUES ($1, $2, $3)`,
      [name, email, hashedPassword]
    );

    res.status(201).json({
      message: "Usuario registrado correctamente",
      user: { name, email }
    });

  } catch (error) {
    console.error("Error en /api/register:", error);
    res.status(500).json({ error: error.message });
  }
});

// ======================
// Login
// ======================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Faltan email o password" });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role
       FROM public.users
       WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login exitoso",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error("Error en /api/login:", error);
    res.status(500).json({ error: error.message });
  }
});

// ======================
// Start server
// ======================
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
