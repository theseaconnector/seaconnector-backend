require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ===============================
// Conexión a PostgreSQL (Render)
// ===============================
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Forzar schema correcto
pool.query("SET search_path TO public")
  .then(() => console.log("Schema fijado a public"))
  .catch(console.error);

// Debug REAL (puedes borrarlo luego)
pool.query(`
  SELECT current_database() AS db,
         current_schema()   AS schema,
         current_user       AS user
`).then(r => console.log("DB INFO:", r.rows))
 .catch(console.error);

// Test de conexión
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "PostgreSQL conectado correctamente",
      time: result.rows[0].now,
    });
  } catch (error) {
    console.error("Error de conexión:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===============================
// Registro
// ===============================
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      `SELECT * FROM public.users`
    );
    await pool.query(
      `INSERT INTO public/users (name, email, password_hash)
       VALUES ($1, $2, $3)`,
      [name, email, hashedPassword]
    );

    res.json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en /api/register:", error);
    if (error.code === "23505") {
      return res.status(400).json({ error: "El email ya existe" });
    }
    res.status(500).json({ error: error.message });
  }
});

// ===============================
// Login
// ===============================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await pool.query(
      `SELECT * FROM public.users WHERE email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login correcto",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("ERROR LOGIN REAL:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===============================
// Middleware JWT
// ===============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token requerido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
}

// Perfil
app.get("/api/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Acceso autorizado",
    user: req.user,
  });
});

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
