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
/* FIXED: Conexión simplificada usando DATABASE_URL (mejor práctica) */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===============================
/* FIXED: Establecer schema en cada conexión nueva */
pool.on('connect', (client) => {
  client.query('SET search_path TO public');
});

// Debug conexión
pool.query(`
  SELECT current_database() AS db,
         current_schema()   AS schema,
         current_user       AS user
`).then(r => console.log("DB INFO:", r.rows))
 .catch(console.error);

// Test conexión
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "🟢 PostgreSQL conectado correctamente - SeaConnector Backend",
      time: result.rows[0].now,
      dbInfo: "Tablas: users, reservations, experiences listas"
    });
  } catch (error) {
    console.error("❌ Error de conexión:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===============================
/* FIXED: Registro - Verificar existencia + manejo mejorado de errores */
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan name, email o password" });
    }

    // Verificar si ya existe
    const existingUser = await pool.query(
      'SELECT id FROM public.users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO public.users (name, email, password_hash)
       VALUES ($1, $2, $3) RETURNING id, name, email`,
      [name, email, hashedPassword]
    );

    res.status(201).json({ 
      message: "✅ Usuario registrado correctamente",
      user: { name, email }
    });
  } catch (error) {
    console.error("❌ Error en /api/register:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===============================
/* FIXED: Login - Consulta corregida + validaciones mejoradas */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Faltan email o password" });
    }

    console.log("🔍 Buscando usuario:", email);

    // FIXED: Consulta corregida con campos específicos
    const result = await pool.query(
      `SELECT id, name, email, password_hash, role 
       FROM public.users 
       WHERE email = $1`,
      [email]
    );

    console.log("📊 Resultados encontrados:", result.rows.length);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role || 'user' },
      process.env.JWT_SECRET || 'tu_secreto_super_seguro_aqui',
      { expiresIn: "24h" }
    );

    console.log("✅ Login exitoso para:", user.email);

    res.json({
      message: "🎉 Login correcto",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user'
      }
    });
  } catch (error) {
    console.error("❌ ERROR LOGIN:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===============================
/* Middleware JWT mejorado */
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'tu_secreto_super_seguro_aqui', (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado" });
    }
    req.user = user;
    next();
  });
}

// Perfil protegido
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const userData = await pool.query(
      `SELECT id, name, email, role FROM public.users WHERE id = $1`,
      [req.user.id]
    );
    
    res.json({
      message: "✅ Perfil accesible",
      user: userData.rows[0]
    });
  } catch (error) {
    console.error("❌ Error perfil:", error);
    res.status(500).json({ error: error.message });
  }
});

// Manejo de errores 404
app.use("*", (req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor SeaConnector escuchando en http://localhost:${PORT}`);
  console.log(`📡 Login: POST /api/login`);
  console.log(`👤 Perfil: GET /api/profile`);
});
