require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Conexión a PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// Ruta test
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "PostgreSQL conectado correctamente 🚀",
      time: result.rows[0].now,
    });
  } catch (error) {
    res.status(500).json({ error: "Error de conexión a PostgreSQL" });
  }
});

// Registro de usuarios
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO public.users (name, email, password_hash) VALUES ($1, $2, $3)",
      [name, email, hashedPassword]
    );

    res.json({ message: "Usuario registrado correctamente ✅" });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({ error: "El email ya existe" });
    }

    console.error(error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

// Login de usuarios
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Faltan datos" });
    }

    const result = await pool.query(
      "SELECT * FROM public.users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login correcto ✅",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error del servidor" });
  }
});

// Middleware JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido" });
    }

    req.user = user;
    next();
  });
}

// Perfil (zona privada)
app.get("/api/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Acceso autorizado 🔐",
    user: req.user,
  });
});

// 🔐 CREAR RESERVA (USUARIO LOGUEADO)
app.post("/api/reservations", authenticateToken, async (req, res) => {
  try {
    const { experience_id, reservation_date } = req.body;

    if (!experience_id || !reservation_date) {
      return res.status(400).json({ error: "Faltan datos de reserva" });
    }

    await pool.query(
      `INSERT INTO reservations (user_id, experience_id, reservation_date, status)
       VALUES ($1, $2, $3, 'pending')`,
      [req.user.id, experience_id, reservation_date]
    );

    res.json({ message: "Reserva creada correctamente ✅" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al crear la reserva" });
  }
});

// Servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
