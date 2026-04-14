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
// Crear tablas afiliados
// ======================
pool.query(`
  CREATE TABLE IF NOT EXISTS public.affiliates (
    id SERIAL PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    phone VARCHAR(20),
    type VARCHAR(20) DEFAULT 'persona',
    commission_rate DECIMAL(5,2) DEFAULT 5.00,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS public.affiliate_clicks (
    id SERIAL PRIMARY KEY,
    affiliate_code VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS public.affiliate_referrals (
    id SERIAL PRIMARY KEY,
    affiliate_code VARCHAR(20) NOT NULL,
    amount DECIMAL(10,2),
    commission DECIMAL(10,2),
    status VARCHAR(20) DEFAULT 'pendiente',
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`).then(() => console.log("Tablas afiliados creadas"))
  .catch(err => console.error("Error creando tablas afiliados:", err));

// ======================
// Registrar click afiliado
// ======================
app.post("/api/affiliate/click", async (req, res) => {
  try {
    const { code } = req.body;
    if(!code) return res.status(400).json({ error: "Falta el código" });
    const affiliate = await pool.query(
      "SELECT id FROM public.affiliates WHERE code = $1 AND active = true",
      [code]
    );
    if(affiliate.rows.length === 0){
      return res.status(404).json({ error: "Código no encontrado" });
    }
    await pool.query(
      "INSERT INTO public.affiliate_clicks (affiliate_code, ip_address) VALUES ($1, $2)",
      [code, req.ip]
    );
    res.json({ message: "Click registrado", code });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================
// Crear afiliado
// ======================
app.post("/api/affiliate/create", async (req, res) => {
  try {
    const { code, name, email, phone, type, commission_rate } = req.body;
    if(!code || !name) return res.status(400).json({ error: "Faltan code y name" });
    await pool.query(
      `INSERT INTO public.affiliates (code, name, email, phone, type, commission_rate)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [code, name, email, phone, type||'persona', commission_rate||5.00]
    );
    res.status(201).json({ message: "Afiliado creado", code });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================
// Registrar referido
// ======================
app.post("/api/affiliate/referral", async (req, res) => {
  try {
    const { affiliate_code, amount, commission, notes } = req.body;
    if(!affiliate_code || !amount) return res.status(400).json({ error: "Faltan datos" });
    await pool.query(
      `INSERT INTO public.affiliate_referrals (affiliate_code, amount, commission, notes)
       VALUES ($1, $2, $3, $4)`,
      [affiliate_code, amount, commission, notes]
    );
    res.status(201).json({ message: "Referido registrado" });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================
// Stats afiliado
// ======================
app.get("/api/affiliate/stats/:code", async (req, res) => {
  try {
    const { code } = req.params;
    const affiliate = await pool.query(
      "SELECT * FROM public.affiliates WHERE code = $1",
      [code]
    );
    if(affiliate.rows.length === 0){
      return res.status(404).json({ error: "Afiliado no encontrado" });
    }
    const clicks = await pool.query(
      "SELECT COUNT(*) FROM public.affiliate_clicks WHERE affiliate_code = $1",
      [code]
    );
    const referrals = await pool.query(
      "SELECT COUNT(*), SUM(amount), SUM(commission) FROM public.affiliate_referrals WHERE affiliate_code = $1",
      [code]
    );
    res.json({
      affiliate: affiliate.rows[0],
      clicks: parseInt(clicks.rows[0].count),
      referrals: parseInt(referrals.rows[0].count),
      total_amount: parseFloat(referrals.rows[0].sum)||0,
      total_commission: parseFloat(referrals.rows[0].sum_1)||0
    });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ======================
// Start server
// ======================
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
