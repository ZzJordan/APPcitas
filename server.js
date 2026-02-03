require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const { pool, initDb } = require('./db');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const crypto = require('crypto');
const QRCode = require('qrcode');
const webpush = require('web-push');
const rateLimit = require('express-rate-limit');

// Security: Rate Limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 login/register requests per windowMs
  message: { error: "Demasiados intentos, por favor intenta de nuevo en 15 minutos." },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200, // Limit API requests
  standardHeaders: true,
  legacyHeaders: false,
});

// SendGrid Configuration
const sgMail = require('@sendgrid/mail');
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
} else {
  console.warn("⚠️ SENDGRID_API_KEY missing. Email sending will be mocked.");
}

async function sendVerificationEmail(email, token, req) {
  const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;

  if (process.env.SENDGRID_API_KEY) {
    const msg = {
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL || 'noreply@cupidosproject.com',
      subject: 'Verifica tu cuenta - Cupidos Project',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2>Bienvenido a Cupidos Project</h2>
          <p>Por favor verifica tu correo haciendo clic en el siguiente enlace:</p>
          <a href="${verifyUrl}" style="background: #ff4757; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verificar Cuenta</a>
          <p>O copia este enlace: ${verifyUrl}</p>
        </div>
      `
    };
    await sgMail.send(msg);
    console.log(`📨 Verification email sent to ${email}`);
  } else {
    console.log(`📨 MOCK VERIFY EMAIL: ${verifyUrl}`);
  }
}

// Web Push Configuration
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    process.env.WEB_PUSH_CONTACT || 'mailto:admin@cupidosproject.com',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
} else {
  console.warn("⚠️ Web Push VAPID keys not missing. Push notifications will not work.");
}

const app = express();
const server = http.createServer(app);

// Error Handling
process.on('uncaughtException', (err) => {
  console.error('❌ CRITICAL: Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});

server.on('error', (err) => {
  console.error('❌ SERVER ERROR:', err);
});

// Socket.io
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Trust Proxy
app.set('trust proxy', 1);

// Health Check
app.get('/healthz', (req, res) => {
  console.log('💓 Health Check triggered');
  res.status(200).send('OK');
});
app.get('/ping', (req, res) => res.status(200).send('pong'));

// Middleware
app.use(morgan('dev'));
app.use(compression());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:*"],
      connectSrc: ["'self'", "ws:", "wss:", "http:", "https:"],
      scriptSrcAttr: ["'unsafe-inline'"],
    },
  },
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: true
}));

// Session Store (PostgreSQL)
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session' // Use different table name to avoid conflicts if needed, but 'session' is standard
  }),
  secret: process.env.SESSION_SECRET || 'cupidos-project-2026',
  resave: false,
  saveUninitialized: false, // Better for compliance
  rolling: true, // Auto-renew session on access
  name: 'cupido.sid',
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true
  }
}));

// --- Presence Logic ---
const roomStatus = {};
const connectedBlinders = new Map();
const connectedUsers = new Set(); // Global tracking for online users
const offlineMessageQueue = new Map(); // userId -> [pending message objects]

async function updateAndNotifyStatus(room_id, cupido_id) {
  if (!room_id || !cupido_id) return;

  try {
    const res = await pool.query("SELECT active_since FROM rooms WHERE id = $1", [room_id]);
    const row = res.rows[0];
    const currentActiveSince = row ? row.active_since : null;

    // Logic remains same, only DB calls change
    const statusObj = roomStatus[room_id];
    let statusText = 'pendiente';
    const isNowActive = (statusObj && statusObj.A && statusObj.B);

    if (isNowActive) statusText = 'activo';
    else if (statusObj && statusObj.A) statusText = 'A conectado';
    else if (statusObj && statusObj.B) statusText = 'B conectado';
    else if (statusObj) statusText = 'desconectado';

    const now = Date.now();

    // Use BigInt for timestamps if needed or just numbers. Postgres active_since is BIGINT.
    if (isNowActive && !currentActiveSince) {
      await pool.query("UPDATE rooms SET status = $1, active_since = $2 WHERE id = $3", [statusText, now, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: now });
    } else if (!isNowActive && currentActiveSince) {
      const duration = Math.floor((now - Number(currentActiveSince)) / 1000);
      await pool.query(
        "UPDATE rooms SET status = $1, active_since = NULL, total_active_seconds = COALESCE(total_active_seconds, 0) + $2 WHERE id = $3",
        [statusText, duration, room_id]
      );
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: null, added_seconds: duration });
    } else {
      await pool.query("UPDATE rooms SET status = $1 WHERE id = $2", [statusText, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
    }

    io.to(`room_${room_id}`).emit('presence-update', {
      A: !!(statusObj && statusObj.A),
      B: !!(statusObj && statusObj.B)
    });
  } catch (err) {
    console.error("Error updating status:", err);
  }
}

// Auth Middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: "No autenticado" });
  }
  res.redirect('/login');
};

// --- TEMP SEED ROUTE ---
// --- TEMP SEED ROUTE ---
app.get('/api/seed-test-matches', isAuthenticated, async (req, res) => {
  try {
    const c1 = await pool.query("SELECT id FROM cupidos WHERE username = 'cupido1'");
    if (!c1.rows.length) return res.send("cupido1 not found");
    const cupidoId = c1.rows[0].id;

    // Helper to get user info by username suffix
    const getBlinder = async (i) => {
      const u = await pool.query("SELECT id, username FROM cupidos WHERE username = $1", [`blinder${i}`]);
      if (!u.rows.length) return null;
      const p = await pool.query("SELECT full_name FROM blinder_profiles WHERE user_id = $1", [u.rows[0].id]);
      return {
        id: u.rows[0].id,
        name: p.rows[0]?.full_name || u.rows[0].username
      };
    };

    const createdRooms = [];
    const create = async (bA, bB) => {
      const linkA = crypto.randomUUID();
      const linkB = crypto.randomUUID();
      const ins = await pool.query(`
                INSERT INTO rooms (cupido_id, friendA_name, friendB_name, linkA, linkB, user_a_id, user_b_id, status, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'activo', NOW())
                ON CONFLICT (linkA) DO NOTHING
                RETURNING id`,
        [cupidoId, bA.name, bB.name, linkA, linkB, bA.id, bB.id]
      );

      if (ins.rows[0]) {
        await pool.query("INSERT INTO user_rooms (cupido_id, room_id, role) VALUES ($1, $2, 'cupido') ON CONFLICT DO NOTHING", [cupidoId, ins.rows[0].id]);
        createdRooms.push(`${bA.name} ↔ ${bB.name}`);
      }
    };

    // Try creating matches for 1-2, 3-4, 5-6
    for (let i = 1; i <= 5; i += 2) {
      const bA = await getBlinder(i);
      const bB = await getBlinder(i + 1);
      if (bA && bB) {
        await create(bA, bB);
      }
    }

    res.send(`Created test matches: ${createdRooms.join(', ') || 'None (maybe already exist or users missing)'}`);
  } catch (e) {
    console.error(e);
    res.status(500).send(e.toString());
  }
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send("Token inválido");

  try {
    const { rows } = await pool.query("SELECT id FROM cupidos WHERE verification_token = $1", [token]);
    const user = rows[0];
    if (!user) return res.status(400).send("Token inválido o expirado.");

    await pool.query("UPDATE cupidos SET is_verified = TRUE, verification_token = NULL WHERE id = $1", [user.id]);
    res.redirect('/login?verified=true');
  } catch (err) {
    console.error(err);
    res.status(500).send("Error al verificar.");
  }
});
app.get('/dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole === 'blinder') return res.redirect('/blinder-dashboard');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/cupido-dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'cupido') return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'cupido-dashboard.html'));
});

app.get('/blinder-dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'blinder') return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'blinder-dashboard.html'));
});

app.get('/admin-dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'admin') return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/join/blinder/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'join-blinder.html'));
});

app.get('/join/blinder/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const { rows } = await pool.query("SELECT * FROM invite_tokens WHERE token = $1 AND expires_at > NOW()", [token]);
    if (rows.length === 0) return res.status(404).send("Invitación inválida o expirada.");
    res.sendFile(path.join(__dirname, 'public', 'join-blinder.html'));
  } catch (err) {
    res.status(500).send("Error de servidor");
  }
});


// API

// --- Web Push APIs ---

// 1. Get Public Key
app.get('/api/vapid-key', (req, res) => {
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

app.get('/api/admin/stats', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'admin') return res.status(403).json({ error: "No autorizado" });

  let client;
  try {
    client = await pool.connect();

    // Queries separated to avoid 'relation does not exist' if migration didn't run perfectly
    let counts = { cupidos: 0, blinders: 0, total_rooms: 0, active_rooms: 0, total_messages: 0, push_subs: 0 };

    // Helper to safely run count query
    const getCount = async (q, name) => {
      try {
        const res = await client.query(q);
        // Postgres COUNT returns bigint as string, parse it safely
        return parseInt(res.rows[0].c, 10) || 0;
      } catch (e) {
        console.error(`Stats Error (${name}):`, e.message);
        return 0;
      }
    };

    counts.cupidos = await getCount("SELECT COUNT(*) as c FROM cupidos WHERE role = 'cupido'", 'cupidos');
    counts.blinders = await getCount("SELECT COUNT(*) as c FROM cupidos WHERE role = 'blinder'", 'blinders');
    counts.total_rooms = await getCount("SELECT COUNT(*) as c FROM rooms", 'rooms');
    counts.active_rooms = await getCount("SELECT COUNT(*) as c FROM rooms WHERE status = 'activo'", 'active_rooms');
    counts.total_messages = await getCount("SELECT COUNT(*) as c FROM messages", 'messages');
    counts.push_subs = await getCount("SELECT COUNT(*) as c FROM push_subscriptions", 'subs');

    let recentUsers = [];
    try {
      const rUsersRes = await client.query("SELECT username, role, created_at FROM cupidos ORDER BY id DESC LIMIT 5");
      recentUsers = rUsersRes.rows;
    } catch (e) {
      console.error("Stats Error (RecentUsers):", e.message);
    }

    // Calculate DB size (approx for Postgres)
    let dbSize = "N/A";
    try {
      const sizeRes = await client.query("SELECT pg_size_pretty(pg_database_size(current_database())) as size");
      dbSize = sizeRes.rows[0].size;
    } catch (e) { }

    res.json({
      counts: counts,
      recentUsers: recentUsers,
      dbSize,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Stats falló" });
  } finally {
    if (client) client.release();
  }
});

// 2. Subscribe Route
app.post('/api/subscribe', isAuthenticated, async (req, res) => {
  const subscription = req.body;
  const userId = req.session.userId;

  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Invalid subscription' });
  }

  try {
    await pool.query(
      "INSERT INTO push_subscriptions (user_id, endpoint, keys) VALUES ($1, $2, $3) ON CONFLICT (endpoint) DO UPDATE SET user_id = EXCLUDED.user_id, keys = EXCLUDED.keys",
      [userId, subscription.endpoint, JSON.stringify(subscription.keys)]
    );
    res.status(201).json({ message: 'Subscription saved' });
  } catch (err) {
    console.error("Subscription Error:", err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Helper: Send Push to User
async function sendPushToUser(userId, data) {
  if (!process.env.VAPID_PRIVATE_KEY) return;
  try {
    const { rows } = await pool.query("SELECT * FROM push_subscriptions WHERE user_id = $1", [userId]);
    const notifications = rows.map(sub => {
      const pushConfig = {
        endpoint: sub.endpoint,
        keys: typeof sub.keys === 'string' ? JSON.parse(sub.keys) : sub.keys
      };
      return webpush.sendNotification(pushConfig, JSON.stringify(data))
        .catch(err => {
          if (err.statusCode === 410 || err.statusCode === 404) {
            // Expired subscription, cleanup
            pool.query("DELETE FROM push_subscriptions WHERE id = $1", [sub.id]);
          }
        });
    });
    await Promise.all(notifications);
  } catch (err) {
    console.error("Push Error:", err);
  }
}

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query("SELECT * FROM cupidos WHERE username = $1", [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });

    if (!user.is_verified) {
      return res.status(401).json({ error: "Debes verificar tu correo electrónico primero." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.userRole = user.role || 'cupido';
      res.status(200).json({ message: "Login exitoso", role: req.session.userRole });
    } else {
      res.status(401).json({ error: "Contraseña incorrecta" });
    }
  } catch (err) {
    res.status(500).json({ error: "Error en el servidor" });
  }
});


app.post('/api/logout', authLimiter, (req, res) => {
  req.session.destroy();
  res.status(200).json({ message: "Sesión cerrada" });
});

app.get('/api/user', apiLimiter, isAuthenticated, (req, res) => {
  res.json({ username: req.session.username, userId: req.session.userId, role: req.session.userRole });
});

// --- Password Recovery ---
app.post('/api/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email requerido" });

  try {
    const { rows } = await pool.query("SELECT id, username FROM cupidos WHERE email = $1", [email]);
    const user = rows[0];

    // Always return success to prevent email enumeration
    if (!user) {
      // Fake delay to mimic processing time
      await new Promise(resolve => setTimeout(resolve, 200));
      return res.status(200).json({ message: "Si el correo está registrado, recibirás un enlace de recuperación." });
    }

    const token = crypto.randomBytes(20).toString('hex');
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;

    // Update DB with token and expiration (1 hour)
    await pool.query("UPDATE cupidos SET recovery_token = $1, token_expires = NOW() + interval '1 hour' WHERE id = $2", [token, user.id]);

    // Send Email via SendGrid
    if (process.env.SENDGRID_API_KEY) {
      const msg = {
        to: email,
        from: process.env.SENDGRID_FROM_EMAIL || 'noreply@cupidosproject.com',
        subject: 'Restablecer Contraseña - Cupidos Project',
        text: `Hola ${user.username},\n\nPara restablecer tu contraseña, haz clic en el siguiente enlace:\n${resetUrl}\n\nSi no solicitaste esto, ignora este mensaje.\n\nEl enlace expira en 1 hora.`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #333;">Restablecer Contraseña</h2>
            <p>Hola <strong>${user.username}</strong>,</p>
            <p>Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente botón para continuar:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" style="background-color: #ff4757; color: white; padding: 12px 24px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;">Cambiar Contraseña</a>
            </div>
            <p style="color: #666; font-size: 14px;">O copia y pega este enlace en tu navegador:</p>
            <p style="color: #666; font-size: 12px; word-break: break-all;">${resetUrl}</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">Si no solicitaste este cambio, puedes ignorar este correo de forma segura. El enlace expirará en 1 hora.</p>
          </div>
        `,
      };
      await sgMail.send(msg);
      console.log(`📨 SendGrid Email sent to ${email}`);
    } else {
      // Mock for local dev without keys
      console.log(`-----------------------------------------`);
      console.log(`📨 MOCK EMAIL TO: ${email}`);
      console.log(`SUBJECT: Recuperación de contraseña`);
      console.log(`LINK: ${resetUrl}`);
      console.log(`-----------------------------------------`);
    }

    res.status(200).json({ message: "Si el correo está registrado, recibirás un enlace de recuperación." });
  } catch (err) {
    console.error("Forgot Password Error:", err);
    res.status(500).json({ error: "Error al procesar solicitud" });
  }
});

app.post('/api/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: "Datos incompletos" });
  if (newPassword.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  try {
    const { rows } = await pool.query("SELECT id FROM cupidos WHERE recovery_token = $1 AND token_expires > NOW()", [token]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Token inválido o expirado" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE cupidos SET password = $1, recovery_token = NULL, token_expires = NULL WHERE id = $2", [hashedPassword, user.id]);
    res.status(200).json({ message: "Contraseña actualizada correctamente" });
  } catch (e) {
    res.status(500).json({ error: "Error al procesar contraseña" });
  }
});


app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password, email, role, fullName, tel, city, age } = req.body;
  const userRole = role === 'blinder' ? 'blinder' : 'cupido';

  if (!username || !password || !email) return res.status(400).json({ error: "Datos incompletos" });
  if (username.length < 4) return res.status(400).json({ error: "El usuario debe tener al menos 4 caracteres" });
  if (password.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationToken = crypto.randomBytes(32).toString('hex');

    // 1. Create User
    const { rows } = await client.query(
      "INSERT INTO cupidos (username, password, email, role, is_verified, verification_token) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      [username, hashedPassword, email, userRole, false, verificationToken]
    );
    const userId = rows[0].id;

    // 2. Create Profile
    if (userRole === 'cupido') {
      await client.query(
        "INSERT INTO cupido_profiles (user_id, full_name, tel, city, age) VALUES ($1, $2, $3, $4, $5)",
        [userId, fullName || '', tel || '', city || '', age || null]
      );
    } else if (userRole === 'blinder') {
      // Support for direct Blinder registration (orphan profile initially)
      await client.query(
        "INSERT INTO blinder_profiles (user_id, full_name, tel, city, age) VALUES ($1, $2, $3, $4, $5)",
        [userId, fullName || '', tel || '', city || '', age || null]
      );
    }

    await client.query('COMMIT');

    // Send Verification Email
    await sendVerificationEmail(email, verificationToken, req);

    // Do NOT auto-login
    res.status(201).json({ message: "Registro exitoso. Revisa tu correo para verificar tu cuenta.", role: userRole });

  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(400).json({ error: "El usuario ya existe" });
    console.error("Register Error:", err);
    res.status(500).json({ error: "Error al registrar" });
  } finally {
    client.release();
  }
});


app.post('/api/rooms', isAuthenticated, async (req, res) => {
  const { friendA_name, friendB_name, noteA, noteB } = req.body;
  const cupido_id = req.session.userId;
  const linkA = crypto.randomUUID();
  const linkB = crypto.randomUUID();

  try {
    const { rows } = await pool.query(
      `INSERT INTO rooms (cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB) 
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB]
    );
    res.status(201).json({ id: rows[0].id, linkA, linkB });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al crear la sala" });
  }
});

// FEATURE: CUPIDO CONTACTS
app.post('/api/cupido/contacts', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const { name, tel, city, age } = req.body;
  if (!name || !tel) return res.status(400).json({ error: "Nombre y teléfono requeridos" });

  const tel_hash = crypto.createHash('sha256').update(tel).digest('hex');
  const tel_last4 = tel.slice(-4);

  try {
    const { rows } = await pool.query(
      "INSERT INTO solteros (cupido_id, name, tel_hash, tel_last4, city, age) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      [req.session.userId, name, tel_hash, tel_last4, city || 'Desconocida', age || 0]
    );
    res.status(201).json({ id: rows[0].id, message: "Contacto guardado" });
  } catch (err) {
    res.status(500).json({ error: "Error al guardar contacto" });
  }
});

// FEATURE: CUPIDO INVITE
app.get('/api/cupido/invite', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const token = crypto.randomUUID();
  // Postgres interval syntax or date object
  const expires = new Date(Date.now() + 60 * 60 * 1000);

  try {
    await pool.query("INSERT INTO invite_tokens (cupido_id, token, expires_at) VALUES ($1, $2, $3)", [req.session.userId, token, expires]);
    const host = req.get('host');
    const protocol = req.protocol;
    const url = `${protocol}://${host}/join/blinder/${token}`;
    res.json({ token, url });
  } catch (err) {
    res.status(500).json({ error: "Error" });
  }
});

app.post('/api/blinder/register-join', async (req, res) => {
  const { username, password, email, token, roomLink, fullName, age, city, tagline, photo, tel } = req.body;

  if (!username || !password || !email) return res.status(400).json({ error: "Datos incompletos" });
  if (username.length < 4) return res.status(400).json({ error: "El usuario debe tener al menos 4 caracteres" });
  if (password.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  const client = await pool.connect();

  try {
    // Check tel uniqueness
    const telCheck = await client.query("SELECT id FROM blinder_profiles WHERE tel = $1", [tel]);
    if (telCheck.rows.length > 0) return res.status(400).json({ error: "Teléfono ya registrado" });

    // Determine connection context
    let contextCupidoId = null;
    let contextRoomId = null;
    let contextRoleLetter = null;

    if (roomLink) {
      const roomRes = await client.query("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = $1 OR linkB = $2", [roomLink, roomLink]);
      if (roomRes.rows.length > 0) {
        const room = roomRes.rows[0];
        contextCupidoId = room.cupido_id;
        contextRoomId = room.id;
        contextRoleLetter = (roomLink === room.linka) ? 'A' : 'B'; // Postgres columns often lowercase
      } else {
        return res.status(400).json({ error: "Enlace inválido" });
      }
    } else if (token) {
      const inviteRes = await client.query("SELECT cupido_id FROM invite_tokens WHERE token = $1 AND expires_at > NOW()", [token]);
      if (inviteRes.rows.length > 0) {
        contextCupidoId = inviteRes.rows[0].cupido_id;
      } else {
        return res.status(400).json({ error: "Token inválido" });
      }
    } else {
      return res.status(400).json({ error: "Token inválido" });
    }

    // Validation: Must have either a valid Cupido context or Room context
    if (!contextCupidoId && !contextRoomId) {
      return res.status(400).json({ error: "Enlace de invitación o token requerido." });
    }

    // Transaction
    await client.query('BEGIN');

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create with is_verified = false
    const userRes = await client.query(
      "INSERT INTO cupidos (username, password, email, role, is_verified, verification_token) VALUES ($1, $2, $3, 'blinder', false, $4) RETURNING id",
      [username, hashedPassword, email, verificationToken]
    );
    const userId = userRes.rows[0].id;

    // Room Session (Wait until login to assign?)
    // Actually, if they are not verified, we probably should NOT assign them to the room yet, 
    // OR we can assign them but they can't access it until they login (which requires verification).
    // Let's bind them now so the "reservation" is made, but they can't use it.

    let sessionToken = null;
    if (contextRoomId && contextRoleLetter) {
      // ... Logic to bind room ... 
      // We will do this logic, but since they can't login, they can't use the session key yet.
      // Actually, we should probably NOT give them the session cookie yet.
    }

    // ... skipping session cookie logic for now ...

    // Blinder Profile
    await client.query(
      `INSERT INTO blinder_profiles (user_id, cupido_id, full_name, age, city, tagline, photo_url, tel) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, contextCupidoId, fullName, age, city, tagline, photo || '', tel]
    );

    // Also bind room if valid context
    if (contextRoomId && contextRoleLetter) {
      if (contextRoleLetter === 'A') {
        await client.query("UPDATE rooms SET user_a_id = $1 WHERE id = $2", [userId, contextRoomId]);
      } else {
        await client.query("UPDATE rooms SET user_b_id = $1 WHERE id = $2", [userId, contextRoomId]);
      }
    }

    await client.query('COMMIT');

    // Send Verification
    await sendVerificationEmail(email, verificationToken, req);

    // NO LOGIN. Respond telling user to verify.
    res.status(201).json({
      message: "Cuenta creada. Por favor verifica tu email antes de entrar.",
      requireVerification: true
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ error: "Usuario ya existe" });
    res.status(500).json({ error: "Error interno" });
  } finally {
    client.release();
  }
});

app.post('/api/blinder/login-join', async (req, res) => {
  const { username, password, token, roomLink } = req.body;

  if (!username || !password) return res.status(400).json({ error: "Credenciales incompletas" });

  const client = await pool.connect();

  try {
    // 1. Validate User
    const userRes = await client.query("SELECT * FROM cupidos WHERE username = $1", [username]);
    const user = userRes.rows[0];
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });

    // CHECK VERIFICATION
    if (!user.is_verified) {
      return res.status(401).json({ error: "Debes verificar tu correo electrónico primero." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Contraseña incorrecta" });
    if (user.role !== 'blinder') return res.status(403).json({ error: "Cuenta no es de tipo Blinder" });

    // 2. Validate Context (Room or Invite)
    let contextCupidoId = null;
    let contextRoomId = null;
    let contextRoleLetter = null;

    if (roomLink) {
      const roomRes = await client.query("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = $1 OR linkB = $2", [roomLink, roomLink]);
      if (roomRes.rows.length > 0) {
        const room = roomRes.rows[0];
        contextCupidoId = room.cupido_id;
        contextRoomId = room.id;
        contextRoleLetter = (roomLink === room.linka) ? 'A' : 'B';
      }
    } else if (token) {
      // Only token provided (invite flow not direct room link, less likely on join page but possible)
      // Usually join page has roomLink param if coming from room link
      // If just token, we might not have a room yet unless we create one? 
      // Requirement says "guardar la sala", implies room link exists.
      // Let's assume roomLink is main driver.
      const inviteRes = await client.query("SELECT cupido_id FROM invite_tokens WHERE token = $1 AND expires_at > NOW()", [token]);
      if (inviteRes.rows.length > 0) {
        contextCupidoId = inviteRes.rows[0].cupido_id;
      }
    }

    if (!contextRoomId && !contextCupidoId) {
      // Just login if no valid context found? Or error?
      // User asked to "save room". If no room found, just standard login.
    }

    await client.query('BEGIN');

    // 3. Link Room if applicable
    let sessionToken = null;
    if (contextRoomId && contextRoleLetter) {
      // Check if room slot is free or can be overwritten?
      // Assuming we overwrite or just claim it.
      sessionToken = crypto.randomUUID();
      if (contextRoleLetter === 'A') {
        await client.query("UPDATE rooms SET linkA_session = $1, user_a_id = $2 WHERE id = $3", [sessionToken, user.id, contextRoomId]);
      } else {
        await client.query("UPDATE rooms SET linkB_session = $1, user_b_id = $2 WHERE id = $3", [sessionToken, user.id, contextRoomId]);
      }
    }

    // 4. Update Profile if needed (optional, maybe link to new cupido?)
    // If arriving via token of a new Cupido, shoud we update cupido_id? 
    // Usually blinder belongs to who invited first, but we can add multiple links in future.
    // For now, let's just create the room link.

    await client.query('COMMIT');

    // 5. Session Setup
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = 'blinder';

    if (sessionToken && contextRoomId) {
      const cookieName = `chat_token_${contextRoomId}_${contextRoleLetter}`;
      res.setHeader('Set-Cookie', `${cookieName}=${sessionToken}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
    }

    res.json({ message: "Login y vinculación exitosa", redirectUrl: roomLink ? `/chat/${roomLink}` : '/blinder-dashboard' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: "Error en servidor" });
  } finally {
    client.release();
  }
});

function getRoomRevealLevel(activeSeconds) {
  const minutes = activeSeconds / 60;
  if (minutes >= 30) return 3;
  if (minutes >= 15) return 2;
  return 1;
}

app.get('/api/blinder/dashboard', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'blinder') return res.status(403).json({ error: "No autorizado" });
  const userId = req.session.userId;

  try {
    const { rows } = await pool.query(`
        SELECT r.id as room_id, r.friendA_name, r.friendB_name, r.status, r.active_since, r.total_active_seconds, 
               c.username as cupido_name, r.linkA, r.linkB, r.user_a_id, r.user_b_id
        FROM rooms r
        JOIN cupidos c ON r.cupido_id = c.id
        WHERE r.user_a_id = $1 OR r.user_b_id = $2
      `, [userId, userId]);

    const processedRooms = rows.map(room => {
      let currentActiveSeconds = room.total_active_seconds || 0;

      // Check type of active_since (it's BIGINT string in pg usually)
      if (room.active_since) {
        currentActiveSeconds += Math.floor((Date.now() - Number(room.active_since)) / 1000);
      }

      const roleLetter = (room.user_a_id === userId) ? 'A' : 'B';
      const myName = roleLetter === 'A' ? room.frienda_name : room.friendb_name; // lowercase from pg driver? usually yes unless quoted
      // Actually pg returns lowercase column names by default.
      // friendA_name -> frienda_name probably.
      // Let's assume standard casing for now or use snake_case in future.
      // With unquoted identifiers in CREATE TABLE, Postgres lowercases them.
      // friendA_name becomes frienda_name.

      const r_friendA = room.frienda_name || room.friendA_name; // fallback
      const r_friendB = room.friendb_name || room.friendB_name;
      const r_linkA = room.linka || room.linkA;
      const r_linkB = room.linkb || room.linkB;

      const myLink = roleLetter === 'A' ? r_linkA : r_linkB;
      const otherName = roleLetter === 'A' ? r_friendB : r_friendA;
      const myNameReal = roleLetter === 'A' ? r_friendA : r_friendB;

      return {
        room_id: room.room_id,
        cupido_name: room.cupido_name,
        other_name: otherName,
        my_name: myNameReal,
        status: room.status,
        active_seconds: currentActiveSeconds,
        reveal_level: getRoomRevealLevel(currentActiveSeconds),
        link: myLink
      };
    });

    res.json({ rooms: processedRooms });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error dashboard" });
  }
});

app.get('/api/cupido/blinders', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No" });
  try {
    const { rows } = await pool.query(
      `SELECT p.*, c.username FROM blinder_profiles p JOIN cupidos c ON p.user_id = c.id WHERE p.cupido_id = $1`,
      [req.session.userId]
    );
    const enriched = rows.map(r => ({
      ...r,
      isConnected: connectedBlinders.has(r.user_id)
    }));
    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: "Error" });
  }
});

app.post('/api/user/delete-account', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const role = req.session.userRole;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    if (role === 'blinder') {
      await client.query("DELETE FROM blinder_profiles WHERE user_id = $1", [userId]);
      await client.query("DELETE FROM cupidos WHERE id = $1", [userId]);
    } else {
      await client.query("DELETE FROM invite_tokens WHERE cupido_id = $1", [userId]);
      await client.query("DELETE FROM solteros WHERE cupido_id = $1", [userId]);
      await client.query("DELETE FROM blinder_profiles WHERE cupido_id = $1", [userId]);
      await client.query("DELETE FROM user_rooms WHERE cupido_id = $1", [userId]);
      await client.query("DELETE FROM rooms WHERE cupido_id = $1", [userId]);
      await client.query("DELETE FROM cupidos WHERE id = $1", [userId]);
    }
    await client.query('COMMIT');
    req.session.destroy();
    res.json({ message: "Cuenta borrada" });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Error" });
  } finally {
    client.release();
  }
});

app.get('/api/rooms', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  try {
    const ownedRes = await pool.query(`
      SELECT r.*, 
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id) as total_messages,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'A') as msgs_a,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'B') as msgs_b
      FROM rooms r 
      WHERE cupido_id = $1 
      ORDER BY created_at DESC
    `, [userId]);

    const enrichedOwned = ownedRes.rows.map(r => {
      let currentActiveSeconds = parseInt(r.total_active_seconds || 0, 10);
      if (r.active_since) {
        currentActiveSeconds += Math.floor((Date.now() - Number(r.active_since)) / 1000);
      }

      const totalMsgs = parseInt(r.total_messages || 0, 10);
      const msgsA = parseInt(r.msgs_a || 0, 10);
      const msgsB = parseInt(r.msgs_b || 0, 10);

      return {
        ...r,
        id: r.id,
        friendA_name: r.frienda_name,
        friendB_name: r.friendb_name,
        status: r.status,
        linkA: r.linka,
        linkB: r.linkb,
        linkA_used: !!r.linka_session,
        linkB_used: !!r.linkb_session,
        active_time_str: formatDuration(currentActiveSeconds),
        active_seconds: currentActiveSeconds,
        stats: {
          total_messages: totalMsgs,
          msgs_A: msgsA,
          msgs_B: msgsB,
          ratio_A: totalMsgs > 0 ? Math.round((msgsA / totalMsgs) * 100) : 0,
          ratio_B: totalMsgs > 0 ? Math.round((msgsB / totalMsgs) * 100) : 0
        }
      };
    });

    const accessedRes = await pool.query(`
        SELECT r.*, ur.role as accessed_role, ur.accessed_at
        FROM rooms r JOIN user_rooms ur ON r.id = ur.room_id
        WHERE ur.cupido_id = $1 AND r.cupido_id != $1
        ORDER BY ur.accessed_at DESC`, [userId]);

    res.json({ owned: enrichedOwned, accessed: accessedRes.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error" });
  }
});

// Generate Room Share Token
app.post('/api/rooms/:id/share', isAuthenticated, async (req, res) => {
  const roomId = req.params.id;
  const userId = req.session.userId;

  try {
    const result = await pool.query("SELECT id, share_token FROM rooms WHERE id = $1 AND cupido_id = $2", [roomId, userId]);
    if (result.rowCount === 0) return res.status(403).json({ error: "No autorizado" });

    let token = result.rows[0].share_token;
    if (!token) {
      token = crypto.randomUUID();
      await pool.query("UPDATE rooms SET share_token = $1 WHERE id = $2", [token, roomId]);
    }
    res.json({ token, url: `${req.protocol}://${req.get('host')}/dashboard?join_room=${token}` });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error" });
  }
});

// Join Room via Token
app.post('/api/rooms/join', isAuthenticated, async (req, res) => {
  const { token } = req.body;
  const userId = req.session.userId;
  if (!token) return res.status(400).json({ error: "Token requerido" });

  try {
    const roomRes = await pool.query("SELECT id, cupido_id FROM rooms WHERE share_token = $1", [token]);
    if (roomRes.rowCount === 0) return res.status(404).json({ error: "Sala no encontrada" });

    const room = roomRes.rows[0];
    if (room.cupido_id === userId) return res.json({ message: "Ya eres el dueño" });

    // Add to user_rooms
    await pool.query(`
            INSERT INTO user_rooms (cupido_id, room_id, role) 
            VALUES ($1, $2, 'cupido') 
            ON CONFLICT (cupido_id, room_id) DO UPDATE SET accessed_at = NOW()
        `, [userId, room.id]);

    res.json({ message: "Unido exitosamente", roomId: room.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error al unirse" });
  }
});

app.delete('/api/rooms/:id', isAuthenticated, async (req, res) => {
  const roomId = req.params.id;
  const cupido_id = req.session.userId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const delRes = await client.query("DELETE FROM rooms WHERE id = $1 AND cupido_id = $2", [roomId, cupido_id]);
    if (delRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Error" });
    }
    await client.query("DELETE FROM messages WHERE room_id = $1", [roomId]);
    await client.query("DELETE FROM user_rooms WHERE room_id = $1", [roomId]);
    await client.query('COMMIT');
    res.json({ message: "Borrado" });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Error" });
  } finally {
    client.release();
  }
});

app.post('/api/request-new-link', async (req, res) => {
  const { oldLink } = req.body;
  try {
    const { rows } = await pool.query("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = $1 OR linkB = $2", [oldLink, oldLink]);
    const room = rows[0];
    if (!room) return res.status(404).json({ error: "No encontrado" });

    const isA = (oldLink === room.linka); // pg lowercase
    const newLink = crypto.randomUUID();

    const linkCol = isA ? 'linkA' : 'linkB';
    const sessionCol = isA ? 'linkA_session' : 'linkB_session';
    // Safe dynamic column because we control the string literal above mostly
    // But query params easier:
    if (isA) {
      await pool.query("UPDATE rooms SET linkA = $1, linkA_session = NULL WHERE id = $2", [newLink, room.id]);
    } else {
      await pool.query("UPDATE rooms SET linkB = $1, linkB_session = NULL WHERE id = $2", [newLink, room.id]);
    }

    io.to(`dashboard_${room.cupido_id}`).emit('link-regenerated', { room_id: room.id, role: isA ? 'A' : 'B', new_link: newLink });
    res.json({ message: "OK" });

  } catch (err) {
    res.status(500).json({ error: "Error" });
  }
});

app.get('/chat/:link', async (req, res) => {
  const { link } = req.params;
  try {
    const { rows } = await pool.query("SELECT * FROM rooms WHERE linkA = $1 OR linkB = $2", [link, link]);
    const room = rows[0];
    if (!room) return res.redirect('/login');

    const isA = (link === room.linka); // check lowercase
    const sessionVal = isA ? room.linka_session : room.linkb_session;

    const cookieName = `chat_token_${room.id}_${isA ? 'A' : 'B'}`;
    const clientToken = req.headers.cookie?.split('; ').find(row => row.startsWith(cookieName))?.split('=')[1];

    if (!sessionVal && !clientToken) {
      return res.redirect(`/join/blinder/profile?link=${link}`);
    }
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));

  } catch (err) {
    res.redirect('/login');
  }
});


app.get('/api/chat-info/:link', async (req, res) => {
  const { link } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT id as room_id, friendA_name, friendB_name, linkA, linkB, cupido_id, user_a_id, user_b_id 
           FROM rooms WHERE linkA = $1 OR linkB = $2`,
      [link, link]
    );
    const room = rows[0];
    if (!room) return res.status(404).json({ error: "No" });

    const sender = (link === room.linka) ? 'A' : 'B';
    const otherRole = (sender === 'A') ? 'B' : 'A';
    const otherUserId = (sender === 'A') ? room.user_b_id : room.user_a_id;
    const statusObj = roomStatus[room.room_id] || { A: null, B: null };

    let isOtherDeleted = false;
    if (otherUserId) {
      const uRes = await pool.query("SELECT id FROM cupidos WHERE id = $1", [otherUserId]);
      isOtherDeleted = (uRes.rows.length === 0);
    }

    const msgRes = await pool.query("SELECT sender, text, timestamp FROM messages WHERE room_id = $1 ORDER BY timestamp ASC", [room.room_id]);

    res.json({
      room_id: room.room_id,
      sender,
      myName: sender === 'A' ? room.frienda_name : room.friendb_name,
      otherName: isOtherDeleted ? "Usuario Eliminado" : (sender === 'A' ? room.friendb_name : room.frienda_name),
      otherRole,
      otherConnected: !!statusObj[otherRole],
      otherDeleted: isOtherDeleted,
      isLoggedIn: !!req.session.userId,
      messages: msgRes.rows || []
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error" });
  }
});


// Socket.io
io.on('connection', (socket) => {
  socket.on('join-user', ({ userId }) => {
    socket.userId = userId;
    socket.join(`user_${userId}`);
    connectedUsers.add(userId.toString());

    // Check for offline messages
    const pending = offlineMessageQueue.get(userId.toString());
    if (pending && pending.length > 0) {
      socket.emit('pending-messages', pending);
      offlineMessageQueue.delete(userId.toString()); // Clear after sending
    }

    pool.query("SELECT cupido_id FROM blinder_profiles WHERE user_id = $1", [userId])
      .then(res => {
        const row = res.rows[0];
        if (row && row.cupido_id) {
          socket.isBlinder = true;
          socket.blinderCupidoId = row.cupido_id;
          connectedBlinders.set(userId, { socketId: socket.id, cupidoId: row.cupido_id });
          io.to(`dashboard_${row.cupido_id}`).emit('blinder-status', { blinderId: userId, isConnected: true });
        }
      })
      .catch(e => console.error(e));
  });

  socket.on('join-dashboard', ({ cupido_id }) => { socket.join(`dashboard_${cupido_id}`); });

  socket.on('join-room', ({ link }) => {
    pool.query("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = $1 OR linkB = $2", [link, link])
      .then(res => {
        const room = res.rows[0];
        if (!room) return;
        socket.join(`room_${room.id}`);
        socket.room_id = room.id;
        socket.sender = (link === room.linka) ? 'A' : 'B';
        socket.cupido_id = room.cupido_id;
        if (!roomStatus[room.id]) roomStatus[room.id] = { A: null, B: null };
        roomStatus[room.id][socket.sender] = socket.id;
        updateAndNotifyStatus(room.id, room.cupido_id);
        socket.to(`room_${room.id}`).emit('user_joined', { role: socket.sender });
      })
      .catch(e => console.error(e));
  });

  socket.on('send-message', async ({ room_id, sender, text }) => {
    try {
      await pool.query("INSERT INTO messages (room_id, sender, text) VALUES ($1, $2, $3)", [room_id, sender, text]);
      io.to(`room_${room_id}`).emit('new-message', { sender, text, timestamp: new Date().toISOString() });

      // Notify the OTHER user
      const roomRes = await pool.query("SELECT user_a_id, user_b_id, friendA_name, friendB_name, linkA, linkB FROM rooms WHERE id = $1", [room_id]);
      const room = roomRes.rows[0];

      if (room) {
        let recipientId, recipientName, myName, myLink, otherLink;
        if (sender === 'A') {
          recipientId = room.user_b_id;
          myName = room.frienda_name;
          otherLink = room.linkb;
        } else {
          recipientId = room.user_a_id;
          myName = room.friendb_name;
          otherLink = room.linka;
        }

        if (recipientId) {
          // 1. Global Socket Notification
          const isConnected = connectedUsers.has(recipientId.toString());
          const notifPayload = {
            room_id,
            otherLink,
            title: `Nuevo mensaje de ${myName}`,
            body: text.length > 50 ? text.substring(0, 50) + '...' : text
          };

          if (isConnected) {
            // Send real-time alert to all tabs of the recipient
            io.to(`user_${recipientId}`).emit('global-message-alert', notifPayload);
          } else {
            // Save in memory queue until they connect
            if (!offlineMessageQueue.has(recipientId.toString())) {
              offlineMessageQueue.set(recipientId.toString(), []);
            }
            offlineMessageQueue.get(recipientId.toString()).push(notifPayload);
          }

          // 2. Web Push (Traditional background)
          sendPushToUser(recipientId, {
            title: notifPayload.title,
            body: notifPayload.body,
            url: `/chat/${notifPayload.otherLink}`,
            tag: `chat-${room_id}`
          });
        }
      }
    } catch (e) {
      console.error("Msg Error", e);
    }
  });

  socket.on('typing', ({ room_id, sender, isTyping }) => {
    socket.to(`room_${room_id}`).emit('display-typing', { sender, isTyping });
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      // Check if user has other sockets open before removing from connectedUsers
      const userRoom = io.sockets.adapter.rooms.get(`user_${socket.userId}`);
      if (!userRoom || userRoom.size === 0) {
        connectedUsers.delete(socket.userId.toString());
      }
    }
    if (socket.room_id && socket.sender && roomStatus[socket.room_id]) {
      roomStatus[socket.room_id][socket.sender] = null;
      updateAndNotifyStatus(socket.room_id, socket.cupido_id);
    }
    if (socket.isBlinder && socket.userId) {
      connectedBlinders.delete(socket.userId);
      if (socket.blinderCupidoId) {
        io.to(`dashboard_${socket.blinderCupidoId}`).emit('blinder-status', { blinderId: socket.userId, isConnected: false });
      }
    }
  });
});

// Utility: QR Code
app.get('/api/utils/qr', async (req, res) => {
  const { text } = req.query;
  if (!text) return res.status(400).send("No text provided");

  try {
    const qrData = await QRCode.toDataURL(text);
    res.json({ dataUrl: qrData });
  } catch (e) {
    res.status(500).json({ error: "QR Error" });
  }
});

// Fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// START
const rawPort = process.env.PORT;
const port = parseInt(rawPort, 10) || 8080;

process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received: Closing server...');
  server.close(() => {
    console.log('👋 Server closed.');
    process.exit(0);
  });
});


function formatDuration(seconds) {
  if (!seconds) return "0m";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

(async () => {
  console.log("🌀 Starting server process...");
  console.log(`ENV PORT check: ${rawPort ? 'Found: ' + rawPort : 'Not found, using fallback'}`);

  try {
    await initDb();
    console.log("✅ initDb() completed.");

    // Clear stale statuses
    await pool.query("UPDATE rooms SET active_since = NULL");

    server.listen(port, '0.0.0.0', () => {
      console.log(`🚀 Cupido's Project LIVE on PORT ${port}`);
      console.log(`🔗 Interface available on http://0.0.0.0:${port}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error("FATAL STARTUP ERROR:", err);
    process.exit(1);
  }
})();
