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
const { execSync } = require('child_process');

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

// Email Configuration (SendGrid & Nodemailer)
const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');

if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
} else {
  console.warn("⚠️ SENDGRID_API_KEY missing. Checking for SMTP...");
}

// 1. SMTP Transporter (Generic Fallback)
let smtpTransport = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  smtpTransport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    // Fail fast if SMTP is stuck
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 10000
  });
  console.log("📧 SMTP Configured via Nodemailer");
}

// 2. SendGrid SMTP Transporter (Alternative)
let sgSmtpTransport = null;
if (process.env.SENDGRID_API_KEY) {
  sgSmtpTransport = nodemailer.createTransport({
    host: 'smtp.sendgrid.net',
    port: 587,
    auth: {
      user: 'apikey',
      pass: process.env.SENDGRID_API_KEY
    },
    // Fail fast if SendGrid SMTP is stuck
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 10000
  });
}

async function sendVerificationEmail(email, token, req) {
  const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;

  const emailSubject = 'Verifica tu cuenta - Cupidos Project';
  const emailHtml = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2>Bienvenido a Cupidos Project</h2>
      <p>Por favor verifica tu correo haciendo clic en el siguiente enlace:</p>
      <a href="${verifyUrl}" style="background: #4ade80; color: white; padding: 12px 24px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;">Verificar Cuenta</a>
      <p>O copia este enlace: ${verifyUrl}</p>
    </div>
  `;

  // Debug: Log the link for development
  console.log(`🔗 EMAIL DEBUG: ${verifyUrl}`);

  // Priority 1: SendGrid Web API (Standard)
  if (process.env.SENDGRID_API_KEY) {
    const msg = {
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL || 'noreply@cupidosproject.com',
      subject: emailSubject,
      html: emailHtml
    };
    try {
      await sgMail.send(msg);
      console.log(`📨 Live verification email sent to ${email} (SendGrid API)`);
      return;
    } catch (error) {
      console.error('❌ SendGrid API Error:', error);
      if (error.response) console.error(error.response.body);
      console.log('⚠️ Falling back to SendGrid SMTP...');
    }
  }

  // Priority 2: SendGrid SMTP (Nodemailer) - PROPOSED FIX
  if (sgSmtpTransport) {
    try {
      await sgSmtpTransport.sendMail({
        from: process.env.SENDGRID_FROM_EMAIL || 'noreply@cupidosproject.com',
        to: email,
        subject: emailSubject,
        html: emailHtml
      });
      console.log(`📨 Live verification email sent to ${email} (SendGrid SMTP)`);
      return;
    } catch (sgErr) {
      console.error("❌ SendGrid SMTP Error:", sgErr);
    }
  }

  // Priority 3: Generic SMTP (Nodemailer)
  if (smtpTransport) {
    try {
      await smtpTransport.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: emailSubject,
        html: emailHtml
      });
      console.log(`📨 Live verification email sent to ${email} (SMTP)`);
      return;
    } catch (smtpErr) {
      console.error("❌ Generic SMTP Error:", smtpErr);
    }
  }

  // Priority 4: Mock
  console.log(`📨 MOCK EMAIL MODE ACTIVE (No working transport found)`);
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

  // 1. Determine Status (Memory Only) - fast & immediate
  const statusObj = roomStatus[room_id];
  const presenceA = !!(statusObj && statusObj.A);
  const presenceB = !!(statusObj && statusObj.B);

  // Emit Presence to Chat Room immediately (Critical for User experience)
  io.to(`room_${room_id}`).emit('presence-update', { A: presenceA, B: presenceB });

  try {
    // 2. DB Sync & Dashboard Updates
    const res = await pool.query("SELECT active_since, friendA_name, friendB_name FROM rooms WHERE id = $1", [room_id]);
    const row = res.rows[0];
    const currentActiveSince = row ? row.active_since : null;

    // Postgres driver might return lowercase column names
    const nameA = row ? (row.frienda_name || row.friendA_name || 'A') : 'A';
    const nameB = row ? (row.friendb_name || row.friendB_name || 'B') : 'B';

    let statusText = 'pendiente';
    const isNowActive = (presenceA && presenceB);

    if (isNowActive) statusText = 'activo';
    else if (presenceA) statusText = `${nameA} conectado`;
    else if (presenceB) statusText = `${nameB} conectado`;
    else if (statusObj) statusText = 'desconectado';

    const now = Date.now();

    if (isNowActive && !currentActiveSince) {
      // Transition to Active
      await pool.query("UPDATE rooms SET status = $1, active_since = $2 WHERE id = $3", [statusText, now, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: now });

    } else if (!isNowActive && currentActiveSince) {
      // Transition to Inactive (Pause timer)
      const duration = Math.floor((now - Number(currentActiveSince)) / 1000);
      await pool.query(
        "UPDATE rooms SET status = $1, active_since = NULL, total_active_seconds = COALESCE(total_active_seconds, 0) + $2 WHERE id = $3",
        [statusText, duration, room_id]
      );
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: null, added_seconds: duration });

    } else {
      // Just status change (e.g. A active -> B active, but never both)
      await pool.query("UPDATE rooms SET status = $1 WHERE id = $2", [statusText, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
    }

    // Debug Log
    console.log(`[Status] Room ${room_id}: A=${presenceA}, B=${presenceB} -> ${statusText}`);

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

  // Fix for legacy redirects or wrong paths
  let returnUrl = req.originalUrl;
  if (returnUrl.startsWith('/dashboard')) {
    returnUrl = returnUrl.replace('/dashboard', '/cupido-dashboard');
  }

  const encodedUrl = encodeURIComponent(returnUrl);
  res.redirect(`/login?returnTo=${encodedUrl}`);
};

// Legacy Redirect
app.get('/dashboard', (req, res) => {
  // Keep query params
  const query = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
  res.redirect('/cupido-dashboard' + query);
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
  const { password: _p, ...safeBody } = req.body;
  console.log("👉 Register Request:", safeBody);
  const { username, password, email, role, fullName, tel, city, age } = req.body;
  const userRole = role === 'blinder' ? 'blinder' : 'cupido';

  if (!username || !password || !email) return res.status(400).json({ error: "Datos incompletos" });
  if (username.length < 4) return res.status(400).json({ error: "El usuario debe tener al menos 4 caracteres" });
  if (password.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });

  const client = await pool.connect();

  try {
    // 0. Pre-check for existence to avoid ambiguous DB errors
    const checkRes = await client.query("SELECT id FROM cupidos WHERE username = $1 OR email = $2", [username, email]);
    if (checkRes.rows.length > 0) {
      return res.status(400).json({ error: "El usuario o el correo ya están registrados." });
    }

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
    const safeAge = (age && !isNaN(parseInt(age))) ? parseInt(age) : null;

    if (userRole === 'cupido') {
      await client.query(
        "INSERT INTO cupido_profiles (user_id, full_name, tel, city, age) VALUES ($1, $2, $3, $4, $5)",
        [userId, fullName || '', tel || '', city || '', safeAge]
      );
    } else if (userRole === 'blinder') {
      await client.query(
        "INSERT INTO blinder_profiles (user_id, full_name, tel, city, age) VALUES ($1, $2, $3, $4, $5)",
        [userId, fullName || '', tel || '', city || '', safeAge]
      );
    }

    await client.query('COMMIT');

    // Send Verification Email (Safe Wrapper)
    let emailStatus = "";
    const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${verificationToken}`;

    try {
      await sendVerificationEmail(email, verificationToken, req);
    } catch (emailErr) {
      console.error("⚠️ Email sending failed (non-fatal):", emailErr);
      emailStatus = " (El correo falló, usa el enlace abajo)";
    }

    // Do NOT auto-login
    // DEV: Returning link in message so user can click it if email fails (common in unverified SendGrid setups)
    res.status(201).json({
      message: `Registro exitoso. Revisa tu correo.${emailStatus} <br><br> <a href="${verifyUrl}" style="color: #fff; text-decoration: underline; font-weight: bold;">[CLICK AQUÍ PARA VERIFICAR MANUALMENTE]</a>`,
      role: userRole
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ Register Error:", err);
    if (err.code === '23505') return res.status(400).json({ error: "El usuario creía no existir, pero la DB dice que sí." });
    res.status(500).json({ error: "Error interno al registrar: " + err.message });
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

// FEATURE: CUPIDO SPY / TOP SECRET
app.get('/api/cupido/spy-status', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const cupidoId = req.session.userId;
  const today = new Date().toISOString().split('T')[0];

  try {
    const { rows } = await pool.query(
      "SELECT usage_count FROM cupido_secrets WHERE cupido_id = $1 AND usage_date = $2",
      [cupidoId, today]
    );
    const used = rows[0] ? rows[0].usage_count : 0;
    const max = 3;
    res.json({ used, max, remaining: Math.max(0, max - used) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error checking quota" });
  }
});

app.post('/api/cupido/spy-consume', isAuthenticated, async (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const cupidoId = req.session.userId;
  const today = new Date().toISOString().split('T')[0];
  const max = 3;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Upsert logic for Postgres: INSERT ... ON CONFLICT
    await client.query(`
      INSERT INTO cupido_secrets (cupido_id, usage_date, usage_count)
      VALUES ($1, $2, 1)
      ON CONFLICT (cupido_id, usage_date) 
      DO UPDATE SET usage_count = cupido_secrets.usage_count + 1
    `, [cupidoId, today]);

    const { rows } = await client.query(
      "SELECT usage_count FROM cupido_secrets WHERE cupido_id = $1 AND usage_date = $2",
      [cupidoId, today]
    );

    const used = rows[0].usage_count;

    if (used > max) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: "Cupo diario agotado" });
    }

    await client.query('COMMIT');
    res.json({ success: true, remaining: max - used });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: "Error consuming credit" });
  } finally {
    client.release();
  }
});

app.get('/api/rooms/:id/peek', isAuthenticated, async (req, res) => {
  const roomId = req.params.id;
  const userId = req.session.userId;

  try {
    // Verify Access
    const accessRes = await pool.query(`
         SELECT id FROM rooms r
         WHERE r.id = $1 AND (r.cupido_id = $2 OR EXISTS (SELECT 1 FROM user_rooms ur WHERE ur.room_id = r.id AND ur.cupido_id = $2))
       `, [roomId, userId]);

    if (accessRes.rows.length === 0) return res.status(403).json({ error: "Acceso denegado" });

    const msgs = await pool.query(`
            SELECT sender, text, timestamp 
            FROM messages 
            WHERE room_id = $1 
            ORDER BY id DESC 
            LIMIT 3
        `, [roomId]);

    res.json(msgs.rows.reverse());
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Error retrieving messages" });
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

    // 4. Update Profile Association (Link Blinder to this Cupido)
    if (contextCupidoId) {
      await client.query("UPDATE blinder_profiles SET cupido_id = $1 WHERE user_id = $2", [contextCupidoId, user.id]);
    }

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
    // 1. Get Real Profile Name First
    const profileRes = await pool.query("SELECT full_name FROM blinder_profiles WHERE user_id = $1", [userId]);
    const realName = profileRes.rows[0]?.full_name || req.session.username;

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

      // Postgres lowercases columns if unquoted
      const r_friendA = room.frienda_name || room.friendA_name;
      const r_friendB = room.friendb_name || room.friendB_name;
      const r_linkA = room.linka || room.linkA;
      const r_linkB = room.linkb || room.linkB;

      const myLink = roleLetter === 'A' ? r_linkA : r_linkB;
      const otherName = roleLetter === 'A' ? r_friendB : r_friendA;

      // FIX: Use Real Name from Profile instead of Room Name
      // const myNameReal = roleLetter === 'A' ? r_friendA : r_friendB; 
      const myNameReal = realName;

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

    // 1. Common cleanup independent of role
    await client.query("DELETE FROM push_subscriptions WHERE user_id = $1", [userId]);

    // Also remove from user_rooms access (member of a room)
    // Note: If they created the room (cupido_id), that's handled below.
    // If they are just assigned to a side (user_a_id/user_b_id in rooms table):
    await client.query("UPDATE rooms SET user_a_id = NULL WHERE user_a_id = $1", [userId]);
    await client.query("UPDATE rooms SET user_b_id = NULL WHERE user_b_id = $1", [userId]);

    // 2. Role Specific Cleanup
    if (role === 'blinder') {
      await client.query("DELETE FROM blinder_profiles WHERE user_id = $1", [userId]);
    } else {
      // Cupido: Has created rooms, invites, contacts, profile, etc.

      // Delete invite tokens
      await client.query("DELETE FROM invite_tokens WHERE cupido_id = $1", [userId]);

      // Delete contacts (Solteros)
      await client.query("DELETE FROM solteros WHERE cupido_id = $1", [userId]);

      // Delete Cupido Profile
      await client.query("DELETE FROM cupido_profiles WHERE user_id = $1", [userId]);

      // Delete Blinder Profiles created by this Cupido (if strictly owned? usually user_id is unique key). 
      // If blinder_profiles are linked via cupido_id:
      await client.query("DELETE FROM blinder_profiles WHERE cupido_id = $1", [userId]);

      // Delete User Rooms (junction table) for rooms this cupido owns or is part of
      await client.query("DELETE FROM user_rooms WHERE cupido_id = $1", [userId]);

      // Complicated: Rooms owned by this Cupido
      // We must delete messages in those rooms first
      await client.query(`
        DELETE FROM messages 
        WHERE room_id IN (SELECT id FROM rooms WHERE cupido_id = $1)
      `, [userId]);

      // Finally delete the rooms
      await client.query("DELETE FROM rooms WHERE cupido_id = $1", [userId]);
    }

    // 3. Finally Delete User
    await client.query("DELETE FROM cupidos WHERE id = $1", [userId]);

    await client.query('COMMIT');
    req.session.destroy();
    res.json({ message: "Cuenta borrada" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Delete Account Error:", err);
    res.status(500).json({ error: "Error al borrar cuenta" });
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
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'B') as msgs_b,
        (SELECT text FROM messages m WHERE m.room_id = r.id ORDER BY timestamp DESC LIMIT 1) as last_message,
        (SELECT sender FROM messages m WHERE m.room_id = r.id ORDER BY timestamp DESC LIMIT 1) as last_sender
      FROM rooms r 
      WHERE cupido_id = $1 
      ORDER BY created_at DESC
    `, [userId]);

    // Helper to format room data
    const enrichRoomData = (rows) => rows.map(r => {
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
        last_message: r.last_message,
        last_sender: r.last_sender,
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

    const enrichedOwned = enrichRoomData(ownedRes.rows);

    const accessedRes = await pool.query(`
        SELECT r.*, ur.role as accessed_role, ur.accessed_at,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id) as total_messages,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'A') as msgs_a,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'B') as msgs_b,
        (SELECT text FROM messages m WHERE m.room_id = r.id ORDER BY timestamp DESC LIMIT 1) as last_message,
        (SELECT sender FROM messages m WHERE m.room_id = r.id ORDER BY timestamp DESC LIMIT 1) as last_sender
        FROM rooms r JOIN user_rooms ur ON r.id = ur.room_id
        WHERE ur.cupido_id = $1 AND r.cupido_id != $1
        ORDER BY ur.accessed_at DESC`, [userId]);

    const enrichedAccessed = enrichRoomData(accessedRes.rows);

    res.json({ owned: enrichedOwned, accessed: enrichedAccessed, my_id: userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error" });
  }
});

// Get Single Room Details (Refresh)
app.get('/api/rooms/:id', isAuthenticated, async (req, res) => {
  const roomId = req.params.id;
  const userId = req.session.userId;
  if (!roomId || isNaN(roomId)) return res.status(400).json({ error: "ID inválido" });

  try {
    const roomRes = await pool.query(`
      SELECT r.*, 
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id) as total_messages,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'A') as msgs_a,
        (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id AND m.sender = 'B') as msgs_b,
        (SELECT timestamp FROM messages m WHERE m.room_id = r.id ORDER BY timestamp DESC LIMIT 1) as last_message_time
      FROM rooms r 
      WHERE r.id = $2 AND (r.cupido_id = $1 OR EXISTS (SELECT 1 FROM user_rooms ur WHERE ur.room_id = r.id AND ur.cupido_id = $1))
    `, [userId, roomId]);

    if (roomRes.rows.length === 0) return res.status(404).json({ error: "Sala no encontrada" });

    const r = roomRes.rows[0];

    let currentActiveSeconds = parseInt(r.total_active_seconds || 0, 10);
    if (r.active_since) {
      currentActiveSeconds += Math.floor((Date.now() - Number(r.active_since)) / 1000);
    }

    const totalMsgs = parseInt(r.total_messages || 0, 10);
    const msgsA = parseInt(r.msgs_a || 0, 10);
    const msgsB = parseInt(r.msgs_b || 0, 10);

    const enrichedRoom = {
      ...r,
      id: r.id,
      friendA_name: r.frienda_name || r.friendA_name, // pg lowercasing handling
      friendB_name: r.friendb_name || r.friendB_name,
      status: r.status,
      linkA: r.linka || r.linkA,
      linkB: r.linkb || r.linkB,
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

    res.json(enrichedRoom);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener sala" });
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
    res.json({ token, url: `${req.protocol}://${req.get('host')}/cupido-dashboard?join_room=${token}` });

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
    const { rows } = await pool.query("SELECT id, cupido_id, linkA, linkB, friendA_name, friendB_name FROM rooms WHERE linkA = $1 OR linkB = $2", [oldLink, oldLink]);
    const room = rows[0];
    if (!room) return res.status(404).json({ error: "No encontrado" });

    const isA = (oldLink === room.linka); // pg lowercase
    const requesterName = isA ? room.frienda_name : room.friendb_name;
    const newLink = crypto.randomUUID();

    // Update DB
    if (isA) {
      await pool.query("UPDATE rooms SET linkA = $1, linkA_session = NULL WHERE id = $2", [newLink, room.id]);
    } else {
      await pool.query("UPDATE rooms SET linkB = $1, linkB_session = NULL WHERE id = $2", [newLink, room.id]);
    }

    // Notify Dashboard via Socket
    io.to(`dashboard_${room.cupido_id}`).emit('link-regenerated', {
      room_id: room.id,
      role: isA ? 'A' : 'B',
      new_link: newLink,
      requester: requesterName
    });

    // Notify via Email
    const cupidoRes = await pool.query("SELECT email, username FROM cupidos WHERE id = $1", [room.cupido_id]);
    const cupido = cupidoRes.rows[0];

    if (cupido && cupido.email) {
      const emailSubject = `📢 Solicitud de nuevo enlace - ${requesterName}`;
      const dashboardUrl = `${req.protocol}://${req.get('host')}/cupido-dashboard`;
      const emailHtml = `
            <div style="font-family: 'Outfit', sans-serif; color: #111; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h2 style="color: #ff4d6d;">Nuevo Link Solicitado</h2>
                <p>Hola <strong>${cupido.username}</strong>,</p>
                <p>Tu blinder <strong>${requesterName}</strong> ha tenido problemas para entrar y ha solicitado un nuevo enlace.</p>
                
                <div style="background: #fdf2f4; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ff4d6d;">
                    <p style="margin: 0; font-size: 0.9rem; color: #666;">Nuevo Enlace Generado:</p>
                    <p style="margin: 5px 0 0 0; font-weight: bold; font-family: monospace; font-size: 1.1rem; word-break: break-all;">
                        ${req.protocol}://${req.get('host')}/join/blinder/profile?link=${newLink}
                    </p>
                </div>

                <p>Por favor, copia este enlace y envíaselo a ${requesterName}.</p>
                <a href="${dashboardUrl}" style="background: #111; color: white; padding: 12px 24px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;">Ir al Dashboard</a>
            </div>
        `;

      const msg = {
        to: cupido.email,
        from: process.env.SENDGRID_FROM_EMAIL || 'no-reply@cupidosproject.com',
        subject: emailSubject,
        html: emailHtml
      };

      // Use existing transport logic (sgMail or Nodemailer) - copying generic send logic here briefly
      if (sgMail && process.env.SENDGRID_API_KEY) {
        sgMail.send(msg).catch(e => console.error("SendGrid Error:", e));
      } else if (smtpTransport) {
        smtpTransport.sendMail(msg).catch(e => console.error("SMTP Error:", e));
      } else {
        console.log("📨 Email simulation:", msg);
      }
    }

    res.json({ message: "OK" });

  } catch (err) {
    console.error("Request Link Error:", err);
    res.status(500).json({ error: "Error" });
  }
});

app.get('/chat/:link', async (req, res) => {
  const { link } = req.params;

  // Cache Buster: Force v=4 param
  if (req.query.v !== '4') {
    const newUrl = req.originalUrl.includes('?')
      ? `${req.originalUrl}&v=4`
      : `${req.originalUrl}?v=4`;
    return res.redirect(newUrl);
  }

  try {
    const { rows } = await pool.query("SELECT * FROM rooms WHERE linkA = $1 OR linkB = $2", [link, link]);
    const room = rows[0];
    if (!room) return res.redirect('/login'); // Link doesn't exist

    const isA = (link === room.linka); // check lowercase from pg check
    const sessionVal = isA ? room.linka_session : room.linkb_session;
    const assignedUserId = isA ? room.user_a_id : room.user_b_id;

    const cookieName = `chat_token_${room.id}_${isA ? 'A' : 'B'}`;
    const clientToken = req.headers.cookie?.split('; ').find(row => row.startsWith(cookieName))?.split('=')[1];

    // LOGIC FIX: Re-entry and Auto-Association

    // LOGIC REFACTOR: Ownership First
    // We check if the link has an ASSIGNED USER in the DB.
    // If assignedUserId is present, the link is CLAIMED permanently by that user.
    // 'sessionVal' (cookie) is just a secondary check for auto-login without session.

    // 1. Link is CLAIMED (Has an Owner)
    if (assignedUserId) {
      // Authenticated check
      if (req.session.userId) {
        if (req.session.userId === assignedUserId) {
          // SUCCESS: Updating/Setting Cookie just in case
          if (sessionVal) {
            res.setHeader('Set-Cookie', `${cookieName}=${sessionVal}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
          }
          return res.sendFile(path.join(__dirname, 'public', 'chat.html'));
        } else {
          // Logged in as WRONG user
          console.log(`[Chat Access] Wrong user ${req.session.userId} for room ${room.id} (Owner: ${assignedUserId})`);
          // Redirect to their dashboard instead of Blocking, so they can see their own chats
          return res.redirect('/blinder-dashboard');
        }
      }

      // Unauthenticated -> Force Login
      // We do NOT send to Join/Register because it's already owned.
      const returnUrl = encodeURIComponent(req.originalUrl);
      return res.redirect(`/login?returnTo=${returnUrl}&msg=owned`);
    }

    // 2. Link is UNCLAIMED (No Owner yet)
    // Redirect to Join/Register flow
    return res.redirect(`/join/blinder/profile?link=${link}`);

  } catch (err) {
    console.error("Chat Route Error:", err);
    res.redirect('/login');
  }
});


app.get('/api/chat-info/:link', async (req, res) => {
  const { link } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT id as room_id, friendA_name, friendB_name, linkA, linkB, cupido_id, user_a_id, user_b_id,
              active_since, total_active_seconds, status
       FROM rooms WHERE linkA = $1 OR linkB = $2`,
      [link, link]
    );
    const room = rows[0];
    if (!room) {
      console.log(`[API Chat Info] Room not found for link: ${link}`);
      return res.status(404).json({ error: "No" });
    }

    const sender = (link === room.linka) ? 'A' : 'B';
    const otherRole = (sender === 'A') ? 'B' : 'A';
    const otherUserId = (sender === 'A') ? room.user_b_id : room.user_a_id;
    const statusObj = roomStatus[room.room_id] || { A: null, B: null };

    let isOtherDeleted = false;
    let otherPhoto = null;

    if (otherUserId) {
      const uRes = await pool.query("SELECT id FROM cupidos WHERE id = $1", [otherUserId]);
      isOtherDeleted = (uRes.rows.length === 0);

      if (!isOtherDeleted) {
        // Fetch Photo
        const pRes = await pool.query("SELECT photo_url FROM blinder_profiles WHERE user_id = $1", [otherUserId]);
        otherPhoto = pRes.rows[0]?.photo_url || null;
      }
    }

    const msgRes = await pool.query("SELECT sender, text, timestamp FROM messages WHERE room_id = $1 ORDER BY timestamp ASC", [room.room_id]);

    // Calculate Active Time
    let currentActiveSeconds = parseInt(room.total_active_seconds || 0, 10);
    if (room.status === 'activo' && room.active_since) {
      currentActiveSeconds += Math.floor((Date.now() - Number(room.active_since)) / 1000);
    }

    res.json({
      room_id: room.room_id,
      sender,
      myName: sender === 'A' ? room.frienda_name : room.friendb_name,
      otherName: isOtherDeleted ? "Usuario Eliminado" : (sender === 'A' ? room.friendb_name : room.frienda_name),
      otherRole,
      otherConnected: !!statusObj[otherRole],
      otherDeleted: isOtherDeleted,
      otherPhoto,
      activeSeconds: currentActiveSeconds,
      roomStatus: room.status, // To know if timer should run client-side
      isLoggedIn: !!req.session.userId,
      messages: msgRes.rows || []
    });

  } catch (err) {
    console.error("[API Chat Info] Error Details:", err);
    res.status(500).json({ error: "Server Error: " + err.message });
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

  socket.on('send-image', ({ room_id, sender, base64 }) => {
    // Just broadcast, NO DB SAVE
    io.to(`room_${room_id}`).emit('new-image', { sender, base64 });
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

        // NOTIFY DASHBOARD (Real-time Preview)
        // We do this here after successful processing
        // NOTIFY DASHBOARD (Real-time Preview)
        // We do this here after successful processing
        try {
          // Notify both the Owner AND any Cupidos with shared access
          const cRes = await pool.query(`
            SELECT cupido_id FROM rooms WHERE id = $1
            UNION
            SELECT cupido_id FROM user_rooms WHERE room_id = $1
          `, [room_id]);

          cRes.rows.forEach(row => {
            io.to(`dashboard_${row.cupido_id}`).emit('preview-update', {
              room_id: room_id,
              text: type === 'image' ? '📷 Imagen' : text,
              sender: sender
            });
          });
        } catch (ignore) { }

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
      // FIX: Only clear if this socket is the one actively holding the slot
      if (roomStatus[socket.room_id][socket.sender] === socket.id) {
        roomStatus[socket.room_id][socket.sender] = null;
        updateAndNotifyStatus(socket.room_id, socket.cupido_id);
      }
    }
    if (socket.isBlinder && socket.userId) {
      const stored = connectedBlinders.get(socket.userId);
      if (stored && stored.socketId === socket.id) {
        connectedBlinders.delete(socket.userId);
        if (socket.blinderCupidoId) {
          io.to(`dashboard_${socket.blinderCupidoId}`).emit('blinder-status', { blinderId: socket.userId, isConnected: false });
        }
      }
    }
  });
});

// ---------------- PROFILE EDITING ----------------

app.get('/api/user/profile', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const role = req.session.userRole;
  try {
    const userRes = await pool.query("SELECT email, username FROM cupidos WHERE id = $1", [userId]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    let profile = {};
    if (role === 'blinder') {
      const pRes = await pool.query("SELECT full_name, tel, photo_url FROM blinder_profiles WHERE user_id = $1", [userId]);
      if (pRes.rows.length > 0) profile = pRes.rows[0];
    } else {
      const pRes = await pool.query("SELECT full_name, tel, city, age FROM cupido_profiles WHERE user_id = $1", [userId]);
      if (pRes.rows.length > 0) profile = pRes.rows[0];
    }

    res.json({
      email: user.email,
      username: user.username,
      full_name: profile.full_name || '',
      tel: profile.tel || '',
      photo_url: profile.photo_url || ''
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error fetch profile" });
  }
});

app.post('/api/user/profile', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const role = req.session.userRole;
  const { full_name, email, tel, photo_url } = req.body;

  if (!email || !full_name) return res.status(400).json({ error: "Nombre y email requeridos" });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Update User (check uniqueness of email first if changed?)
    // Simplified: optimistic update
    await client.query("UPDATE cupidos SET email = $1 WHERE id = $2", [email, userId]);

    // 2. Update Profile
    if (role === 'blinder') {
      // Upsert logic or assume exists
      const pRes = await client.query("UPDATE blinder_profiles SET full_name = $1, tel = $2, photo_url = $3 WHERE user_id = $4",
        [full_name, tel, photo_url, userId]);
      if (pRes.rowCount === 0) {
        // Insert if missing (unlikely)
        await client.query("INSERT INTO blinder_profiles (user_id, full_name, tel, photo_url) VALUES ($1, $2, $3, $4)",
          [userId, full_name, tel, photo_url]);
      }
    } else {
      await client.query("UPDATE cupido_profiles SET full_name = $1, tel = $2 WHERE user_id = $3",
        [full_name, tel, userId]);
    }

    await client.query('COMMIT');
    res.json({ message: "Perfil actualizado" });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    if (err.code === '23505') return res.status(400).json({ error: "El email ya está en uso" });
    res.status(500).json({ error: "Error updating profile" });
  } finally {
    client.release();
  }
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

  // Webhook GitHub Auto-Deploy
  app.post('/webhook-deploy', express.raw({ type: 'application/json' }), async (req, res) => {
    try {
      console.log("🔄 Webhook Triggered: Deploying...");
      execSync('cd ~/APPcitas && ~/deploy.sh', { stdio: 'inherit' });
      res.json({ success: true, message: 'Deployed OK' });
    } catch (e) {
      console.error("❌ Deploy Error:", e);
      res.status(500).json({ error: e.message });
    }
  });

  // Init DB in background with readiness flag
  let isDbReady = false;

  // Middleware to check readiness (Optional: Apply to /api routes only or all)
  app.use((req, res, next) => {
    if (!isDbReady && req.path.startsWith('/api/') && req.path !== '/healthz') {
      return res.status(503).json({ error: 'Server warming up, please retry in a moment.' });
    }
    next();
  });

  // Start Server immediately (Optimistic Start)
  server.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Cupido's Project LIVE on PORT ${port}`);
    console.log(`🔗 Interface available on http://0.0.0.0:${port}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  });

  // Execute Init
  initDb().then(async () => {
    isDbReady = true;
    console.log("✅ initDb() completed. API is ready.");
    // Clear stale statuses
    try {
      await pool.query("UPDATE rooms SET active_since = NULL");
    } catch (e) {
      console.warn("Could not clear stale rooms:", e.message);
    }
  }).catch(err => {
    console.error("❌ FATAL DB ERROR (Background):", err);
    // In production, keep running for static files, but API will stay 503
  });

})();
