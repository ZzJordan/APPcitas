require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const { db, initDb } = require('./db');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// Error Handling to prevent silent crashes
process.on('uncaughtException', (err) => {
  console.error('❌ CRITICAL: Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});

server.on('error', (err) => {
  console.error('❌ SERVER ERROR:', err);
});


// Initialize Socket.io with broad CORS for production flexibility
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Trust Proxy is ESSENTIAL for Railway/Heroku/Vercel with 'secure: true' cookies
app.set('trust proxy', 1);

// FAST Health Check - Moved to top to respond before heavy middleware
app.get('/healthz', (req, res) => {
  console.log('💓 Health Check triggered');
  res.status(200).send('OK');
});
app.get('/ping', (req, res) => res.status(200).send('pong'));


// Production Security, Logging, and Performance
app.use(morgan('dev')); // 'dev' is better for live debugging
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

// Session Store (Persistent)
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    table: 'sessions',
    dir: path.join(__dirname)
  }),
  secret: process.env.SESSION_SECRET || 'cupidos-project-2026',
  resave: false,
  saveUninitialized: true,
  name: 'cupido.sid', // Custom cookie name
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    httpOnly: true
  }
}));

// --- Presence Logic ---
const roomStatus = {};

function updateAndNotifyStatus(room_id, cupido_id) {
  if (!room_id || !cupido_id) return;

  db.get("SELECT active_since FROM rooms WHERE id = ?", [room_id], (err, row) => {
    if (err) return console.error("Error fetching room status:", err);

    const currentActiveSince = row ? row.active_since : null;
    const statusObj = roomStatus[room_id];
    let statusText = 'pendiente';

    const isNowActive = (statusObj && statusObj.A && statusObj.B);

    if (isNowActive) {
      statusText = 'activo';
    } else if (statusObj && statusObj.A) {
      statusText = 'A conectado';
    } else if (statusObj && statusObj.B) {
      statusText = 'B conectado';
    } else if (statusObj) {
      statusText = 'desconectado';
    }

    const now = Date.now();

    if (isNowActive && !currentActiveSince) {
      db.run("UPDATE rooms SET status = ?, active_since = ? WHERE id = ?", [statusText, now, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: now });
    } else if (!isNowActive && currentActiveSince) {
      const duration = Math.floor((now - currentActiveSince) / 1000);
      db.run(
        "UPDATE rooms SET status = ?, active_since = NULL, total_active_seconds = total_active_seconds + ? WHERE id = ?",
        [statusText, duration, room_id]
      );
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: null, added_seconds: duration });
    } else {
      db.run("UPDATE rooms SET status = ? WHERE id = ?", [statusText, room_id]);
      io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
    }

    io.to(`room_${room_id}`).emit('presence-update', {
      A: !!(statusObj && statusObj.A),
      B: !!(statusObj && statusObj.B)
    });
  });
}

// Auth Middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();
  res.redirect('/login');
};

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole === 'blinder') return res.redirect('/blinder-matches');
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

app.get('/join/blinder/:token', (req, res) => {
  const { token } = req.params;
  db.get("SELECT * FROM invite_tokens WHERE token = ? AND expires_at > DATETIME('now')", [token], (err, row) => {
    if (err || !row) return res.status(404).send("Invitación inválida o expirada.");
    res.sendFile(path.join(__dirname, 'public', 'join-blinder.html'));
  });
});



// API
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM cupidos WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).json({ error: "Error en el servidor" });
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.userRole = user.role || 'cupido';
      res.status(200).json({ message: "Login exitoso", role: req.session.userRole });
    } else {
      res.status(401).json({ error: "Contraseña incorrecta" });
    }
  });
});


app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.status(200).json({ message: "Sesión cerrada" });
});

app.get('/api/user', isAuthenticated, (req, res) => {
  res.json({ username: req.session.username, userId: req.session.userId, role: req.session.userRole });
});


app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  const userRole = role === 'blinder' ? 'blinder' : 'cupido';
  if (!username || !password) return res.status(400).json({ error: "Datos incompletos" });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO cupidos (username, password, role) VALUES (?, ?, ?)", [username, hashedPassword, userRole], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) return res.status(400).json({ error: "El usuario ya existe" });
        return res.status(500).json({ error: "Error al registrar" });
      }
      req.session.userId = this.lastID;
      req.session.username = username;
      req.session.userRole = userRole;
      res.status(201).json({ message: "Registro exitoso", role: userRole });
    });
  } catch (err) { res.status(500).json({ error: "Error en el servidor" }); }
});


app.post('/api/rooms', isAuthenticated, (req, res) => {
  // Solo cupidos pueden crear salas (o blinders si se permite, pero por ahora seguimos lógica previa)
  const { friendA_name, friendB_name, noteA, noteB } = req.body;
  const cupido_id = req.session.userId;
  const linkA = crypto.randomUUID();
  const linkB = crypto.randomUUID();
  db.run(
    `INSERT INTO rooms (cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB],
    function (err) {
      if (err) return res.status(500).json({ error: "Error al crear la sala" });
      res.status(201).json({ id: this.lastID, linkA, linkB });
    }
  );
});

// FEATURE: CUPIDO CONTACTS
app.post('/api/cupido/contacts', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const { name, tel, city, age } = req.body;
  if (!name || !tel) return res.status(400).json({ error: "Nombre y teléfono requeridos" });

  // Privacy: Hash the phone number
  const tel_hash = crypto.createHash('sha256').update(tel).digest('hex');
  const tel_last4 = tel.slice(-4);

  db.run(
    "INSERT INTO solteros (cupido_id, name, tel_hash, tel_last4, city, age) VALUES (?, ?, ?, ?, ?, ?)",
    [req.session.userId, name, tel_hash, tel_last4, city || 'Desconocida', age || 0],
    function (err) {
      if (err) return res.status(500).json({ error: "Error al guardar contacto" });
      res.status(201).json({ id: this.lastID, message: "Contacto guardado" });
    }
  );
});

// FEATURE: CUPIDO INVITE & BLINDER REVEAL
app.get('/api/cupido/invite', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No autorizado" });
  const token = crypto.randomUUID();
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  db.run("INSERT INTO invite_tokens (cupido_id, token, expires_at) VALUES (?, ?, ?)", [req.session.userId, token, expires], function (err) {
    if (err) return res.status(500).json({ error: "Error" });
    const host = req.get('host');
    const protocol = req.protocol;
    const url = `${protocol}://${host}/join/blinder/${token}`;
    res.json({ token, url });
  });
});

app.post('/api/blinder/register-join', async (req, res) => {
  const { username, password, token, fullName, age, city, tagline, photo, tel } = req.body;

  db.get("SELECT id FROM blinder_profiles WHERE tel = ?", [tel], (err, existingTel) => {
    if (existingTel) return res.status(400).json({ error: "Este número de teléfono ya está registrado" });

    db.get("SELECT cupido_id FROM invite_tokens WHERE token = ? AND expires_at > DATETIME('now')", [token], async (err, invite) => {
      if (err || !invite) return res.status(400).json({ error: "Token inválido o expirado" });

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.serialize(() => {
          db.run("BEGIN TRANSACTION");
          db.run("INSERT INTO cupidos (username, password, role) VALUES (?, ?, 'blinder')", [username, hashedPassword], function (err) {
            if (err) {
              db.run("ROLLBACK");
              return res.status(400).json({ error: "El nombre de usuario ya existe" });
            }
            const userId = this.lastID;
            db.run(
              `INSERT INTO blinder_profiles (user_id, cupido_id, full_name, age, city, tagline, photo_url, tel) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
              [userId, invite.cupido_id, fullName, age, city, tagline, photo || '', tel],
              function (err) {
                if (err) {
                  db.run("ROLLBACK");
                  return res.status(500).json({ error: "Error al crear el perfil" });
                }
                db.run("COMMIT");
                req.session.userId = userId;
                req.session.username = username;
                req.session.userRole = 'blinder';
                res.status(201).json({ message: "OK", role: 'blinder' });
              }
            );
          });
        });
      } catch (err) { res.status(500).json({ error: "Error interno del servidor" }); }
    });
  });
});

function getRevealLevel(createdAt) {
  const diff = (Date.now() - new Date(createdAt).getTime()) / 1000 / 60; // minutes
  if (diff >= 30) return 3; // Bio, Tel, Age
  if (diff >= 15) return 2; // Photo
  return 1; // Name, Tagline
}

app.get('/api/blinder/dashboard', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'blinder') return res.status(403).json({ error: "No" });
  db.get(`
    SELECT c.username as cupido_name, p.created_at
    FROM blinder_profiles p JOIN cupidos c ON p.cupido_id = c.id
    WHERE p.user_id = ?`, [req.session.userId], (err, data) => {
    if (err || !data) return res.status(404).json({ error: "Not found" });
    const level = getRevealLevel(data.created_at);
    res.json({ ...data, revealLevel: level });
  });
});

app.get('/api/cupido/blinders', isAuthenticated, (req, res) => {
  if (req.session.userRole !== 'cupido') return res.status(403).json({ error: "No" });
  db.all(`SELECT p.*, c.username FROM blinder_profiles p JOIN cupidos c ON p.user_id = c.id WHERE p.cupido_id = ?`, [req.session.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error" });
    const enriched = rows.map(r => ({ ...r, revealLevel: getRevealLevel(r.created_at) }));
    res.json(enriched);
  });
});

app.post('/api/user/delete-account', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  const role = req.session.userRole;

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");

    if (role === 'blinder') {
      db.run("DELETE FROM blinder_profiles WHERE user_id = ?", [userId]);
      db.run("DELETE FROM cupidos WHERE id = ?", [userId]);
    } else {
      // Cupido: delete everything he created
      db.run("DELETE FROM invite_tokens WHERE cupido_id = ?", [userId]);
      db.run("DELETE FROM solteros WHERE cupido_id = ?", [userId]);
      db.run("DELETE FROM blinder_profiles WHERE cupido_id = ?", [userId]); // (Optional: depends on business logic, here we delete their connection to him)
      db.run("DELETE FROM user_rooms WHERE cupido_id = ?", [userId]);
      db.run("DELETE FROM rooms WHERE cupido_id = ?", [userId]);
      db.run("DELETE FROM cupidos WHERE id = ?", [userId]);
    }

    db.run("COMMIT", (err) => {
      if (err) return res.status(500).json({ error: "Error al borrar cuenta" });
      req.session.destroy();
      res.json({ message: "Cuenta borrada con éxito" });
    });
  });
});




app.get('/api/rooms', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  db.all(`SELECT * FROM rooms WHERE cupido_id = ? ORDER BY created_at DESC`, [userId], (err, owned) => {
    if (err) return res.status(500).json({ error: "Error" });
    const enrichedOwned = owned.map(r => ({ ...r, linkA_used: !!r.linkA_session, linkB_used: !!r.linkB_session }));
    db.all(`
      SELECT r.*, ur.role as accessed_role, ur.accessed_at
      FROM rooms r JOIN user_rooms ur ON r.id = ur.room_id
      WHERE ur.cupido_id = ? AND r.cupido_id != ?
      ORDER BY ur.accessed_at DESC`, [userId, userId], (err, accessed) => {
      res.json({ owned: enrichedOwned, accessed: accessed || [] });
    });
  });
});

app.delete('/api/rooms/:id', isAuthenticated, (req, res) => {
  const roomId = req.params.id;
  const cupido_id = req.session.userId;
  db.run("DELETE FROM rooms WHERE id = ? AND cupido_id = ?", [roomId, cupido_id], function (err) {
    if (err || this.changes === 0) return res.status(403).json({ error: "Error" });
    db.run("DELETE FROM messages WHERE room_id = ?", [roomId]);
    db.run("DELETE FROM user_rooms WHERE room_id = ?", [roomId]);
    res.json({ message: "Borrado" });
  });
});

app.post('/api/request-new-link', (req, res) => {
  const { oldLink } = req.body;
  db.get("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = ? OR linkB = ?", [oldLink, oldLink], (err, room) => {
    if (err || !room) return res.status(404).json({ error: "No encontrado" });
    const isA = (oldLink === room.linkA);
    const newLink = crypto.randomUUID();
    const linkField = isA ? 'linkA' : 'linkB';
    const sessionField = isA ? 'linkA_session' : 'linkB_session';
    db.run(`UPDATE rooms SET ${linkField} = ?, ${sessionField} = NULL WHERE id = ?`, [newLink, room.id], (err) => {
      if (err) return res.status(500).json({ error: "Error" });
      io.to(`dashboard_${room.cupido_id}`).emit('link-regenerated', { room_id: room.id, role: isA ? 'A' : 'B', new_link: newLink });
      res.json({ message: "OK" });
    });
  });
});

app.get('/chat/:link', (req, res) => {
  const { link } = req.params;
  db.get("SELECT * FROM rooms WHERE linkA = ? OR linkB = ?", [link, link], (err, room) => {
    if (err || !room) return res.sendFile(path.join(__dirname, 'public', 'chat.html'));
    const isA = (link === room.linkA);
    const sessionField = isA ? 'linkA_session' : 'linkB_session';
    const cookieName = `chat_token_${room.id}_${isA ? 'A' : 'B'}`;
    const clientToken = req.headers.cookie?.split('; ').find(row => row.startsWith(cookieName))?.split('=')[1];

    if (!room[sessionField]) {
      const newToken = crypto.randomUUID();
      db.run(`UPDATE rooms SET ${sessionField} = ? WHERE id = ?`, [newToken, room.id], () => {
        res.setHeader('Set-Cookie', `${cookieName}=${newToken}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
        res.sendFile(path.join(__dirname, 'public', 'chat.html'));
      });
    } else if (clientToken === room[sessionField]) {
      res.sendFile(path.join(__dirname, 'public', 'chat.html'));
    } else {
      res.sendFile(path.join(__dirname, 'public', 'chat.html'));
    }
  });
});

app.get('/api/chat-info/:link', (req, res) => {
  const { link } = req.params;
  db.get(`SELECT id as room_id, friendA_name, friendB_name, linkA, linkB, cupido_id FROM rooms WHERE linkA = ? OR linkB = ?`, [link, link], (err, room) => {
    if (err || !room) return res.status(404).json({ error: "No" });
    const sender = (link === room.linkA) ? 'A' : 'B';
    const otherRole = (sender === 'A') ? 'B' : 'A';
    const statusObj = roomStatus[room.room_id] || { A: null, B: null };
    db.all("SELECT sender, text, timestamp FROM messages WHERE room_id = ? ORDER BY timestamp ASC", [room.room_id], (err, messages) => {
      res.json({
        room_id: room.room_id, sender, myName: sender === 'A' ? room.friendA_name : room.friendB_name,
        otherName: sender === 'A' ? room.friendB_name : room.friendA_name, otherRole,
        otherConnected: !!statusObj[otherRole], isLoggedIn: !!req.session.userId, messages: messages || []
      });
    });
  });
});

// Socket.io initialization
io.on('connection', (socket) => {
  socket.on('join-dashboard', ({ cupido_id }) => { socket.join(`dashboard_${cupido_id}`); });
  socket.on('join-room', ({ link }) => {
    db.get("SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = ? OR linkB = ?", [link, link], (err, room) => {
      if (err || !room) return;
      socket.join(`room_${room.id}`);
      socket.room_id = room.id;
      socket.sender = (link === room.linkA) ? 'A' : 'B';
      socket.cupido_id = room.cupido_id;
      if (!roomStatus[room.id]) roomStatus[room.id] = { A: null, B: null };
      roomStatus[room.id][socket.sender] = socket.id;
      updateAndNotifyStatus(room.id, room.cupido_id);
      socket.to(`room_${room.id}`).emit('user_joined', { role: socket.sender });
    });
  });

  socket.on('send-message', ({ room_id, sender, text }) => {
    db.run("INSERT INTO messages (room_id, sender, text) VALUES (?, ?, ?)", [room_id, sender, text], function (err) {
      if (err) return;
      io.to(`room_${room_id}`).emit('new-message', { sender, text, timestamp: new Date().toISOString() });
    });
  });

  socket.on('disconnect', () => {
    if (socket.room_id && socket.sender && roomStatus[socket.room_id]) {
      roomStatus[socket.room_id][socket.sender] = null;
      updateAndNotifyStatus(socket.room_id, socket.cupido_id);
    }
  });
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

(async () => {
  console.log("🌀 Starting server process...");
  console.log(`ENV PORT check: ${rawPort ? 'Found: ' + rawPort : 'Not found, using fallback'}`);

  try {
    await initDb();
    console.log("✅ initDb() completed.");

    db.run("UPDATE rooms SET active_since = NULL", (err) => {
      if (err) console.error("⚠️ Error clearing active_since:", err);
    });

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
