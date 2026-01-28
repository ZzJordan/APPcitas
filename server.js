const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const { db, initDb } = require('./db');
const http = require('http');
const socketIo = require('socket.io'); // Changed from { Server } to socketIo

const app = express();
const server = http.createServer(app);
const io = socketIo(server); // Changed to use socketIo directly
const crypto = require('crypto');

function getFingerprint(req) {
  const ua = req.headers['user-agent'] || '';
  const hash = crypto.createHash('md5').update(ua).digest('hex').substring(0, 10);
  return `${req.sessionID}_${hash}`;
}

// Initialize Database
(async () => {
  try {
    await initDb();
    console.log("Database initialized successfully.");
  } catch (err) {
    console.error("Failed to initialize database:", err);
  }
})();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'cupido-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

// Auth Middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Existing Route (Preserved)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auth Routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM cupidos WHERE username = ?", [username], async (err, user) => {
    if (err) return res.status(500).json({ error: "Error en el servidor" });
    if (!user) return res.status(401).json({ error: "Usuario no encontrado" });

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user.id;
      req.session.username = user.username;
      res.status(200).json({ message: "Login exitoso" });
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
  res.json({ username: req.session.username, userId: req.session.userId });
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Datos incompletos" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO cupidos (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) return res.status(400).json({ error: "El usuario ya existe" });
        return res.status(500).json({ error: "Error al registrar" });
      }
      req.session.userId = this.lastID;
      req.session.username = username;
      res.status(201).json({ message: "Registro exitoso" });
    });
  } catch (err) {
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Room Management Routes
app.post('/api/rooms', isAuthenticated, (req, res) => {
  const { friendA_name, friendB_name, noteA, noteB } = req.body;
  const cupido_id = req.session.userId;
  const linkA = require('crypto').randomUUID();
  const linkB = require('crypto').randomUUID();

  db.run(
    `INSERT INTO rooms (cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB) 
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [cupido_id, friendA_name, friendB_name, noteA, noteB, linkA, linkB],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Error al crear la sala" });
      }
      res.status(201).json({ id: this.lastID, linkA, linkB });
    }
  );
});

app.get('/api/rooms', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  // Get rooms created by the user
  const ownedQuery = `SELECT * FROM rooms WHERE cupido_id = ? ORDER BY created_at DESC`;
  // Get rooms accessed (shared with) the user
  const accessedQuery = `
    SELECT r.*, ur.role as accessed_role, ur.accessed_at
    FROM rooms r
    JOIN user_rooms ur ON r.id = ur.room_id
    WHERE ur.cupido_id = ? AND r.cupido_id != ?
    ORDER BY ur.accessed_at DESC
  `;

  db.all(ownedQuery, [userId], (err, owned) => {
    if (err) return res.status(500).json({ error: "Error al obtener salas" });

    // Add info about used links
    const enrichedOwned = owned.map(room => ({
      ...room,
      linkA_used: !!room.linkA_session,
      linkB_used: !!room.linkB_session
    }));

    db.all(accessedQuery, [userId, userId], (err, accessed) => {
      if (err) return res.status(500).json({ error: "Error al obtener chats" });
      res.json({ owned: enrichedOwned, accessed });
    });
  });
});

app.delete('/api/rooms/:id', isAuthenticated, (req, res) => {
  const roomId = req.params.id;
  const cupido_id = req.session.userId;

  // Verify ownership and delete
  db.run("DELETE FROM rooms WHERE id = ? AND cupido_id = ?", [roomId, cupido_id], function (err) {
    if (err) return res.status(500).json({ error: "Error al borrar sala" });
    if (this.changes === 0) return res.status(403).json({ error: "No autorizado" });

    // Also delete messages and access records
    db.run("DELETE FROM messages WHERE room_id = ?", [roomId]);
    db.run("DELETE FROM user_rooms WHERE room_id = ?", [roomId]);
    res.json({ message: "Sala borrada" });
  });
});

// Protected Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// --- CHAT ROUTES ---

app.post('/api/request-new-link', (req, res) => {
  // This endpoint is public because the user is blocked from the chat, 
  // but they have the "old" link as proof of knowing the URL.
  const { oldLink } = req.body;

  db.get(
    "SELECT id, cupido_id, linkA, linkB, created_at FROM rooms WHERE linkA = ? OR linkB = ?",
    [oldLink, oldLink],
    (err, room) => {
      if (err || !room) return res.status(404).json({ error: "Link no encontrado" });

      const isA = (oldLink === room.linkA);
      const newLink = require('crypto').randomUUID();
      const linkField = isA ? 'linkA' : 'linkB';
      const sessionField = isA ? 'linkA_session' : 'linkB_session';

      // Update DB: Set new link, clear session (so new user can claim it)
      db.run(
        `UPDATE rooms SET ${linkField} = ?, ${sessionField} = NULL WHERE id = ?`,
        [newLink, room.id],
        function (err) {
          if (err) return res.status(500).json({ error: "Error al generar" });

          // Notify Cupido Dashboard
          io.to(`dashboard_${room.cupido_id}`).emit('link-regenerated', {
            room_id: room.id,
            role: isA ? 'A' : 'B',
            new_link: newLink
          });

          res.json({ message: "Link regenerado" });
        }
      );
    }
  );
});

// Render Chat Page
app.get('/chat/:link', (req, res) => {
  const { link } = req.params;
  const ua = req.headers['user-agent'] || '';
  const isBot = /bot|facebookexternalhit|whatsapp|telegrambot|slackbot|twitterbot|spider|crawl|externalhit/i.test(ua);

  // Parse cookies
  const parseCookies = (header) => {
    const list = {};
    if (!header) return list;
    header.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
    return list;
  };

  db.get(
    "SELECT * FROM rooms WHERE linkA = ? OR linkB = ?",
    [link, link],
    (err, room) => {
      if (err || !room) return res.sendFile(path.join(__dirname, 'public', 'chat.html'));

      // Check Expiration (24h)
      const created = new Date(room.created_at).getTime();
      const now = Date.now();
      const hoursDiff = (now - created) / (1000 * 60 * 60);

      if (hoursDiff > 24) {
        // Frontend handles 403/404 from API
        return res.sendFile(path.join(__dirname, 'public', 'chat.html'));
      }

      const isA = (link === room.linkA);
      const sessionField = isA ? 'linkA_session' : 'linkB_session';
      const currentTokenInDb = room[sessionField];

      const cookieName = `chat_token_${room.id}_${isA ? 'A' : 'B'}`;
      const cookies = parseCookies(req.headers.cookie);
      const clientToken = cookies[cookieName];

      if (!currentTokenInDb) {
        if (!isBot) {
          // First access! Claim it.
          const newToken = require('crypto').randomUUID();
          db.run(`UPDATE rooms SET ${sessionField} = ? WHERE id = ?`, [newToken, room.id], (err) => {
            res.setHeader('Set-Cookie', `${cookieName}=${newToken}; Path=/; Max-Age=31536000; HttpOnly`);
            res.sendFile(path.join(__dirname, 'public', 'chat.html'));
          });
        } else {
          res.sendFile(path.join(__dirname, 'public', 'chat.html'));
        }
      } else {
        // Already claimed
        if (clientToken === currentTokenInDb || isBot) {
          res.sendFile(path.join(__dirname, 'public', 'chat.html'));
        } else {
          // Blocked - Serve HTML so frontend shows "Request New Link" overlay
          res.sendFile(path.join(__dirname, 'public', 'chat.html'));
        }
      }
    }
  );
});

// API to get chat info (for the frontend)
app.get('/api/chat-info/:link', (req, res) => {
  const { link } = req.params;
  const userId = req.session.userId;

  db.get(
    `SELECT id as room_id, friendA_name, friendB_name, linkA, linkB, cupido_id 
     FROM rooms WHERE linkA = ? OR linkB = ?`,
    [link, link],
    (err, room) => {
      if (err || !room) return res.status(404).json({ error: "No encontrado" });

      const sender = (link === room.linkA) ? 'A' : 'B';
      const myName = (sender === 'A') ? room.friendA_name : room.friendB_name;
      const otherName = (sender === 'A') ? room.friendB_name : room.friendA_name;
      const otherRole = (sender === 'A') ? 'B' : 'A';

      // If logged in AND not the owner, track this room as "Accessed/Shared"
      if (userId && userId !== room.cupido_id) {
        db.run(
          "INSERT OR REPLACE INTO user_rooms (cupido_id, room_id, role) VALUES (?, ?, ?)",
          [userId, room.room_id, sender]
        );
      }

      // Check real-time presence
      const statusObj = roomStatus[room.room_id] || { A: null, B: null };
      const otherConnected = !!statusObj[otherRole];

      db.all(
        "SELECT sender, text, timestamp FROM messages WHERE room_id = ? ORDER BY timestamp ASC",
        [room.room_id],
        (err, messages) => {
          res.json({
            room_id: room.room_id,
            sender: sender,
            myName: myName,
            otherName: otherName,
            otherRole: otherRole,
            otherConnected: otherConnected,
            isLoggedIn: !!userId,
            messages: messages || []
          });
        }
      );
    }
  );
});

// --- SOCKET.IO LOGIC ---
const roomStatus = {}; // { room_id: { A: socketId, B: socketId } }

io.on('connection', (socket) => {
  console.log('Usuario conectado:', socket.id);

  // Cupido joining their dashboard room
  socket.on('join-dashboard', ({ cupido_id }) => {
    socket.join(`dashboard_${cupido_id}`);
    console.log(`Cupido ${cupido_id} unido a su dashboard`);
  });

  socket.on('join-room', ({ link }) => {
    db.get(
      "SELECT id, cupido_id, linkA, linkB FROM rooms WHERE linkA = ? OR linkB = ?",
      [link, link],
      (err, room) => {
        if (err || !room) return;

        const room_id = room.id;
        const sender = (link === room.linkA) ? 'A' : 'B';

        socket.join(`room_${room_id}`);
        socket.room_id = room_id;
        socket.sender = sender;
        socket.cupido_id = room.cupido_id;

        if (!roomStatus[room_id]) roomStatus[room_id] = { A: null, B: null };
        roomStatus[room_id][sender] = socket.id;

        updateAndNotifyStatus(room_id, room.cupido_id);

        // Notify others in room
        socket.to(`room_${room_id}`).emit('user_joined', { role: sender });
      }
    );
  });


  // Clean up stalled active sessions on restart
  db.run("UPDATE rooms SET active_since = NULL");

  function updateAndNotifyStatus(room_id, cupido_id) {
    db.get("SELECT active_since FROM rooms WHERE id = ?", [room_id], (err, row) => {
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

      // Time Tracking Logic
      if (isNowActive && !currentActiveSince) {
        // Just became active -> Start timer
        const now = Date.now();
        db.run("UPDATE rooms SET status = ?, active_since = ? WHERE id = ?", [statusText, now, room_id]);

        // Notify Dashboard immediately
        io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
        io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: now });

      } else if (!isNowActive && currentActiveSince) {
        // Stopped being active -> Stop timer and accumulate
        const now = Date.now();
        const duration = Math.floor((now - currentActiveSince) / 1000);
        db.run(
          "UPDATE rooms SET status = ?, active_since = NULL, total_active_seconds = total_active_seconds + ? WHERE id = ?",
          [statusText, duration, room_id]
        );

        // Notify Dashboard
        io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
        // We send active_since: null so client knows to stop counting
        // We also should technically send the new total, but client can refetch or just stop. 
        // Let's send a specific event or just let the client refresh if they want precise exactness,
        // but for smooth UI, sending null active_since stops the counter.
        io.to(`dashboard_${cupido_id}`).emit('time-update', { room_id, active_since: null, added_seconds: duration });

      } else {
        // Status changed but not related to active/inactive transition (e.g. A connected -> B connected but A left)
        // Or just refreshing state
        db.run("UPDATE rooms SET status = ? WHERE id = ?", [statusText, room_id]);
        io.to(`dashboard_${cupido_id}`).emit('status-change', { room_id, status: statusText });
      }

      // Notify the room itself for real-time presence indicators
      io.to(`room_${room_id}`).emit('presence-update', {
        A: !!(statusObj && statusObj.A),
        B: !!(statusObj && statusObj.B)
      });
    });
  }

  socket.on('send-message', ({ room_id, sender, text }) => {
    if (!text || text.trim() === '') return;

    // Save to DB
    db.run(
      "INSERT INTO messages (room_id, sender, text) VALUES (?, ?, ?)",
      [room_id, sender, text],
      function (err) {
        if (err) return console.error("Error guardando mensaje:", err);

        // Broadcast to room
        io.to(`room_${room_id}`).emit('new-message', {
          sender: sender,
          text: text,
          timestamp: new Date().toISOString()
        });
      }
    );
  });

  socket.on('disconnect', () => {
    if (socket.room_id && socket.sender) {
      if (roomStatus[socket.room_id]) {
        roomStatus[socket.room_id][socket.sender] = null;
        updateAndNotifyStatus(socket.room_id, socket.cupido_id);

        // Notify others in room
        io.to(`room_${socket.room_id}`).emit('user_left', { role: socket.sender });
      }
    }
    console.log('Usuario desconectado:', socket.id);
  });
});

const port = 3000;
server.listen(port, () => console.log(`🚀 http://localhost:${port}`));
