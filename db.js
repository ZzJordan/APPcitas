require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, process.env.DB_PATH || 'database.sqlite');
const db = new sqlite3.Database(dbPath);

const initDb = () => {
    console.log("🗄️ Initializing database...");
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            try {
                // 1. Table: cupidos
                db.run(`CREATE TABLE IF NOT EXISTS cupidos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'cupido'
                )`, (err) => {
                    if (!err) {
                        db.run("ALTER TABLE cupidos ADD COLUMN role TEXT DEFAULT 'cupido'", () => { });
                    }
                });

                // 2. Table: rooms
                db.run(`CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cupido_id INTEGER,
                    friendA_name TEXT,
                    friendB_name TEXT,
                    noteA TEXT,
                    noteB TEXT,
                    linkA TEXT UNIQUE,
                    linkB TEXT UNIQUE,
                    linkA_session TEXT,
                    linkB_session TEXT,
                    status TEXT DEFAULT 'pendiente',
                    active_since INTEGER,
                    total_active_seconds INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
                )`, (err) => {
                    if (err) console.error("❌ Error creating rooms table:", err);

                    // Manual migrations
                    db.run("ALTER TABLE rooms ADD COLUMN active_since INTEGER", () => { });
                    db.run("ALTER TABLE rooms ADD COLUMN total_active_seconds INTEGER DEFAULT 0", () => { });
                    db.run("ALTER TABLE rooms ADD COLUMN linkA_session TEXT", () => { });
                    db.run("ALTER TABLE rooms ADD COLUMN linkB_session TEXT", () => { });
                });

                // 3. Table: invite_tokens
                db.run(`CREATE TABLE IF NOT EXISTS invite_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cupido_id INTEGER,
                    token TEXT UNIQUE,
                    expires_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
                )`);

                // 4. Table: blinder_profiles
                db.run(`CREATE TABLE IF NOT EXISTS blinder_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    cupido_id INTEGER,
                    full_name TEXT,
                    age INTEGER,
                    city TEXT,
                    tagline TEXT,
                    photo_url TEXT,
                    tel TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES cupidos(id),
                    FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
                )`);

                // 5. Table: solteros
                db.run(`CREATE TABLE IF NOT EXISTS solteros (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cupido_id INTEGER,
                    name TEXT,
                    tel_hash TEXT,
                    tel_last4 TEXT,
                    city TEXT,
                    age INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
                )`);

                // 6. Table: messages
                db.run(`CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER,
                    sender TEXT,
                    text TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                )`);

                // 5. Table: user_rooms
                db.run(`CREATE TABLE IF NOT EXISTS user_rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cupido_id INTEGER,
                    room_id INTEGER,
                    role TEXT,
                    accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cupido_id) REFERENCES cupidos(id),
                    FOREIGN KEY (room_id) REFERENCES rooms(id),
                    UNIQUE(cupido_id, room_id)
                )`);

                // 6. Default Users
                db.get("SELECT id FROM cupidos LIMIT 1", async (err, row) => {
                    if (err) {
                        console.error("❌ Error checking users:", err);
                        return resolve(); // Resolve anyway to start server
                    }
                    if (!row) {
                        try {
                            const pass = process.env.DEFAULT_USER_PASSWORD || '1234';
                            const hashedPassword = await bcrypt.hash(pass, 10);
                            db.run("INSERT OR IGNORE INTO cupidos (username, password, role) VALUES (?, ?, ?)", ['cupido1', hashedPassword, 'cupido']);
                            db.run("INSERT OR IGNORE INTO cupidos (username, password, role) VALUES (?, ?, ?)", ['cupido2', hashedPassword, 'cupido']);
                            console.log("✅ Default users created safely.");
                        } catch (hashErr) {
                            console.error("❌ Error hashing password:", hashErr);
                        }
                    }
                    console.log("✅ Database tables confirmed.");
                    resolve();
                });
            } catch (err) {
                console.error("❌ Critical error during DB init:", err);
                reject(err);
            }
        });
    });
};

module.exports = { db, initDb };
