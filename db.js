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
                    password TEXT
                )`);

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

                // 3. Table: messages
                db.run(`CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER,
                    sender TEXT, 
                    text TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (room_id) REFERENCES rooms(id)
                )`);

                // 4. Table: user_rooms
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

                // 5. Default Users
                db.get("SELECT id FROM cupidos LIMIT 1", async (err, row) => {
                    if (err) {
                        console.error("❌ Error checking users:", err);
                        return resolve(); // Resolve anyway to start server
                    }
                    if (!row) {
                        try {
                            const pass = process.env.DEFAULT_USER_PASSWORD || '1234';
                            const hashedPassword = await bcrypt.hash(pass, 10);
                            db.run("INSERT OR IGNORE INTO cupidos (username, password) VALUES (?, ?)", ['cupido1', hashedPassword]);
                            db.run("INSERT OR IGNORE INTO cupidos (username, password) VALUES (?, ?)", ['cupido2', hashedPassword]);
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
