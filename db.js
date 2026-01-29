require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, process.env.DB_PATH || 'database.sqlite');
const db = new sqlite3.Database(dbPath);

const initDb = async () => {
    return new Promise((resolve, reject) => {
        db.serialize(async () => {
            // Create cupidos table
            db.run(`CREATE TABLE IF NOT EXISTS cupidos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )`, (err) => {
                if (err) reject(err);
            });

            // Create rooms table
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
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
            )`, (err) => {
                if (err) reject(err);

                // Add columns if they don't exist (for existing DBs)
                db.run("ALTER TABLE rooms ADD COLUMN linkA_session TEXT", () => { });
                db.run("ALTER TABLE rooms ADD COLUMN linkB_session TEXT", () => { });
                db.run("ALTER TABLE rooms ADD COLUMN active_since INTEGER", () => { });
                db.run("ALTER TABLE rooms ADD COLUMN total_active_seconds INTEGER DEFAULT 0", () => { });
            });

            // Create messages table
            db.run(`CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id INTEGER,
                sender TEXT, -- 'A' or 'B'
                text TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (room_id) REFERENCES rooms(id)
            )`, (err) => {
                if (err) reject(err);
            });

            // Create user_rooms table
            db.run(`CREATE TABLE IF NOT EXISTS user_rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cupido_id INTEGER,
                room_id INTEGER,
                role TEXT, -- 'A' or 'B'
                accessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cupido_id) REFERENCES cupidos(id),
                FOREIGN KEY (room_id) REFERENCES rooms(id),
                UNIQUE(cupido_id, room_id)
            )`, (err) => {
                if (err) reject(err);
            });

            // Check if default user exists
            db.get("SELECT * FROM cupidos WHERE username = 'cupido1'", async (err, row) => {
                if (err) {
                    console.error("Error checking for default user:", err);
                    return;
                }

                if (!row && process.env.NODE_ENV !== 'production') {
                    const hashedPassword = await bcrypt.hash(process.env.DEFAULT_USER_PASSWORD || '1234', 10);
                    db.run("INSERT INTO cupidos (username, password) VALUES (?, ?)", ['cupido1', hashedPassword], (err) => {
                        if (err) console.error("Error creating default user:", err);
                        else console.log("Default user 'cupido1' created.");
                    });
                }

                // Check cupido2
                db.get("SELECT id FROM cupidos WHERE username = 'cupido2'", async (err, row2) => {
                    if (!row2 && process.env.NODE_ENV !== 'production') {
                        const hashedPassword = await bcrypt.hash(process.env.DEFAULT_USER_PASSWORD || '1234', 10);
                        db.run("INSERT INTO cupidos (username, password) VALUES (?, ?)", ['cupido2', hashedPassword], (err) => {
                            if (err) console.error("Error creating cupido2:", err);
                            else console.log("Default user 'cupido2' created.");
                        });
                    }
                });

                resolve();
            });
        });
    });
};

module.exports = { db, initDb };
