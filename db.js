require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Use DATABASE_URL from environment (Railway providing this)
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false } // Required for Railway/Heroku
});

// Helper for param replacement (? -> $1, $2...)
const query = async (text, params) => {
    // Basic regex to replace ? with $1, $2, etc. logic might be needed for complexity, 
    // but for this app simplistic replacement usually works if order is preserved.
    // actually, most secure way is to manually update queries in server.js.
    // But for a quick shim:
    let i = 0;
    const activeText = text.replace(/\?/g, () => `$${++i}`);
    return pool.query(activeText, params);
};

const initDb = async () => {
    console.log("🗄️ Initializing PostgreSQL database...");
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Table: cupidos
        await client.query(`
            CREATE TABLE IF NOT EXISTS cupidos (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT,
                recovery_token TEXT,
                token_expires TIMESTAMP,
                role TEXT DEFAULT 'cupido'
            );
        `);
        // Migrations (Add columns if missing - simplified for Postgres with IF NOT EXISTS logic usually involves checking info_schema)
        // For now, assuming fresh start or standard creates. If columns missing on existing DB, manual migration needed.
        // We'll skip complex migration checks for this 'init -y' prompt style unless critical.

        // 2. Table: rooms
        await client.query(`
            CREATE TABLE IF NOT EXISTS rooms (
                id SERIAL PRIMARY KEY,
                cupido_id INTEGER REFERENCES cupidos(id),
                friendA_name TEXT,
                friendB_name TEXT,
                noteA TEXT,
                noteB TEXT,
                linkA TEXT UNIQUE,
                linkB TEXT UNIQUE,
                linkA_session TEXT,
                linkB_session TEXT,
                user_a_id INTEGER REFERENCES cupidos(id),
                user_b_id INTEGER REFERENCES cupidos(id),
                status TEXT DEFAULT 'pendiente',
                active_since BIGINT, 
                total_active_seconds INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. Table: invite_tokens
        await client.query(`
            CREATE TABLE IF NOT EXISTS invite_tokens (
                id SERIAL PRIMARY KEY,
                cupido_id INTEGER REFERENCES cupidos(id),
                token TEXT UNIQUE,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 4. Table: blinder_profiles
        await client.query(`
            CREATE TABLE IF NOT EXISTS blinder_profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE REFERENCES cupidos(id),
                cupido_id INTEGER REFERENCES cupidos(id),
                full_name TEXT,
                age INTEGER,
                city TEXT,
                tagline TEXT,
                photo_url TEXT,
                tel TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 5. Table: solteros
        await client.query(`
            CREATE TABLE IF NOT EXISTS solteros (
                id SERIAL PRIMARY KEY,
                cupido_id INTEGER REFERENCES cupidos(id),
                name TEXT,
                tel_hash TEXT,
                tel_last4 TEXT,
                city TEXT,
                age INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 6. Table: messages
        await client.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                room_id INTEGER REFERENCES rooms(id),
                sender TEXT,
                text TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 7. Table: user_rooms
        await client.query(`
            CREATE TABLE IF NOT EXISTS user_rooms (
                id SERIAL PRIMARY KEY,
                cupido_id INTEGER REFERENCES cupidos(id),
                room_id INTEGER REFERENCES rooms(id),
                role TEXT,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(cupido_id, room_id)
            );
        `);

        // 8. Table: session (Required by connect-pg-simple)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "session" (
              "sid" varchar NOT NULL COLLATE "default",
              "sess" json NOT NULL,
              "expire" timestamp(6) NOT NULL
            )
            WITH (OIDS=FALSE);
            
            ALTER TABLE "session" DROP CONSTRAINT IF EXISTS "session_pkey";
            ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
            
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
        `);

        // Default Users
        const res = await client.query("SELECT id FROM cupidos LIMIT 1");
        if (res.rowCount === 0) {
            const pass = process.env.DEFAULT_USER_PASSWORD || '1234';
            const hashedPassword = await bcrypt.hash(pass, 10);

            await client.query(
                "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
                ['cupido1', hashedPassword, 'cupido']
            );
            await client.query(
                "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
                ['cupido2', hashedPassword, 'cupido']
            );
            console.log("✅ Default users created.");
        }

        await client.query('COMMIT');
        console.log("✅ Database tables confirmed (PostgreSQL).");

    } catch (e) {
        await client.query('ROLLBACK');
        console.error("❌ DB Init Error:", e);
        throw e;
    } finally {
        client.release();
    }
};

module.exports = { pool, query, initDb };
