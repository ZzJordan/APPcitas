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
                role TEXT DEFAULT 'cupido',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        // Migrations
        try {
            await client.query(`ALTER TABLE cupidos ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;`);
        } catch (e) {
            if (e.code !== '42701') console.warn("Migration Warning (cupidos.created_at):", e.message);
        }

        try {
            await client.query(`ALTER TABLE cupidos ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;`);
        } catch (e) {
            if (e.code !== '42701') console.warn("Migration Warning (cupidos.is_verified):", e.message);
        }

        try {
            await client.query(`ALTER TABLE cupidos ADD COLUMN IF NOT EXISTS verification_token TEXT;`);
            // Migration: Auto-verify existing users (heuristic: no token means old user)
            await client.query("UPDATE cupidos SET is_verified = TRUE WHERE is_verified = FALSE AND verification_token IS NULL");
        } catch (e) {
            if (e.code !== '42701') console.warn("Migration Warning (cupidos.verification_token):", e.message);
        }

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                share_token TEXT UNIQUE
            );
        `);
        // Migration for existing tables: Add share_token if missing
        // Migration for existing tables: Add share_token if missing
        try {
            await client.query(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE;`);
        } catch (e) {
            // 42701 = Duplicate column (already exists, though IF NOT EXISTS should handle it)
            if (e.code !== '42701') console.warn("Migration Warning (share_token):", e.message);
        }

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

        // 4b. Table: cupido_profiles
        await client.query(`
            CREATE TABLE IF NOT EXISTS cupido_profiles (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE REFERENCES cupidos(id),
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

        // 9. Table: push_subscriptions
        await client.query(`
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES cupidos(id),
                endpoint TEXT UNIQUE,
                keys JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 10. Table: cupido_secrets (Track spy/top-secret usage)
        await client.query(`
            CREATE TABLE IF NOT EXISTS cupido_secrets (
                cupido_id INTEGER,
                usage_date DATE DEFAULT CURRENT_DATE,
                usage_count INTEGER DEFAULT 0,
                PRIMARY KEY (cupido_id, usage_date),
                FOREIGN KEY (cupido_id) REFERENCES cupidos(id)
            );
        `);

        // Default Users (Always attempt creation with ON CONFLICT)
        const pass = process.env.DEFAULT_USER_PASSWORD || '1234';
        const hashedPassword = await bcrypt.hash(pass, 10);

        // Master User (Password 12345)
        const masterPass = await bcrypt.hash('12345', 10);
        await client.query(
            "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET password = $2",
            ['master', masterPass, 'admin']
        );

        await client.query(
            "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
            ['cupido1', hashedPassword, 'cupido']
        );
        await client.query(
            "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
            ['cupido2', hashedPassword, 'cupido']
        );

        // Create extra Cupidos (3-6)
        for (let i = 3; i <= 6; i++) {
            await client.query(
                "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
                [`cupido${i}`, hashedPassword, 'cupido']
            );
        }

        // Create Blinders (1-4) linked to Cupido1
        const c1Res = await client.query("SELECT id FROM cupidos WHERE username='cupido1'");
        const cupido1Id = c1Res.rows[0]?.id;

        if (cupido1Id) {
            for (let i = 1; i <= 4; i++) {
                const bUsername = `blinder${i}`;
                // Insert user
                await client.query(
                    "INSERT INTO cupidos (username, password, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING",
                    [bUsername, hashedPassword, 'blinder']
                );

                // Get ID
                const bRes = await client.query("SELECT id FROM cupidos WHERE username=$1", [bUsername]);
                const bId = bRes.rows[0]?.id;

                if (bId) {
                    // Create Profile
                    await client.query(`
                        INSERT INTO blinder_profiles (user_id, cupido_id, full_name, age, city, tagline, tel)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (user_id) DO NOTHING
                    `, [bId, cupido1Id, `Blinder Master ${i}`, 20 + i, 'Madrid', 'Testing Account', `555-000${i}`]);
                }
            }
        }

        console.log("✅ Default users verified/created.");

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
