require('dotenv').config();
const { pool } = require('../db');

async function clearTestUsers() {
    const client = await pool.connect();
    try {
        console.log("🗑️ Cleaning up test users (and freeing up emails)...");

        // List of protected usernames (Seed data)
        const protectedUsers = [
            'master',
            'cupido1', 'cupido2', 'cupido3', 'cupido4', 'cupido5', 'cupido6',
            'blinder1', 'blinder2', 'blinder3', 'blinder4'
        ];

        // Placeholder for query parameter
        const placeholders = protectedUsers.map((_, i) => `$${i + 1}`).join(',');

        await client.query('BEGIN');

        // 1. Get IDs of users to delete
        const res = await client.query(
            `SELECT id, username, email FROM cupidos WHERE username NOT IN (${placeholders})`,
            protectedUsers
        );

        const idsToDelete = res.rows.map(r => r.id);

        if (idsToDelete.length === 0) {
            console.log("✅ No test users found to delete.");
            await client.query('ROLLBACK');
            return;
        }

        console.log(`⚠️ Deleting ${idsToDelete.length} users:`, res.rows.map(u => `${u.username} (${u.email})`).join(', '));

        // 2. Delete from related tables (Order matters due to Foreign Keys)
        // Dependencies: 
        // cupido_profiles(user_id)
        // blinder_profiles(user_id)
        // push_subscriptions(user_id)
        // user_rooms(cupido_id)
        // invite_tokens(cupido_id)
        // rooms(cupido_id, user_a_id, user_b_id) -> This handles rooms created BY them or WHERE they are participants

        const idParams = idsToDelete.map((_, i) => `$${i + 1}`).join(',');
        const idValues = idsToDelete;

        await client.query(`DELETE FROM cupido_profiles WHERE user_id IN (${idParams})`, idValues);
        await client.query(`DELETE FROM blinder_profiles WHERE user_id IN (${idParams})`, idValues);
        await client.query(`DELETE FROM push_subscriptions WHERE user_id IN (${idParams})`, idValues);
        await client.query(`DELETE FROM user_rooms WHERE cupido_id IN (${idParams})`, idValues);
        await client.query(`DELETE FROM invite_tokens WHERE cupido_id IN (${idParams})`, idValues);
        await client.query(`DELETE FROM solteros WHERE cupido_id IN (${idParams})`, idValues);

        // Rooms: Delete rooms created by them OR where they are participants
        // Note: If we delete a user who is part of a room, we might want to keep the room but set user_id to NULL, 
        // OR delete the room. For "Cleanup", deleting the room is usually cleaner.

        // First find the rooms to be deleted to clear messages
        const roomsToDeleteRes = await client.query(`SELECT id FROM rooms WHERE cupido_id IN (${idParams}) OR user_a_id IN (${idParams}) OR user_b_id IN (${idParams})`, idValues);
        const roomIds = roomsToDeleteRes.rows.map(r => r.id);

        if (roomIds.length > 0) {
            // Delete messages in those rooms
            const roomPlaceholders = roomIds.map((_, i) => `$${i + 1}`).join(',');
            await client.query(`DELETE FROM messages WHERE room_id IN (${roomPlaceholders})`, roomIds);

            // Now delete the rooms
            await client.query(`DELETE FROM rooms WHERE id IN (${roomPlaceholders})`, roomIds);
        }

        // Finally, delete the users
        await client.query(`DELETE FROM cupidos WHERE id IN (${idParams})`, idValues);

        await client.query('COMMIT');
        console.log("✅ Cleanup complete. Emails are now free to be reused.");

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("❌ Error clearing users:", err);
    } finally {
        client.release();
        pool.end(); // Close connection to script finishes
    }
}

clearTestUsers();
