const express = require('express');
const crypto = require('crypto');
const { db } = require('../db');
const { isAuthenticated } = require('../middleware/auth');
const { createRoomValidator, roomIdValidator, requestNewLinkValidator } = require('../middleware/validators/roomValidator');
const { handleValidationErrors } = require('../middleware/validators/handleValidation');

const router = express.Router();

// Crear sala (requiere autenticación)
router.post('/',
  isAuthenticated,
  createRoomValidator,
  handleValidationErrors,
  (req, res) => {
    const { friendA_name, friendB_name, noteA, noteB } = req.body;
    const cupido_id = req.session.userId;
    const linkA = crypto.randomUUID();
    const linkB = crypto.randomUUID();

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
  }
);

// Obtener salas del usuario
router.get('/',
  isAuthenticated,
  (req, res) => {
    const userId = req.session.userId;

    const ownedQuery = `SELECT * FROM rooms WHERE cupido_id = ? ORDER BY created_at DESC`;
    const accessedQuery = `
      SELECT r.*, ur.role as accessed_role, ur.accessed_at
      FROM rooms r
      JOIN user_rooms ur ON r.id = ur.room_id
      WHERE ur.cupido_id = ? AND r.cupido_id != ?
      ORDER BY ur.accessed_at DESC
    `;

    db.all(ownedQuery, [userId], (err, owned) => {
      if (err) return res.status(500).json({ error: "Error al obtener salas" });

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
  }
);

// Eliminar sala
router.delete('/:id',
  isAuthenticated,
  roomIdValidator,
  handleValidationErrors,
  (req, res) => {
    const roomId = req.params.id;
    const cupido_id = req.session.userId;

    db.run("DELETE FROM rooms WHERE id = ? AND cupido_id = ?", [roomId, cupido_id], function (err) {
      if (err) return res.status(500).json({ error: "Error al borrar sala" });
      if (this.changes === 0) return res.status(403).json({ error: "No autorizado" });

      db.run("DELETE FROM messages WHERE room_id = ?", [roomId]);
      db.run("DELETE FROM user_rooms WHERE room_id = ?", [roomId]);
      res.json({ message: "Sala borrada" });
    });
  }
);

// Generar nuevo link
router.post('/request-new-link',
  requestNewLinkValidator,
  handleValidationErrors,
  (req, res, io) => {
    const { oldLink } = req.body;

    db.get(
      "SELECT id, cupido_id, linkA, linkB, created_at FROM rooms WHERE linkA = ? OR linkB = ?",
      [oldLink, oldLink],
      (err, room) => {
        if (err || !room) return res.status(404).json({ error: "Link no encontrado" });

        const isA = (oldLink === room.linkA);
        const newLink = crypto.randomUUID();
        const linkField = isA ? 'linkA' : 'linkB';
        const sessionField = isA ? 'linkA_session' : 'linkB_session';

        db.run(
          `UPDATE rooms SET ${linkField} = ?, ${sessionField} = NULL WHERE id = ?`,
          [newLink, room.id],
          function (err) {
            if (err) return res.status(500).json({ error: "Error al generar" });
            res.json({ message: "Link regenerado" });
          }
        );
      }
    );
  }
);

module.exports = router;
