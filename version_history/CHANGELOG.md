# Historial de Versiones - Cupido's Project

Este archivo registra los cambios importantes y la evolución del proyecto.

## [v1.2.0] - 2026-01-31 (Actual)
### Seguridad y Estabilidad - "The Fortified Edition"
- **Seguridad en Registro**:
  - Implementada validación estricta en el registro de Blinders.
  - Se rechazan intentos de registro sin token de invitación o enlace de sala válido.
  - Prevención de "cuentas huérfanas" (Blinders sin Cupido asignado).
- **Correcciones Críticas**:
  - Solucionado bucle de redirección en el dashboard de Blinders.
  - Arreglado bug en el formulario de login de Blinder (Javascript activado).
  - Corregida sintaxis en `server.js` (cierre de llaves).
  - Añadidas dependencias faltantes en `package.json` (`qrcode`, `pg`) para despliegue en Railway.
  - Eliminado código legacy de `sqlite3`.

## [v1.1.0] - 2026-01-31
### Migración a PostgreSQL & QR - "The Production Ready Update"
- **Base de Datos**:
  - Migración completa de SQLite a PostgreSQL.
  - Implementación de `connect-pg-simple` para sesiones persistentes.
  - Script `initDb` mejorado para crear usuarios master (`cupido1-6`, `blinder1-4`) automáticamente.
- **Funcionalidades**:
  - **Generación de QR**: Nuevos botones en el dashboard para compartir invitaciones vía código QR.
  - **Cuentas Master**: Generación automática de cuentas de prueba para QA.

## [v1.0.0] - 2026-01-30
### Lanzamiento Inicial - "MVP"
- **Core**:
  - servidor Express básico.
  - Websockets para chat en tiempo real.
- **Roles**:
  - Sistema de Cupidos (creadores) y Blinders (invitados).
- **Features**:
  - Chat "ciego" (Blind chat).
  - Dashboard de gestión para Cupidos.
  - Invitaciones por enlace único.
