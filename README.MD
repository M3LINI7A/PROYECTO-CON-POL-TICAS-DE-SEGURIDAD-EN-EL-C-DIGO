Guía rápida: MySQL + Apache (XAMPP)
1) Instalar y ubicar el proyecto

Instala XAMPP (Windows/macOS/Linux).

Copia la carpeta del proyecto dentro de:

Windows: C:\xampp\htdocs\SPV

macOS: /Applications/XAMPP/htdocs/SPV

Linux: /opt/lampp/htdocs/SPV

Para una mejor seguridad, sirve solo public/:

Acceso: http://localhost/SPV/public/

(Opcional) Configura un VirtualHost para que public/ sea la raíz.

2) Habilitar PDO MySQL (si hace falta)

Abre php.ini (desde XAMPP Control Panel → Apache → Config → php.ini).

Asegúrate de tener descomentado:

extension=pdo_mysql


Reinicia Apache.

3) Crear la base y el usuario

En phpMyAdmin o consola MySQL:

CREATE DATABASE spv CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'spv_user'@'localhost' IDENTIFIED BY 'spv_pass';
GRANT ALL PRIVILEGES ON spv.* TO 'spv_user'@'localhost';
FLUSH PRIVILEGES;

USE spv;
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'USER',
  created_at DATETIME NOT NULL
);

4) Cambiar DSN a MySQL en tus endpoints (ej. public/login.php)
$dsn = 'mysql:host=localhost;dbname=spv;charset=utf8mb4';
$pdo = new PDO($dsn, 'spv_user', 'spv_pass', [
  PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
  PDO::ATTR_EMULATE_PREPARES => false,
]);

5) Crear un usuario admin (snippet rápido)

Crea un archivo temporal scripts/init_mysql_admin.php:

<?php
require __DIR__.'/../security/auth.php';
$pdo = new PDO('mysql:host=localhost;dbname=spv;charset=utf8mb4','spv_user','spv_pass',[
  PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false,
]);
register_user($pdo, 'admin@example.com', 'Admin123!', 'ADMIN');
echo "Admin creado.\n";


Ejecuta:

php scripts/init_mysql_admin.php


Luego elimina ese archivo.

6) (Opcional) VirtualHost para apuntar a public/

En httpd-vhosts.conf:

<VirtualHost *:80>
  ServerName spv.local
  DocumentRoot "C:/xampp/htdocs/SPV/public"
  <Directory "C:/xampp/htdocs/SPV/public">
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>


Agrega 127.0.0.1 spv.local a tu archivo hosts.

Reinicia Apache y entra a http://spv.local/.

Nota: .htaccess ya impide el listado de directorios en security/. Si usas Nginx, replica las cabeceras de security/headers.php desde la app (ya están) o en la config del servidor si gustas.

FAQ / Troubleshooting
1) 419 Token CSRF inválido

Causa: se envió POST sin token o se reutilizó el token (one-time).

Solución: recarga el formulario (GET) y reintenta; verifica que el handler use enforce_post_csrf('clave') con la misma clave usada en csrf_field('clave').

2) 429 Demasiadas solicitudes

Causa: rate-limit activado (por IP y ruta).

Solución: espera la ventana (p.ej. 60s) o reduce intentos; ajusta valores en enforce_rate_limit(max, window).

3) 401 No autenticado / 403 No autorizado

Causa: falta sesión o rol insuficiente.

Solución: inicia sesión primero; usa require_auth() o require_auth('ADMIN') según corresponda; revisa la cookie de sesión y que secure_session_start() se ejecute antes.

4) 500 Ha ocurrido un error inesperado

Causa: excepción en servidor (DB, permisos, etc.).

Solución: revisa logs en security/logs/php-error.log.

Si no se crea el log, verifica permisos de carpeta security/logs/.

En producción, mantén display_errors=Off.

5) PDOException: could not find driver

Causa: falta pdo_mysql (MySQL) o driver deshabilitado.

Solución: habilita extension=pdo_mysql en php.ini y reinicia Apache.

6) random_bytes() / OpenSSL warnings

Causa: entornos muy antiguos o sin entropía.

Solución: usa PHP 7.2+ (recomendado 8.1+); en Windows con XAMPP viene listo.

7) CSP bloquea archivos externos (CDN)

Causa: Content-Security-Policy restrictivo ('self').

Solución: añade fuentes permitidas en security/headers.php, ejemplo:

"script-src 'self' https://cdn.jsdelivr.net"


Revisa consola del navegador para ver qué se bloqueó.

8) No aparece Strict-Transport-Security

Causa: estás en HTTP (no HTTPS).

Solución: HSTS solo se envía en HTTPS (el código ya lo hace automáticamente).

9) SQLite: database is locked (solo si usas SQLite)

Causa: múltiples escrituras concurrentes.

Solución: usa una sola conexión por request; para producción usa MySQL.

10) No se ven estilos o rutas

Causa: sirviendo desde /SPV/ en lugar de /SPV/public/, o paths relativos.

Solución: entra por http://localhost/SPV/public/ o configura VirtualHost a public/.

11) “No inicia sesión” aun con credenciales correctas

Causas: reloj del SO, cookies bloqueadas, mezcla HTTP/HTTPS.

Solución: prueba en HTTP o HTTPS consistente; revisa que el navegador no bloquee cookies y que SameSite=Strict sea compatible con tu flujo (por defecto seguro para misma pestaña).

12) “No se registran usuarios”

Causa: restricción por política de contraseñas.

Solución: la clave debe tener ≥8, mayúscula, minúscula, dígito y símbolo.

Consejos finales

Mantén siempre HTTPS; HSTS se auto-activa en headers.php.

No guardes secretos en código; usa variables de entorno.

Para el video: muestra curl -I con cabeceras, un POST sin CSRF (419), rate-limit (429), login correcto (200) y api/me.php autenticado.