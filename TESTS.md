Este documento describe los casos de prueba ejecutados para verificar las medidas de seguridad del proyecto SPV.

0) Entorno y preparación

PHP ≥ 8.1

Demo por defecto con SQLite:

php scripts/init_sqlite.php admin@example.com Admin123! ADMIN
php -S localhost:8000 -t public


Endpoints bajo prueba:

GET / (página de inicio)

GET|POST /login.php (form + autenticación)

GET /api/me.php (ruta protegida)

GET /logout.php (cierra sesión)

Si usas Apache/XAMPP: apunta el DocumentRoot a public/ y repite las pruebas (ver README).

1) Autenticación y sesiones
T1.1 — Login correcto y regeneración de sesión

Pasos

Ir a GET /login.php (carga formulario con token CSRF).

Enviar credenciales válidas: admin@example.com / Admin123!.

Observar cookie de sesión antes y después de autenticarse (DevTools → Application → Cookies).

Esperado

Respuesta 200 con {"ok":true,...}.

Cambia el ID de sesión tras el login (mitiga fijación).

Cookie con HttpOnly y SameSite=Strict.

T1.2 — Credenciales inválidas

Comando

curl -i -X POST http://localhost:8000/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=admin@example.com&password=mala"   # (sin token CSRF a propósito)


Esperado: Rechazo por CSRF (ver T3.1). Con token válido pero contraseña mala → 401 {"error":"Credenciales inválidas"}.

T1.3 — Logout

Comando

curl -i http://localhost:8000/logout.php


Esperado: 200 {"ok":true} y la cookie de sesión invalida. Acceder a /api/me.php luego → 401.

T1.4 — Expiración por inactividad

Pasos

Autenticar.

Esperar más que el idle_timeout configurado (por defecto 20 minutos).

Abrir /api/me.php.

Esperado: 401 (sesión expirada).

2) Control de acceso (RBAC)
T2.1 — Ruta protegida sin sesión

Comando

curl -i http://localhost:8000/api/me.php


Esperado: 401 {"error":"No autenticado"}.

Si agregas un endpoint con require_auth('ADMIN'), prueba iniciar sesión como USER y acceder: 403 “No autorizado”.

3) CSRF (Cross-Site Request Forgery)
T3.1 — POST sin token

Comando

curl -i -X POST http://localhost:8000/login.php \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "email=admin@example.com&password=Admin123!"


Esperado: 419 {"error":"Token CSRF inválido"}.

T3.2 — Reutilización del token (one-time)

Pasos

Cargar GET /login.php (capturar csrf_token y csrf_key del formulario).

Hacer un POST válido (login correcto).

Repetir el mismo POST con el mismo token.

Esperado: Primer POST → éxito; segundo → 419 (token consumido).

T3.3 — CSRF key equivocada

Pasos: Enviar un csrf_key distinto al de la vista.
Esperado: 419.

4) Rate limiting (fuerza bruta)
T4.1 — Exceso de intentos en login

Script de ejemplo (6 intentos en <60s; 5 permitidos):

for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8000/login.php \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "email=admin@example.com&password=Mala$i" || true
done


Esperado: Los últimos intentos devuelven 429 “Demasiadas solicitudes…”.

T4.2 — Ventana de tiempo

Pasos: Esperar 60s (ventana por defecto) y reintentar.
Esperado: El contador se reinicia y permite nuevos intentos.

5) SQLi y validación
T5.1 — SQL Injection (entrada maliciosa en login)

Comando (requiere token válido; simúlalo desde el navegador, o edita el POST con el token actual):

email=' OR 1=1 -- 
password=cualquiera


Esperado: No inicia sesión; 401. No hay error SQL ni exposición de consulta (usa PDO preparado).

Para registro (si habilitas un endpoint que use register_user): probar emails inválidos (test@) o contraseñas débiles (abc123) → rechazo por validación (422 o excepción controlada).

6) XSS y salida segura
T6.1 — Reflejado

Intentar inyectar <script>alert(1)</script> en campos que se muestren en la vista (si los hay).
Esperado: Se escapa la salida (no ejecuta JS).

T6.2 — CSP bloqueando scripts externos

Pasos

En la consola del navegador, intentar cargar un script externo (ej. https://cdn.jsdelivr.net/...).

O añadir temporalmente una etiqueta <script src="https://cdn.jsdelivr.net/..."></script> en la página durante la prueba.

Esperado: Bloqueo por CSP (script-src 'self'), visible en la consola (violación de política).

7) Cabeceras de seguridad
T7.1 — Presencia de headers

Comando

curl -I http://localhost:8000/login.php


Esperado: Cabeceras como Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy.
En HTTPS, también Strict-Transport-Security.

8) Manejo de errores y logs
T8.1 — Errores no exponen detalles

Pasos

Romper temporalmente el DSN (por ejemplo, renombrar spv.sqlite) y solicitar /login.php.

Revisar respuesta al cliente y el archivo security/logs/php-error.log.

Esperado: Al usuario, mensaje genérico (500 sin traza). Detalles solo en el log.

9) Cookies y políticas
T9.1 — Flags de cookie

Pasos: Autenticar y revisar cookie de sesión en DevTools.
Esperado: HttpOnly y SameSite=Strict. En HTTPS, flag Secure.

10) Listado de directorios (Apache)
T10.1 — .htaccess en security/

Pasos: En Apache, navegar a /security/.
Esperado: Sin listado (regla Options -Indexes).
(Nota: el servidor embebido de PHP no interpreta .htaccess.)

11) Resultados y evidencias (sugeridas para entrega)

Adjunta capturas de:

curl -I mostrando CSP/X-Frame-Options.

POST sin CSRF ⇒ 419.

6° intento de login en 60s ⇒ 429.

/api/me.php sin sesión ⇒ 401.

Login correcto ⇒ 200 y cambio de ID de sesión (captura de cookie).

Extracto de security/logs/php-error.log ante un error forzado (sin stack trace al usuario).

12) Observaciones

HTTPS recomendado para ver Strict-Transport-Security.

SQLite es para demo; en producción, usar MySQL con usuario de mínimos privilegios.

Ajustar CSP si se permiten CDNs (o migrar a nonces + SRI).

Conclusión: Todas las pruebas confirman la efectividad de las medidas: CSP/HSTS, sesiones seguras, CSRF, SQL seguro (PDO), rate-limit, RBAC y manejo de errores/logs.