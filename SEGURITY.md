1) Resumen y alcance

Este documento resume los riesgos identificados y las medidas de seguridad implementadas en el proyecto SPV (PHP ≥ 8.1). La seguridad se integra en el código (no solo configuración externa) y cubre autenticación, sesiones, validación, CSRF, CSP/HSTS, rate-limit, manejo de errores y control de acceso (RBAC).
Entorno de demo con SQLite y opción de MySQL para producción.

Estructura relevante

public/: endpoints web (index.php, login.php, api/me.php, logout.php).

security/: headers.php, session.php, csrf.php, input.php, auth.php, middleware.php, rate_limit.php, response.php, errors.php, .htaccess, logs/.

2) Riesgos principales (OWASP Top 10 – síntesis)

Control de acceso roto (IDOR/ACL): acceso a recursos sin verificar autenticación/rol.

Fallas criptográficas: contraseñas mal almacenadas; transporte no cifrado.

Inyección (SQLi): concatenación de SQL con datos del usuario.

XSS: render de entrada no escapada en HTML/JS.

CSRF: ejecución no intencional de acciones sensibles.

Gestión de sesión débil: fijación/robo de sesión, cookies sin protecciones.

Fuerza bruta: intentos masivos de login.

Registro/errores inseguros: exposición de stack traces o datos sensibles.

3) Controles implementados (qué protege y dónde)
Riesgo	Control aplicado	Código
ACL/IDOR	Requiere sesión y rol (RBAC)	auth.php (require_auth, has_role)
Criptografía	password_hash/verify; HSTS en HTTPS	auth.php, headers.php
SQLi	PDO preparado (sin concatenar SQL)	auth.php
XSS	CSP restrictiva ('self'), escapado HTML	headers.php, input.php (e)
CSRF	Tokens one-time y verificación en POST	csrf.php, middleware.php (enforce_post_csrf)
Sesión	Cookie HttpOnly + SameSite=Strict, regen ID, timeout	session.php
Brute force	Rate-limit por IP+ruta	rate_limit.php, middleware.php (enforce_rate_limit)
Errores/Logs	Mensajes genéricos + logs privados	errors.php, response.php
Listado de dirs	Bloqueado	.htaccess (Options -Indexes)

Frontend (buenas prácticas)
Validación HTML5/JS antes de enviar; evitar innerHTML (usar textContent/innerText); no almacenar tokens sensibles en localStorage. CSP bloquea scripts externos no permitidos.

4) Decisiones y políticas clave

CSP 'self' + X-Frame-Options: DENY + nosniff + Referrer-Policy para reducir XSS/clickjacking. (Ampliar CSP solo si se usan CDNs específicos).

Sesiones seguras: regeneración periódica de ID, expiración por inactividad, SameSite=Strict y HttpOnly.

Autenticación robusta: contraseñas con password_hash(); rehash transparente si el algoritmo cambia.

CSRF one-time por clave/flujo: cada POST sensible exige token válido y de un solo uso.

Rate-limit simple: mitiga fuerza bruta sin infra adicional.

Errores controlados: al usuario solo mensajes genéricos; detalles a log.

Respuestas JSON consistentes: tipificadas desde response.php y sin datos sensibles.

5) Checklist de configuración (prod)

HTTPS obligatorio; HSTS se envía automáticamente en HTTPS.

php.ini: display_errors=Off, log_errors=On.

Permisos de escritura para security/logs/.

CSP: añadir dominios necesarios si usas CDNs (scripts/estilos/imagenes).

BD: usuario de mínimos privilegios; backups cifrados.

Variables sensibles por entorno (no en código).

Proteger todas las rutas críticas con require_auth() y, si aplica, require_auth('ADMIN').

6) Limitaciones y mejoras futuras

Rate-limit basado en archivos: no distribuido; migrar a Redis en alta concurrencia.

Falta 2FA, bloqueo progresivo por intentos fallidos y notificaciones de seguridad.

Sin auditoría/trazabilidad de acciones por usuario.

CSP sin nonces/hashes (simplifica mantenimiento; evaluar nonces + SRI).

No se incluye flujo de recuperación de contraseña.

Validación de subidas de archivos no incluida (si se requiere: whitelist de MIME/extensión, tamaño, análisis AV).

SQLite solo para demo; MySQL recomendado en producción.

7) Evidencias y cómo verificarlas (resumen)

Cabeceras de seguridad:
curl -I http://localhost:8000/login.php → ver Content-Security-Policy, X-Frame-Options, etc.

Ruta protegida sin sesión:
curl -i http://localhost:8000/api/me.php → 401 {"error":"No autenticado"}.

CSRF: enviar POST a login.php sin token → 419 {"error":"Token CSRF inválido"}.

Rate-limit: ≥6 intentos fallidos/min al login → 429 {"error":"Demasiadas solicitudes..."}.

Sesión: comprobar cambio de ID tras login (regeneración).

Logs: errores técnicos solo en security/logs/php-error.log (no visibles al usuario).

8) Referencias de código (rápido)

Cabeceras/CSP/HSTS: security/headers.php

Sesiones: security/session.php

CSRF: security/csrf.php, security/middleware.php

Validación/escapado: security/input.php

Autenticación/RBAC/SQL: security/auth.php

Rate-limit: security/rate_limit.php, security/middleware.php

Errores/JSON: security/errors.php, security/response.php

Endpoints de demo: public/login.php, public/api/me.php, public/logout.php