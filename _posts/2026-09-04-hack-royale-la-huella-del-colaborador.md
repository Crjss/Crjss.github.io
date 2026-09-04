---
title: "La huella del colaborador"
date: 2026-09-04 14:30:00 -0400
description: "Reto de OSINT en el que se reconstruye el rastro digital de un desarrollador siguiendo un directorio público, un repositorio Git expuesto y su historial de commits hasta recuperar un secreto de despliegue filtrado."
categories: [Hack Royale, OSINT]
tags: [osint, git-leak, git-dumper, dns-spoofing, reconocimiento, facil]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** Hack Royale CTF 2026
> - **Evento/Sala/Reto:** La huella del colaborador
> - **Dificultad:** Fácil
> - **Categoría:** OSINT
> - **Técnicas Clave:** Enumeración de directorio web, análisis de perfil público, identificación de repositorio Git expuesto, extracción de repositorio con `git-dumper`, resolución de host manual (`/etc/hosts`), análisis de historial de Git (`git log --all`), recuperación de commit eliminado con secretos.
{: .prompt-tip }

---

## Introducción

El reto **"La huella del colaborador"** plantea un escenario de auditoría en el que un desarrollador del equipo organizador de un evento fue dejando, sin darse cuenta, un rastro de información sensible repartido entre un directorio de personal público y un repositorio Git accesible desde la web. El objetivo es reconstruir ese rastro paso a paso —sin fuerza bruta ni explotación de vulnerabilidades— hasta llegar a un secreto que el desarrollador creyó haber eliminado.

La descripción del reto entrega dos datos de partida fundamentales:

- El **handle** del colaborador: `a.mendoza-dev`.
- El **subdominio** donde comienza la investigación: `eventos.academia-ciberseguridad.com`.

Con esto, el punto de entrada natural es reconocer qué servicios expone ese subdominio.

## Reconocimiento

### Escaneo de puertos con Nmap

El primer paso en cualquier ejercicio de reconocimiento —incluso en OSINT, donde la superficie suele limitarse a servicios web— es confirmar qué puertos están abiertos en el objetivo:

```bash
nmap -sC -sV 10.0.160.52
```

Desglosando los parámetros:

- `-sC`: ejecuta el conjunto de *scripts* por defecto de Nmap (NSE), que incluyen comprobaciones básicas como la obtención del título de la página HTTP.
- `-sV`: intenta identificar la versión del servicio y del software que corre detrás de cada puerto abierto.

El resultado fue el siguiente:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx
|_http-title: Directorio del equipo — Academia Ciberseguridad
```

Solo hay un puerto abierto, el **80/tcp**, sirviendo una aplicación web con **nginx** cuyo título es *"Directorio del equipo — Academia Ciberseguridad"*. Esto confirma que toda la investigación se centrará en esta aplicación web y descarta de entrada vectores como SSH, bases de datos expuestas u otros servicios.

> ⚠️ **Advertencia:** en un reto de OSINT, encontrar un solo puerto abierto no es una limitación, es una pista: significa que la información que buscamos no está protegida por un servicio adicional, sino simplemente "a la vista", esperando ser correlacionada correctamente.
{: .prompt-warning }

### Exploración del directorio del equipo

Al acceder a `http://10.0.160.52` se encuentra una página que actúa como un directorio interno de personal, listando tres colaboradores del evento:

| Nombre | Handle | Rol |
|---|---|---|
| Alejandro Mendoza | `a.mendoza-dev` | Desarrollador backend · Plataforma |
| Lucía Ríos | `l.rios-ops` | Infraestructura y operación |
| Javier Santos | `j.santos-qa` | Aseguramiento de calidad |

Dado que el reto indica explícitamente que hay que arrancar por el handle `a.mendoza-dev`, el análisis se centra en su perfil, ubicado en `/u/a.mendoza-dev/`.

### Análisis del perfil de Alejandro Mendoza

El perfil de Alejandro contiene dos secciones relevantes: una biografía ("Sobre mí") y un listado de repositorios.

En la biografía aparece el siguiente texto, que en un ejercicio de OSINT nunca debe leerse como simple relleno decorativo, sino como una pista deliberada del diseñador del reto:

> "A veces subo cosas que no debería y las quito después — cosas de las prisas."

Esta frase es la clave de todo el reto: indica que, en algún momento, se subió información sensible a un repositorio y luego se intentó eliminar. En Git, **eliminar un archivo en un nuevo commit no borra su existencia del historial**; el contenido sigue siendo recuperable mientras el commit anterior exista en el repositorio.

Más abajo, en la sección de repositorios, se encuentra el dato técnico que permite continuar:

```
Repositorios
portal-eventos (público)
Microservicio para publicar la agenda del evento. Node + Express.

Clónalo por HTTP:
git clone http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git

Historial completo disponible. Si algo no aparece en la última
versión, puede seguir vivo en un commit anterior.
```

De nuevo, el texto refuerza la misma idea: *"si algo no aparece en la última versión, puede seguir vivo en un commit anterior"*. Con handle, biografía y URL del repositorio en mano, el siguiente paso lógico es intentar acceder a ese repositorio Git.

> 💡 **Tip:** en un reto de OSINT bien diseñado, cada frase de "relleno" en una biografía o descripción suele ser una pista disfrazada. Conviene leer dos veces cualquier texto que mencione hábitos, errores o rutinas del objetivo.
{: .prompt-tip }

## Obtención del repositorio Git

### Primer intento fallido: `git clone` directo

El intento más directo es clonar el repositorio tal como lo indica el propio perfil:

```bash
git clone http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git
```

El resultado fue un error:

```
fatal: repositorio 'http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/' no encontrado
```

Este mensaje no significa necesariamente que el repositorio no exista, sino que el servidor **no tiene habilitado el protocolo *smart HTTP*** de Git (el que usa el binario `git-upload-pack` para negociar la clonación de forma eficiente). Esto es habitual cuando el `.git` de un proyecto queda expuesto por un simple error de configuración del servidor web (por ejemplo, servir una carpeta como archivos estáticos), en lugar de estar detrás de un servidor Git propiamente dicho.

### Segundo obstáculo: resolución DNS incorrecta

Antes de descartar la vía HTTP dumb, se intentó verificar manualmente si el `.git` estaba expuesto como archivos estáticos:

```bash
curl -s http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/HEAD
```

La respuesta fue inesperada: un **301 Moved Permanently** servido por **Cloudflare**. Esto reveló un detalle crítico del reto: el nombre `eventos.academia-ciberseguridad.com` **resuelve por DNS público a una infraestructura real y completamente distinta** —en este caso, la plataforma pública del evento "Hack Royale" (un CMS de tipo *cyber range* basado en Yii/echoCTF)— y no a la máquina del laboratorio local (`10.0.160.52`) donde realmente vive el reto.

Esto se confirmó al seguir el redirect con `curl -L`: la respuesta era una página 404 completamente ajena al directorio de personal, perteneciente a la plataforma pública real del evento.

> ⚠️ **Advertencia:** este es un patrón importante para recordar en retos de laboratorio: cuando un hostname pertenece a un dominio real registrado en internet, las peticiones normales seguirán la resolución DNS pública, no la topología del laboratorio. Hay que forzar la resolución hacia la IP interna del reto.
{: .prompt-warning }

### Solución: forzar la resolución del hostname

Existen dos formas de forzar que las peticiones a `eventos.academia-ciberseguridad.com` viajen hacia la IP del laboratorio (`10.0.160.52`) en lugar de a la IP pública real:

**Opción puntual, solo para `curl`:**

```bash
curl -sL --resolve eventos.academia-ciberseguridad.com:80:10.0.160.52 \
  http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/HEAD
```

El flag `--resolve host:puerto:IP` le indica a `curl` que, para ese host y puerto específicos, use la IP indicada en lugar de consultar el DNS real. Con esto se obtuvo:

```
ref: refs/heads/master
```

Esto confirmó que el `.git` **sí estaba expuesto** en el servidor local, y que el problema nunca fue el repositorio, sino la resolución del nombre.

**Opción persistente, para todas las herramientas (`curl`, `git`, `git-dumper`, navegador, etc.):**

Como herramientas como `git-dumper` no ofrecen una opción equivalente a `--resolve`, la solución robusta es editar el archivo `/etc/hosts` del sistema para fijar la resolución de ese hostname a nivel de sistema operativo:

```bash
echo "10.0.160.52 eventos.academia-ciberseguridad.com" | sudo tee -a /etc/hosts
```

Verificación de que el cambio surtió efecto:

```bash
getent hosts eventos.academia-ciberseguridad.com
# 10.0.160.52  eventos.academia-ciberseguridad.com
```

A partir de este punto, cualquier herramienta del sistema que resuelva ese nombre de dominio será dirigida automáticamente hacia la máquina del laboratorio.

### Descubriendo la estructura real del repositorio expuesto

Con la resolución ya corregida, se intentó extraer el repositorio con **git-dumper**, una herramienta pensada específicamente para reconstruir repositorios Git a partir de un directorio `.git` filtrado en un servidor web:

```bash
git-dumper http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/ ./portal-eventos-dump
```

El resultado fue un error 404:

```
[-] Testing http://eventos.academia-ciberseguridad.com/repos/portal-eventos/.git/HEAD [404]
```

Este error reveló un detalle importante sobre cómo funciona `git-dumper` internamente: la herramienta asume el patrón más común de exposición accidental, en el que existe una carpeta de proyecto (`portal-eventos/`) que contiene *dentro* un subdirectorio oculto `.git/`. Por eso, al recibir una URL que termina en `portal-eventos.git`, la herramienta le quita la extensión `.git` y vuelve a añadir `/.git/` al final, buscando `portal-eventos/.git/HEAD` — una ruta que no existe en este servidor.

En este reto, sin embargo, el directorio expuesto se llama literalmente `portal-eventos.git` y **es él mismo el repositorio bare** (la estructura interna de Git: `HEAD`, `config`, `objects/`, `refs/`, etc.), sin ninguna carpeta de proyecto por encima. Esto se confirmó comprobando si el servidor tenía listado de directorio (*autoindex*) habilitado:

```bash
curl -s http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/
```

```
Index of /repos/portal-eventos.git/
branches/
hooks/
info/
objects/
refs/
HEAD
config
description
packed-refs
```

Efectivamente, esto es la estructura interna de un repositorio bare, expuesta directamente por nginx sin ningún tipo de restricción.

### Descarga del repositorio con `wget`

Al confirmar el listado de directorio, la forma más simple y fiable de reconstruir el repositorio completo es espejar recursivamente toda la estructura con `wget`:

```bash
wget -r -np -nH --cut-dirs=1 -R "index.html*" \
  http://eventos.academia-ciberseguridad.com/repos/portal-eventos.git/
```

Explicación de los parámetros utilizados:

- `-r`: descarga de forma recursiva, siguiendo enlaces dentro de los directorios listados.
- `-np` (*no parent*): evita que `wget` suba a directorios superiores al indicado, limitando la descarga solo a `portal-eventos.git/` y su contenido.
- `-nH` (*no host directories*): evita que `wget` cree una carpeta con el nombre del host (`eventos.academia-ciberseguridad.com/`) como raíz de la descarga.
- `--cut-dirs=1`: elimina un nivel de la ruta original (`repos/`) para que la estructura descargada quede directamente como `portal-eventos.git/` en el directorio actual.
- `-R "index.html*"`: excluye de la descarga los archivos `index.html` que nginx genera automáticamente para representar el listado de cada carpeta (no son parte real del repositorio, solo son la vista HTML del *autoindex*).

Tras la descarga, es necesario eliminar cualquier resto de esos archivos de listado que `wget` no haya excluido del todo:

```bash
find . -name "index.html*" -delete
```

## Análisis del historial de Git

### Clonado local del repositorio reconstruido

Con la estructura bare completa en disco, se puede clonar localmente para trabajar con ella como con cualquier repositorio Git normal:

```bash
git clone portal-eventos.git portal-eventos-work
cd portal-eventos-work
```

### Revisión del historial completo de commits

Siguiendo la pista dejada por Alejandro en su biografía ("puede seguir vivo en un commit anterior"), el paso natural es no limitarse al estado actual del código (`HEAD`), sino revisar **todo el historial de commits, en todas las ramas**:

```bash
git log --all --oneline
```

```
e5d7635 (HEAD -> master, origin/master, origin/HEAD) chore: añadir .gitignore
7e332fa docs: añadir sección de estado al README
5af7d34 chore: quitar credenciales del repo (no deben ir aquí)
eb23288 Añadir notas de despliegue con credenciales de prod
61c760a Estructura inicial del portal de eventos
```

El historial es muy revelador incluso solo con los mensajes de commit:

1. `61c760a` — Estructura inicial del proyecto.
2. `eb23288` — **Se añaden notas de despliegue que incluyen credenciales de producción.** Este es el commit donde se introdujo el secreto.
3. `5af7d34` — **Se "quitan" esas credenciales**, reconociendo en el propio mensaje que "no deben ir aquí". Este commit borra el archivo del árbol de trabajo, pero **no borra el contenido del historial de Git**.
4. `7e332fa` y `e5d7635` — Commits posteriores de limpieza (README y `.gitignore`), probablemente ya con la intención de "prevenir" que vuelva a pasar, aunque el daño ya estaba hecho en el historial.

> 💡 **Tip:** en Git, un `git rm archivo.md` seguido de un commit **no destruye la información**, solo la elimina de la última instantánea (`HEAD`). El contenido del archivo permanece perfectamente accesible en el(los) commit(s) anterior(es), a menos que se reescriba activamente el historial (`git filter-repo`, `BFG Repo-Cleaner`) y se fuerce un `push --force` junto con la expiración del *reflog* y el *garbage collection*. Nada de eso ocurrió aquí.
{: .prompt-tip }

### Recuperando el contenido eliminado

El commit `5af7d34` es exactamente el que elimina el archivo sensible. Para ver qué contenido se quitó, basta con inspeccionar el *diff* de ese commit:

```bash
git show 5af7d34
```

```diff
commit 5af7d3475d80b67643d1728df283204fdc4e6ae8
Author: Alejandro Mendoza <a.mendoza-dev@correo.mx>
Date:   Thu Mar 5 11:03:00 2026 -0600

    chore: quitar credenciales del repo (no deben ir aquí)

diff --git a/notas-despliegue.md b/notas-despliegue.md
deleted file mode 100644
index faddcbf..0000000
--- a/notas-despliegue.md
+++ /dev/null
@@ -1,20 +0,0 @@
-# Notas de despliegue (privado)
-
-Recordatorio rápido para no volver a pelearme con el servidor.
-
-## Servidor
-
-- Host: portal-int.eventos.academia-ciberseguridad.com
-- Usuario SSH: deploy
-
-## Variables reales de producción
-
-```
-DB_HOST=10.10.4.12
-DB_USER=portal
-DB_PASS=otoño-2026-Guadalajara
-DEPLOY_TOKEN=ctf{4648852292XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
-```
-
-El DEPLOY_TOKEN lo pide el webhook de CI para publicar. NO compartir.
-Cuando tenga tiempo lo muevo a un gestor de secretos.
```

Como el *diff* de un archivo eliminado se muestra en formato "todo en rojo" (líneas que existían y se quitaron), el contenido completo del archivo `notas-despliegue.md` queda perfectamente legible en la salida, incluyendo la variable `DEPLOY_TOKEN`, que contiene la flag del reto en formato `ctf{...}`.

> ⚠️ **Advertencia:** este mismo resultado también se podría haber obtenido, de forma equivalente, con `git show <hash>:<ruta>` apuntando al commit *anterior* a la eliminación (`eb23288:notas-despliegue.md`), o revisando directamente los objetos blob del repositorio con `git cat-file`. `git show` sobre el commit de borrado es simplemente el camino más directo cuando ya se sabe qué commit buscar.
{: .prompt-warning }

## Flag

```
ctf{4648852292bXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

## Conclusión y Aprendizajes

Este reto es un ejemplo muy claro de un problema real y extremadamente común en entornos de desarrollo: **la falsa sensación de seguridad que da "borrar" un archivo con credenciales de un repositorio**. Alejandro Mendoza hizo exactamente lo que muchos desarrolladores hacen al darse cuenta de un error: eliminó el archivo y confió en que, al no estar visible en la última versión, el problema quedaba resuelto. Sin embargo, el modelo de datos de Git está diseñado para preservar el historial completo por defecto, y un simple `git log --all` junto con `git show` sobre el commit de borrado es suficiente para recuperar cualquier secreto que haya pasado, aunque sea brevemente, por un commit.

Desde el punto de vista metodológico, el reto también deja varias lecciones de proceso muy valiosas:

- **Los perfiles y biografías "de relleno" en retos de OSINT casi nunca son relleno real.** Frases aparentemente casuales ("subo cosas que no debería y las quito después") son, en la práctica, el guion que indica exactamente qué técnica aplicar.
- **Un error de "repositorio no encontrado" en `git clone` no es sinónimo de "no existe".** Puede significar simplemente que el servidor no soporta el protocolo *smart HTTP*, mientras que el `.git` sigue perfectamente accesible como archivos estáticos vía el protocolo *dumb HTTP*.
- **La resolución DNS puede jugar en contra en entornos de laboratorio que usan nombres de dominio reales.** Cuando un hostname del reto coincide con un dominio público real, hay que forzar la resolución hacia la IP del laboratorio (con `curl --resolve` para pruebas puntuales, o editando `/etc/hosts` para que todas las herramientas del sistema se vean beneficiadas).
- **Herramientas como `git-dumper` asumen un patrón de exposición específico** (carpeta de proyecto con `.git/` oculto dentro) y pueden fallar silenciosamente ante variantes, como un directorio bare expuesto directamente. Conocer la estructura interna de un repositorio Git (`HEAD`, `config`, `objects/`, `refs/`, `packed-refs`) permite reconocer estos casos y adaptar la técnica de extracción, incluso reconstruyéndolo a mano con `curl` o `wget` cuando la herramienta automatizada no encaja con el escenario.
- **El historial de Git es, en sí mismo, una fuente de OSINT.** Los metadatos de autoría (nombre, correo, fecha) de cada commit también aportan contexto de inteligencia sobre la persona detrás del repositorio, más allá del propio contenido del código.

En definitiva, el reto refuerza un principio fundamental de higiene en el manejo de secretos: **si una credencial llegó a hacer commit alguna vez, debe considerarse comprometida y rotarse**, independientemente de si el archivo fue eliminado después. La única forma segura de "borrar" un secreto de un repositorio Git es reescribir el historial completo y rotar la credencial; borrar el archivo en un nuevo commit es, únicamente, un gesto cosmético.
