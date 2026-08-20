---
title: "Old Sessions - picoCTF 2026"
date: 2026-08-20 18:00:00 -0400
description: "Análisis y explotación de una vulnerabilidad de Information Disclosure en un endpoint que expone tokens de sesión activos, permitiendo un Session Hijacking hacia la cuenta de administrador."
categories: [CyLab Security Academy, picoCTF 2026]
tags: [web, session-hijacking, information-disclosure, cookies, easy]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** CyLab Security Academy (anteriormente picoCTF)
> - **Evento/Sala/Reto:** picoCTF 2026 — Old Sessions
> - **Dificultad:** Fácil
> - **Categoría:** Web Exploitation
> - **Técnicas Clave:** Information Disclosure, Session Hijacking, Insecure Session Management, Cookie Manipulation

---

## Introducción

El reto **Old Sessions** nos presenta una aplicación web tipo red social en desarrollo, denominada *"The New Twitter"*. La descripción del reto nos advierte sobre un problema crítico en la gestión de sesiones: el desarrollador, por comodidad, configuró el sistema para que las sesiones nunca expiren. Esto, combinado con un endpoint que filtra información sensible, abre la puerta a un ataque de **Session Hijacking** (secuestro de sesión) que nos permite impersonar al usuario administrador sin conocer sus credenciales.

La vulnerabilidad principal reside en dos fallas de seguridad concatenadas:

1. **Information Disclosure:** Un endpoint accesible (`/sessions`) lista todas las sesiones activas del servidor, incluyendo los tokens de sesión de otros usuarios.
2. **Insecure Session Management:** Las sesiones están marcadas como permanentes (`_permanent: True`) y no poseen tiempo de expiración, lo que permite reutilizar un token robado indefinidamente.

En este writeup analizaremos cada componente de la aplicación, entenderemos por qué estas decisiones de diseño son peligrosas y ejecutaremos el ataque paso a paso.

---

## Reconocimiento Inicial

Al iniciar la instancia del reto, se nos proporciona la siguiente URL de entrada:

```
http://dolphin-cove.picoctf.net:53630/login
```

La página presenta un formulario de autenticación con dos campos (`username` y `password`) y dos botones de acción: **Login** y **Register**. La interfaz es minimalista, lo que sugiere que la complejidad del reto no reside en el frontend, sino en la lógica de backend que gestiona las sesiones.

### Análisis del código fuente de `/login`

Al inspeccionar el código fuente de la página de inicio de sesión (mediante `Ctrl + U`), observamos una estructura HTML estándar sin elementos sospechosos a primera vista:

```html
<!doctype html>
<html>
<head>
  <title>The New Twitter</title>
  <link rel="stylesheet" href="/static/login-register.css">
</head>
<body>
  <div class="container">
    <div class="input-box">
      <div class="title-box">
        <h1>Login</h1>
      </div>
      <hr>
      <form id="input-form" method="POST">
        <label for="username">Username:</label>
        <input id="username" name="username" type="text">
        <br><br>
        <label for="password">Password:</label>
        <input id="password" name="password" type="password">
        <br><br>
        <div class="button-group">
          <input type="submit" value="Login" class="primary-button">
          <a href="/register" class="alt-action-button">Register</a>
        </div>
      </form>
      <hr>
    </div>
  </div>
</body>
</html>
```

> 💡 **Tip:** Cuando un formulario utiliza el método `POST` sin especificar el atributo `action`, el navegador envía los datos a la misma URL actual. En este caso, las credenciales se envían a `/login` vía POST.
{: .prompt-tip }

No encontramos campos ocultos, tokens CSRF ni referencias a archivos JavaScript que pudieran contener lógica adicional. La página `/register` tiene una estructura análoga, solo que incluye un campo adicional para confirmar la contraseña (`conf_password`).

---

## Registro y primer acceso

Para poder interactuar con la aplicación como usuario autenticado, procedemos a crear una cuenta de prueba. Esto es fundamental porque muchos endpoints en aplicaciones web solo son accesibles una vez establecida una sesión válida.

### Datos de registro

| Campo | Valor |
|-------|-------|
| Username | `test1` |
| Password | `123` |

Tras registrarnos e iniciar sesión, el servidor nos redirige a la página principal (`/`), donde se muestra un panel de bienvenida y una lista de comentarios públicos.

### Análisis del código fuente de la página principal

El HTML de la página autenticada revela algo extremadamente valioso:

```html
<!doctype html>
<html>
<head>
  <title>The New Twitter</title>
  <link rel="stylesheet" href="/static/index.css">
</head>
<body>
  <div class="container">
    <div class="header-box">
      <div class="title-box">
        <h1 id="page-title">Homepage</h1>
      </div>
      <hr>
      <div class="welcome-logout">
        <h3 class="welcome-message">Welcome <em>test1</em></h3>
        <a href="/logout" class="logout-button">Logout</a>
      </div>
    </div>
    <div class="comments-box">
      <h3>Comments</h3>
      <hr>
      <ul class="comment-list" id="commentList">
        <li class="comment">
          <div class="comment-header">
            <span class="username">billy_joe_134</span>
            <span class="timestamp">2025-04-10 09:15</span>
          </div>
          <div class="comment-text">This site is cool :D</div>
        </li>
        <li class="comment">
          <div class="comment-header">
            <span class="username">mary_jones_8992</span>
            <span class="timestamp">2024-2-20 14:50</span>
          </div>
          <div class="comment-text">Hey I found a strange page at /sessions</div>
        </li>
        <li class="comment">
          <div class="comment-header">
            <span class="username">autin_1244</span>
            <span class="timestamp">2023-07-05 18:30</span>
          </div>
          <div class="comment-text">Hey everyone!!!</div>
        </li>
        <li class="comment">
          <div class="comment-header">
            <span class="username">Admin</span>
            <span class="timestamp">2023-01-02 07:45</span>
          </div>
          <div class="comment-text">Hello world!</div>
        </li>
      </ul>
    </div>
  </div>
</body>
</html>
```

> ⚠️ **Atención:** El comentario del usuario `mary_jones_8992` es una pista deliberadamente insertada por los creadores del reto. Nos señala la existencia de un endpoint llamado `/sessions`. En un entorno real, este tipo de revelación podría provenir de un error de configuración, un archivo de documentación expuesto o un comentario olvidado en el código fuente.
{: .prompt-warning }

---

## Enumeración del endpoint `/sessions`

Siguiendo la pista del comentario, navegamos al endpoint:

```
http://dolphin-cove.picoctf.net:53630/sessions
```

Es importante destacar que este endpoint **requiere autenticación**. Si intentamos acceder sin una sesión válida, probablemente recibamos una redirección a `/login`. Sin embargo, al estar autenticados como `test1`, el servidor nos responde con el siguiente contenido:

```
1) session:j3cDgHn4nStyIgjgCIwm3q2eXPWxdoZqsMjwVdkmZHA, {'_permanent': True, 'key': 'admin'}

2) session:LjmNcaL8UofZQr61FLPxGreZJ3tT2g0lp4toMDtdBDA, {'_permanent': True, 'key': 'test1'}
```

### Análisis de la respuesta

La respuesta del servidor es un volcado crudo de las sesiones almacenadas en el backend. Vamos a desglosar cada componente:

| Componente | Significado |
|------------|-------------|
| `session:` | Prefijo que indica que el valor siguiente es un identificador de sesión. |
| `j3cDgHn4nStyIgjgCIwm3q2eXPWxdoZqsMjwVdkmZHA` | Token de sesión del usuario `admin`. Es una cadena codificada en Base64 o una firma HMAC generada por el framework web. |
| `'_permanent': True` | Flag que indica que la sesión no expirará por tiempo de inactividad. Es equivalente a configurar `session.permanent = True` en Flask. |
| `'key': 'admin'` | Valor interno que el servidor utiliza para identificar al usuario asociado a esa sesión. |

> ⚠️ **Crítico:** Este endpoint representa una vulnerabilidad de **Information Disclosure** de severidad crítica. Nunca, bajo ninguna circunstancia, una aplicación web debe exponer los identificadores de sesión de sus usuarios. Un endpoint de administración que liste sesiones activas debería, como mínimo, ofuscar o truncar los tokens, y requerir privilegios elevados.
{: .prompt-danger }

La estructura de la cookie (`session:...`) y el uso de `_permanent` son características típicas del framework **Flask** de Python, que utiliza cookies de sesión firmadas con la clave secreta de la aplicación (`SECRET_KEY`). Aunque la cookie está firmada (lo que impide modificar su contenido sin conocer la clave secreta), el hecho de que el servidor nos entregue una cookie válida de otro usuario nos permite el secuestro directo.

---

## Explotación: Session Hijacking

El **Session Hijacking** (secuestro de sesión) es un ataque en el cual un adversario obtiene el token de sesión de una víctima legítima y lo utiliza para impersonarla ante el servidor. En este caso, no necesitamos interceptar tráfico de red ni ejecutar un ataque Man-in-the-Middle; el servidor nos entregó el token del administrador voluntariamente.

### Concepto teórico

En arquitecturas web stateless (sin estado), el servidor no mantiene en memoria la información de cada usuario conectado. En su lugar, delega esa responsabilidad en el cliente mediante una **cookie de sesión**. Cada vez que el navegador realiza una petición, envía automáticamente esta cookie en el header `Cookie`. El servidor la valida, extrae la identidad del usuario y responde en consecuencia.

El problema surge cuando:

1. El token de sesión tiene una entropía baja (es predecible).
2. El token no expira nunca.
3. El token es expuesto a terceros (como en este caso).

### Procedimiento de explotación

#### Paso 1: Abrir las DevTools del navegador

Presionamos `F12` para abrir las herramientas de desarrollo del navegador. Navegamos a la pestaña **Application** (en Chrome/Edge) o **Storage** (en Firefox).

#### Paso 2: Localizar la cookie de sesión

En el panel izquierdo, expandimos la sección **Cookies** y seleccionamos el dominio `http://dolphin-cove.picoctf.net:53630`. Observamos una entrada similar a esta:

| Nombre | Valor | Dominio | Ruta | Expira |
|--------|-------|---------|------|--------|
| `session` | `LjmNcaL8UofZQr61FLPxGreZJ3tT2g0lp4toMDtdBDA` | `dolphin-cove.picoctf.net` | `/` | Session |

Este es nuestro token como usuario `test1`.

#### Paso 3: Reemplazar el token

Hacemos doble clic sobre el valor de la cookie `session` y lo sustituimos por el token del administrador:

```
j3cDgHn4nStyIgjgCIwm3q2eXPWxdoZqsMjwVdkmZHA
```

> 💡 **Tip:** Es fundamental no agregar espacios ni saltos de línea al pegar el token. La cookie debe contener exactamente la cadena del token para que la firma sea válida.
{: .prompt-tip }

#### Paso 4: Recargar la página

Presionamos `F5` para recargar la página principal (`/`). Al hacerlo, el navegador envía una petición HTTP GET con el header modificado:

```http
GET / HTTP/1.1
Host: dolphin-cove.picoctf.net:53630
Cookie: session=j3cDgHn4nStyIgjgCIwm3q2eXPWxdoZqsMjwVdkmZHA
```

El servidor recibe esta petición, deserializa la cookie, encuentra el valor `'key': 'admin'` dentro de la sesión decodificada, y determina que el solicitante es el usuario `admin`. Por lo tanto, renderiza la interfaz con privilegios de administrador.

---

## Obtención de la flag

Tras recargar la página con la cookie del administrador, el mensaje de bienvenida cambia de `Welcome test1` a `Welcome admin`. En el cuerpo del HTML, el servidor incluye la flag como recompensa por haber comprometido exitosamente la cuenta de mayor privilegio:

```html
<p class="flag-message">picoCTF{s3t_s3ss10n_3xp1rat10n5_11cae9aa}</p>
```

### Flag obtenida

```
picoCTF{s3t_s3ss10n_3xp1rat10n5_11cae9aa}
```

> 💡 **Nota sobre la flag:** Las flags en picoCTF son dinámicas y únicas por instancia de jugador. El hash final (`11cae9aa`) varía entre participantes, lo que previene la copia directa de flags entre usuarios.
{: .prompt-info }

---

## Alternativa técnica: Explotación con cURL

Para quienes prefieren una aproximación más técnica sin depender del navegador, el ataque puede replicarse mediante línea de comandos utilizando `curl`:

```bash
curl -s -b "session=j3cDgHn4nStyIgjgCIwm3q2eXPWxdoZqsMjwVdkmZHA"   http://dolphin-cove.picoctf.net:53630/ | grep -oP 'picoCTF\{[^\}]+\}'
```

### Explicación de los parámetros

| Parámetro | Función |
|-----------|---------|
| `-s` | Modo silencioso. Suprime la barra de progreso de `curl`. |
| `-b "session=..."` | Envía la cookie `session` con el valor especificado en el header `Cookie`. |
| `http://dolphin-cove.picoctf.net:53630/` | URL objetivo. |
| `\| grep -oP 'picoCTF\{[^\}]+\}'` | Pipe a `grep` con expresión regular Perl-compatible (`-P`) para extraer únicamente la flag del HTML. |

Este método es más rápido y permite automatizar el proceso si tuviéramos que probar múltiples tokens.

---

## Análisis de la vulnerabilidad desde el código

Aunque no tenemos acceso al código fuente del servidor, podemos inferir su lógica interna basándonos en el comportamiento observado. La aplicación probablemente está construida con **Flask** y utiliza el sistema de sesiones integrado de dicho framework.

### Código vulnerable inferido

```python
from flask import Flask, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'una_clave_secreta'

# ❌ VULNERABLE: Las sesiones nunca expiran
app.config['PERMANENT_SESSION_LIFETIME'] = None  # o simplemente no se define

@app.route('/sessions')
def list_sessions():
    # ❌ VULNERABLE: Expone todos los tokens de sesión
    sessions = redis_client.keys('session:*')  # o almacenamiento similar
    output = ""
    for idx, sess_key in enumerate(sessions, 1):
        data = redis_client.get(sess_key)
        output += f"{idx}) {sess_key}, {data}\n\n"
    return output

@app.route('/')
def home():
    user = session.get('key')
    if user == 'admin':
        return render_template('admin.html', flag=FLAG)
    return render_template('home.html')
```

### Código seguro recomendado

```python
from flask import Flask, session, redirect, url_for
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'una_clave_secreta_muy_larga_y_aleatoria'

# ✅ SEGURO: Configurar tiempo de expiración de sesiones
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.route('/sessions')
def list_sessions():
    # ✅ SEGURO: No exponer tokens. Si es necesario un panel de admin,
    # mostrar solo metadatos anonimizados y requerir autenticación de admin.
    return "403 Forbidden", 403

@app.route('/logout')
def logout():
    # ✅ SEGURO: Invalidar la sesión en el servidor
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'key' not in session:
        return redirect(url_for('login'))

    # ✅ SEGURO: Regenerar session ID tras cambios de privilegios
    user = session.get('key')
    return render_template('home.html', user=user)
```

---

## Conclusión y Aprendizajes

El reto **Old Sessions** es un ejercicio didáctico excepcional que ilustra cómo dos fallas aparentemente menores pueden concatenarse para producir un compromiso total de la aplicación. No fue necesario realizar ingeniería inversa, explotar buffer overflows ni ejecutar payloads complejos; simplemente observamos el comportamiento del sistema, seguimos una pista explícita y reutilizamos un token que nunca debió haber sido expuesto.

### Lecciones clave

1. **Information Disclosure es siempre grave:** Un endpoint que filtra datos internos, por inocente que parezca, puede ser la llave maestra que desbloquea todo el sistema. La seguridad por oscuridad no funciona.

2. **Las sesiones deben expirar:** Configurar sesiones permanentes por comodidad del usuario es un riesgo inaceptable. Un tiempo de expiración razonable (15-30 minutos de inactividad) mitiga el impacto de tokens robados.

3. **Validar el alcance de los endpoints:** Todo endpoint nuevo debe ser evaluado desde la perspectiva de "¿qué pasa si un usuario normal lo descubre?". El endpoint `/sessions` debería haber requerido autenticación de administrador y, aún así, nunca exponer tokens en texto plano.

4. **Las cookies son credenciales:** Un token de sesión válido es tan sensible como una contraseña. Debe protegerse con las flags `HttpOnly`, `Secure` y `SameSite`, y nunca transmitirse por canales no cifrados.

5. **El reconocimiento importa:** En este reto, el 90 % del trabajo fue leer atentamente los comentarios en la página principal. En pentesting real, la fase de reconocimiento y recolección de información consume la mayor parte del tiempo y es donde se descubren los vectores de ataque más valiosos.

### Referencias

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Flask Documentation — Sessions](https://flask.palletsprojects.com/en/latest/quickstart/#sessions)
- [PortSwigger — Session Hijacking](https://portswigger.net/web-security/authentication/session-based)

---

*Writeup redactado con fines educativos para la comunidad de ciberseguridad. El conocimiento debe ser libre, pero siempre utilizado de manera ética y responsable.*
