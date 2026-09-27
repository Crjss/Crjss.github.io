---
title: "Fusión"
date: 2026-09-26 14:30:00 -0400
description: "Writeup del reto web 'Fusión' de la Plataforma de Práctica CTF CITC, donde se analiza JavaScript ofuscado, se descartan varios señuelos (decoys) y se descifra la contraseña real mediante deofuscación e ingeniería inversa manual."
categories: [CITC, Web]
tags: [ctf, web, javascript, ofuscacion, ingenieria-inversa, media]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** Plataforma de Práctica CTF - CITC (Centro de Investigación en Tecnologías de la Comunicación, Bolivia)
> - **Evento/Sala/Reto:** Fusión
> - **Dificultad:** Media
> - **Categoría:** Web / Ofuscación de JavaScript
> - **Técnicas Clave:** Análisis de código fuente HTML/JS, deofuscación de arrays estilo `obfuscator.js`, identificación de señuelos (red herrings), resolución de anagramas por diccionario, análisis forense básico de imágenes (EXIF, binwalk, steghide) y cálculo de hashes MD5.

---

## Introducción

"Fusión" es un reto de la categoría **Web** de la Plataforma de Práctica CTF del CITC. El enunciado nos sitúa en el papel de un nuevo empleado que debe revisar código fuente de una aplicación web para encontrar "variables fundamentales" y, en última instancia, una contraseña que abre un formulario. El propio enunciado advierte que "hay algo más en juego" además de la contraseña, una pista narrativa que resultó ser literal: el reto está lleno de **señuelos** diseñados para hacer perder tiempo a quien ataque el problema sin método.

El formato de la flag es:

```text
cidsi{Flag_en_MD5}
```

Es decir, la flag final es el hash **MD5** de un texto concreto que se descubre durante la resolución, envuelto en el prefijo `cidsi{}`.

## Reconocimiento inicial

Al acceder a la URL proporcionada por la plataforma se muestra una página muy simple:

- Un título en verde: **"UNA DE LAS LLAVES DEL EXITO ES LA AUTOCONFIANZA"**.
- Un formulario con un único campo de tipo `password` y un botón **"Ingresar"**.
- Una imagen llamada `fusion.jpg` (un fan-art de la fusión de personajes de Dragon Ball).
- Un `<div id="tagreply">` casi vacío, que contiene únicamente un comentario HTML.

Lo primero que llama la atención es que, al intentar inspeccionar la página con el clic derecho, el menú contextual está deshabilitado. Esto nos obliga a usar el atajo de teclado directamente para ver el código fuente.

> 💡 **Tip:** Cuando el clic derecho está bloqueado, casi siempre basta con usar los atajos de teclado del navegador (`Ctrl+U` para ver el código fuente, `F12` o `Ctrl+Shift+I` para las DevTools) o acceder manualmente a `view-source:` seguido de la URL. Rara vez estos bloqueos están implementados de forma robusta, porque dependen completamente del lado del cliente.
{: .prompt-tip }

## Análisis del código fuente

### Bloqueo de DevTools

Dentro del `<head>` del documento encontramos un primer bloque `<script>` ofuscado. Al desofuscarlo (ver sección siguiente) se reduce a lo siguiente:

```javascript
document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey && e.key === 'u') || (e.ctrlKey && e.key === 's')) {
        e.preventDefault();
    }
});
```

Es decir, el script únicamente intercepta las combinaciones `Ctrl+U` (ver código fuente) y `Ctrl+S` (guardar página) para cancelarlas con `preventDefault()`. Además, el `<body>` incluye los atributos:

```html
<body style="display:none" onload="document.body.style.display='block'" oncontextmenu="return false" onkeydown="return (event.ctrlKey) || true">
```

- `oncontextmenu="return false"` deshabilita el menú contextual (clic derecho).
- `onkeydown="return (event.ctrlKey) || true"` es, en la práctica, una condición que casi siempre evalúa a `true` y no bloquea nada adicional relevante.

> ⚠️ **Warning:** Ninguna de estas protecciones detiene realmente a un analista. Son controles puramente del lado del cliente y decorativos: cualquier persona puede ver el código fuente accediendo directamente a `view-source:http://<host>/` en la barra de direcciones, usando un proxy como Burp Suite, o simplemente descargando la respuesta con `curl`.
{: .prompt-warning }

### Ofuscación del formulario de contraseña

El segundo bloque `<script>` es mucho más grande y está ofuscado con un patrón muy característico de la librería **javascript-obfuscator**: un array gigante de strings que se reordena en tiempo de ejecución mediante una IIFE (Immediately Invoked Function Expression), y una función `_0x3b20(index)` que actúa como "diccionario" para traducir índices numéricos a los strings reales del array.

Para no perder tiempo desofuscando a mano, reproduje el entorno del navegador con **Node.js**, sustituyendo `document.getElementById` por un objeto simulado (*stub*) que permite ejecutar la función `items()` tal cual, capturando sus resultados:

```javascript
// Stub mínimo del DOM para poder ejecutar el script fuera del navegador
class El { constructor(){ this.value=""; this.innerHTML=""; this.style={}; } }
const passwordEl = new El();
const messageEl = new El();

global.document = {
  getElementById: function (id) {
    if (id === 'password') return passwordEl;
    if (id === 'message')  return messageEl;
    return new El();
  }
};

// (Aquí se pega tal cual el script ofuscado extraído de la página)
```

Con este *stub* se puede llamar directamente a la función de decodificación interna (`_0x3b20`) para volcar **todos** los elementos reales de los dos arrays de strings, en vez de intentar leerlos manualmente índice por índice desde el bytecode ofuscado.

> 💡 **Tip:** Cuando un reto usa `javascript-obfuscator`, casi siempre es más rápido ejecutar el script en un entorno controlado (Node.js con `document` simulado, o la propia consola del navegador) que intentar desofuscar la aritmética de índices a mano. El propio código ya sabe cómo traducirse a sí mismo.
{: .prompt-tip }

Tras volcar los arrays, la función `items()` desofuscada se reduce, en esencia, a lo siguiente:

```javascript
function items() {
    const password = document.getElementById('password').value;
    const messageEl = document.getElementById('message');

    // Array 1 (fragmentos "A")
    const A = [
        "Incorrect password",                          // A[0]
        "la vida es un rompecabezas",                  // A[1]  <- ya legible
        "al aniceic se mas rtea euq cneiiac",           // A[2]  <- anagrama por palabra
        "estas cerca",                                  // A[3]  <- ya legible
        "msa laev rdtae euq cnaun",                     // A[4]  <- anagrama ("mas vale tarde que nunca")
        "on ahy mla uqe rued rapa prmeeis",              // A[5]  <- anagrama
        "la crcitaap aech al trmaeso",                   // A[6]  <- anagrama
        "le euq no rcroe vluae",                         // A[7]  <- anagrama
        "al aenrsop a rgoac sree ut",                    // A[8]  <- anagrama
        "la cpinaicea es al reamd ed al eccinia"         // A[9]  <- anagrama
    ];

    // Array 2 (fragmentos "B")
    const B = [
        "getElementById",
        "ayh nieb y lma ne otsod dlosa",                 // B[1] <- anagrama
        "el pimteo es roo",                               // B[2] <- anagrama
        " no todos los dias son piezas perfectas",       // B[3] <- ya legible
        "pero aun no",                                    // B[4] <- ya legible
        "no odto lo ueq rlbail es oor",                   // B[5] <- anagrama
        "la iascdrdoiu tamo la gato",                     // B[6] <- anagrama
        "on edjse qeu un bonrme et spideet",               // B[7] <- anagrama
        "a sceve la negte no aerntneed",                  // B[8] <- anagrama
        "ermhba y seuño es ol que ssdteue ietnne"         // B[9] <- anagrama
    ];

    const cond1 = A[2] + A[1];   // A2 + A1
    const cond2 = A[2] + B[8];   // A2 + B8
    const cond3 = A[2] + B[3];   // A2 + B3
    const cond4 = A[1] + B[3];   // A1 + B3  <-- la única con ambos fragmentos legibles
    const cond5 = A[1] + B[8];   // A1 + B8
    const cond6 = B[8] + B[3];   // B8 + B3

    switch (true) {
        case password === cond1: messageEl.innerHTML = A[3] + ', ' + A[2] + '∅'; break;
        case password === cond2: messageEl.innerHTML = A[3] + ', ' + B[3] + '¼'; break;
        case password === cond3: messageEl.innerHTML = A[3] + ', ' + B[8] + '½'; break;
        case password === cond4: messageEl.innerHTML = A[2] + ' , ' + B[8] + '&nbsp;'; break;
        case password === cond5: messageEl.innerHTML = A[3] + ', ' + A[1] + '¼'; break;
        case password === cond6: messageEl.innerHTML = A[3] + ', ' + B[4] + '¼'; break;
        default:
            messageEl.innerHTML = "Non habet esse simplex XD";
            messageEl.style.color = "red";
    }
}
```

Este análisis revela dos cosas fundamentales:

1. El formulario **no envía ninguna petición al servidor**. Todo el "chequeo" de la contraseña ocurre en el navegador, comparando el valor introducido contra **seis combinaciones posibles** (concatenaciones de dos fragmentos cada una).
2. Ninguna de las seis ramas del `switch` corresponde a un mensaje de "éxito" explícito: todas devuelven textos con apariencia de pista ("estás cerca...") o directamente en el idioma ofuscado por palabras revueltas. La única diferencia visible es el **color del texto**: negro para cualquiera de las seis coincidencias válidas, rojo para cualquier otra entrada (incluyendo la cadena vacía).

## Identificación de los señuelos (red herrings)

Antes de decidir qué contraseña probar, investigué dos elementos que parecían prometedores y que, tras el análisis, resultaron ser **distracciones** deliberadas del reto.

### El comentario oculto en el HTML

Dentro del `<div id="tagreply">` había el siguiente comentario:

```html
<!-- 70103ff52f2f673fc6af91945cd502a9 -->
```

Al tener exactamente 32 caracteres hexadecimales, tiene la forma de un hash **MD5**, por lo que la hipótesis inicial fue que la flag ya venía resuelta directamente en el código fuente:

```text
cidsi{70103ff52f2f673fc6af91945cd502a9}
```

Esta hipótesis fue **descartada**, ya que la plataforma rechazó la flag. El identificador `tagreply` corresponde típicamente a *widgets* de chat embebido (Tawk.to, Crisp y similares), que suelen dejar identificadores de sesión con ese mismo formato hexadecimal. Todo indica que se trataba de un residuo de plantilla sin relación con el reto.

> ⚠️ **Warning:** No toda cadena con forma de hash en un código fuente es relevante para el reto. Antes de darla por buena conviene verificar el contexto (el nombre del elemento que la contiene, si aparece en scripts de terceros conocidos, etc.).
{: .prompt-warning }

### Análisis de la imagen `fusion.jpg`

El nombre del reto ("Fusión"), el hecho de que la imagen muestre la fusión de personajes de Dragon Ball, y el alias del autor ("Rick C-25") apuntaban a que la imagen pudiera ocultar datos mediante esteganografía o ser un archivo *polyglot*. Se descargó la imagen y se ejecutó una batería de comprobaciones estándar:

```bash
file fusion.jpg
exiftool fusion.jpg
strings -a fusion.jpg | grep -iE "cidsi|flag|password|md5"
binwalk fusion.jpg
binwalk -e fusion.jpg
steghide info fusion.jpg
```

Resultados:

- `file` confirma que es un JPEG progresivo válido, sin firmas de otro formato de archivo concatenado.
- `exiftool` no muestra campos EXIF ni comentarios adicionales, solo metadatos JFIF estándar.
- `strings` no encuentra ninguna cadena relacionada con la flag.
- `binwalk` no detecta ninguna firma de archivo adicional incrustado tras el marcador de fin de JPEG (`FF D9`).
- Un análisis manual de los marcadores JPEG (segmentos `APPn`, `COM`, etc.) tampoco reveló ningún comentario oculto.
- `steghide` no logra extraer nada con contraseñas candidatas obvias (cadena vacía, nombres temáticos del reto, etc.).

Con esto se concluyó que la imagen es puramente decorativa y forma parte de la temática del reto ("Fusión"), no del vector técnico de explotación.

> 📌 **Nota:** Descartar hipótesis de forma metódica y documentada es tan importante como encontrar la solución correcta. En un reto con múltiples señuelos, perder tiempo en pistas falsas es precisamente el objetivo de quien lo diseñó.
{: .prompt-info }

## Deofuscación y explotación

### Determinación de la contraseña correcta

Volviendo a las seis condiciones del `switch`, se observó un detalle clave: **cinco de las seis combinaciones incluyen al menos un fragmento con las letras de cada palabra revueltas** (un anagrama), mientras que **una única combinación está formada por dos fragmentos ya perfectamente legibles en español**, sin necesidad de resolver ningún anagrama:

```text
A[1] + B[3] =
"la vida es un rompecabezas" + " no todos los dias son piezas perfectas"
```

Al concatenar ambos fragmentos se obtiene una frase completa, coherente y gramaticalmente correcta:

```text
la vida es un rompecabezas no todos los dias son piezas perfectas
```

Esta es, con diferencia, la única combinación que un usuario podría **reconstruir y escribir de forma natural** tras desofuscar el array, sin necesidad de resolver acertijos adicionales. Todo apunta a que esta es la contraseña que el autor del reto diseñó como solución real, mientras que las otras cinco combinaciones (con fragmentos en forma de anagrama) actúan como ruido adicional para dificultar el reconocimiento de la combinación correcta a simple vista.

### Confirmación de la contraseña

Al introducir la frase en el campo de contraseña del formulario:

```text
la vida es un rompecabezas no todos los dias son piezas perfectas
```

El mensaje devuelto por la página cambia de rojo ("Incorrect password") a **negro**, mostrando el siguiente texto:

```text
al aniceic se mas rtea euq cneiiac , a sceve la negte no aerntneed
```

El cambio de color de rojo a negro confirma que la contraseña coincide con una de las seis condiciones válidas del `switch`, específicamente con `A[1] + B[3]`.

## Desciframiento del mensaje de respuesta

El mensaje devuelto está compuesto por dos fragmentos cuyas palabras tienen las letras revueltas (anagramas por palabra). Para resolverlo de forma sistemática, en lugar de intentarlo a ojo, se automatizó la búsqueda de anagramas contra un diccionario de español (`aspell-es`), comparando la "firma" de cada palabra (sus letras ordenadas alfabéticamente, sin tildes) contra las palabras del diccionario que comparten exactamente la misma firma:

```python
import unicodedata
import collections

def strip_accents(s: str) -> str:
    """Elimina tildes para poder comparar firmas de letras sin acentos."""
    return ''.join(
        c for c in unicodedata.normalize('NFD', s)
        if unicodedata.category(c) != 'Mn'
    )

# sig_map: firma de letras -> lista de palabras del diccionario con esa misma firma
sig_map = collections.defaultdict(list)
with open('es_words_clean.txt', encoding='utf-8') as f:
    for word in f:
        word = word.strip()
        base = strip_accents(word)
        signature = ''.join(sorted(base))
        sig_map[signature].append(word)

def resolver_palabra(palabra_revuelta: str) -> list:
    firma = ''.join(sorted(palabra_revuelta))
    return sig_map.get(firma, [])
```

Aplicando esta función a cada palabra del mensaje devuelto se obtienen las siguientes correspondencias:

| Palabra revuelta | Palabra real     |
|-------------------|-------------------|
| `aniceic`         | ciencia           |
| `rtea`             | arte               |
| `cneiiac`         | ciencia           |
| `sceve`            | veces              |
| `negte`            | gente              |
| `aerntneed`       | entenderá          |

Reconstruyendo la frase completa a partir de estas correspondencias, y respetando el formato exacto en el que la página la muestra (todo en minúsculas y sin tildes, tal como se renderiza en el navegador), el mensaje final queda así:

```text
la ciencia es mas arte que ciencia, a veces la gente no entendera
```

> 💡 **Tip:** Al calcular un hash sobre un texto obtenido de una página web, es fundamental respetar el formato **exacto** en el que ese texto se muestra en pantalla (mayúsculas/minúsculas, presencia o ausencia de tildes, espacios, comas), y no la versión "corregida" gramaticalmente. Una diferencia mínima en el string de entrada produce un hash MD5 completamente distinto.
{: .prompt-tip }

## Obtención de la flag

Con el texto exacto ya identificado, el último paso es calcular su hash **MD5**:

```bash
echo -n "la ciencia es mas arte que ciencia, a veces la gente no entendera" | md5sum
```

```text
5a8f7fbe0596858ed5c3bbf9557b890f
```

Envolviendo el hash en el formato indicado por el enunciado del reto, se obtiene la flag final:

```text
cidsi{5a8f7fbe0596858ed5c3bbf9557b890f}
```

Esta flag fue aceptada exitosamente por la plataforma de práctica del CITC. 🏁

## Conclusión y Aprendizajes

El reto "Fusión" es un buen ejercicio de **análisis de código del lado del cliente** más que de explotación de una vulnerabilidad tradicional. Su principal desafío no es técnico en el sentido de encontrar un fallo de seguridad explotable, sino **metodológico**: exige separar con disciplina las pistas reales de los numerosos señuelos colocados deliberadamente por el autor (el comentario HTML con apariencia de hash, la imagen temática sin esteganografía real, y cinco de las seis combinaciones de contraseña construidas a partir de anagramas sin salida).

Los aprendizajes principales que me deja este reto son:

- **Nunca confiar en protecciones del lado del cliente.** Los bloqueos de clic derecho y de atajos de teclado (`Ctrl+U`, `Ctrl+S`) son triviales de evadir y no deben disuadir de inspeccionar el código fuente de una aplicación web.
- **Automatizar la desofuscación en lugar de hacerla a mano.** Ejecutar el propio script ofuscado en un entorno controlado (Node.js con un `document` simulado) es mucho más fiable y rápido que intentar seguir manualmente la aritmética de índices de un ofuscador tipo `javascript-obfuscator`.
- **Verificar cada hipótesis antes de darla por buena.** Tanto el comentario HTML como la imagen parecían pistas prometedoras a primera vista, y ambas requirieron un proceso de descarte metódico (con herramientas como `exiftool`, `binwalk` y `steghide`) antes de continuar por el camino correcto.
- **Prestar atención a asimetrías en el código.** La clave para encontrar la contraseña correcta no fue "romper" ninguna protección, sino notar que, de seis combinaciones posibles, solo una estaba compuesta por texto ya legible en español, una señal deliberada dejada por el autor del reto para quien completara correctamente la fase de deofuscación.
- **Respetar el formato exacto del dato antes de hashear.** El paso final —calcular el MD5 del mensaje de respuesta— solo funciona si el texto de entrada coincide carácter por carácter con lo que la página realmente renderiza, incluyendo la ausencia de tildes y el uso de minúsculas.

En general, "Fusión" es un reto entretenido para practicar paciencia y método frente a código ofuscado, y un buen recordatorio de que, en seguridad web, **la superficie de ataque más obvia rara vez es donde termina el reto**.
