---
title: "Overheard at Breakfast"
date: 2026-08-01 09:40:00 -0400
description: "Writeup del reto OSINT 'Overheard at Breakfast' del evento Hacker Holidays en TryHackMe, donde una conversación aparentemente inocua revela pistas que conducen a un perfil oculto en Gravatar."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [OSINT, Gravatar, Social Engineering, Easy, Hacker Holidays]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays - Overheard at Breakfast
> - **Dificultad:** Fácil
> - **Categoría:** OSINT
> - **Técnicas Clave:** Análisis de imágenes, extracción de metadatos visuales, enumeración de perfiles por email, decodificación Base64

---

## Introducción

Durante el evento **Hacker Holidays 2026** de TryHackMe, participé en el reto **Overheard at Breakfast**, una sala de categoría **OSINT** y dificultad **Easy**. La premisa es sencilla pero efectiva: una conversación capturada en una terraza de desayuno contiene pistas suficientes para rastrear una cuenta que nadie debía encontrar.

El reto nos entrega una única imagen (`conversation.png`) que muestra un chat entre dos personas. El objetivo es analizar esa conversación, extraer los detalles relevantes y localizar la cuenta oculta que contiene la flag.

> Este writeup asume que ya has completado el reto y buscas documentar el proceso. Si aún no lo has resuelto, te recomiendo intentarlo primero.
{: .prompt-warning }

---

## Reconocimiento: Análisis de la conversación

Al abrir la imagen proporcionada, observamos una captura de pantalla de una conversación de chat entre dos usuarios: **Ponzi** y **Lambo**. La mayoría de los mensajes son triviales: hablan sobre el desayuno, el hotel y planes para el día. Sin embargo, el arte del OSINT radica en no solo leer lo que se dice, sino en identificar lo que se filtra sin intención.

Al analizar el chat con atención, se identifican dos pistas críticas:

1. **Una dirección de correo electrónico** mencionada explícitamente por Lambo.
2. **Una referencia a una plataforma gratuita** donde se pueden vincular perfiles y que su nombre comienza con la letra **"G"**.

> En OSINT, los detalles aparentemente irrelevantes suelen ser la llave maestra. No subestimes una dirección de email expuesta en un chat casual.
{: .prompt-tip }

---

## Extracción de pistas

### Correo electrónico expuesto

Dentro del flujo de la conversación, Lambo comparte su email para coordinar algo relacionado con el hotel:

```text
lambobytelotushotel@gmail.com
```

Este es nuestro punto de partida. Un email público puede actuar como un identificador único a través de múltiples servicios y plataformas.

### La pista de la plataforma "G"

En otro punto de la conversación, se hace referencia a una plataforma donde los usuarios pueden crear un perfil gratuito y vincular otras cuentas de redes sociales o medios. La pista clave es que el nombre de esta plataforma comienza con **"G"**.

Combinando estas dos piezas de información, la plataforma candidata es **Gravatar**, un servicio ampliamente utilizado que asocia avatares y perfiles públicos con direcciones de correo electrónico mediante hashes.

---

## Identificación de la plataforma: Gravatar

**Gravatar** (Globally Recognized Avatar) es un servicio de Automattic que permite a los usuarios asociar un avatar y un perfil público con su dirección de email. La URL del perfil y el avatar se generan a partir del hash MD5 o SHA-256 del email, lo que significa que cualquier persona con el email puede calcular el hash y buscar el perfil asociado.

> Gravatar es una mina de oro para OSINT. Muchos usuarios no son conscientes de que su perfil público, biografía e incluso enlaces a redes sociales quedan expuestos simplemente por usar su email en foros, comentarios de blogs o registros de servicios.
{: .prompt-info }

---

## Búsqueda del perfil oculto

### Paso 1: Calcular el hash del email

Para localizar el perfil de Gravatar, primero calculamos el hash SHA-256 del email en minúsculas:

```bash
echo -n "lambobytelotushotel@gmail.com" | sha256sum
```

El resultado es el identificador único del perfil en Gravatar.

### Paso 2: Consultar el perfil público

Utilizando el hash obtenido, accedemos a la URL del perfil de Gravatar:

```text
https://gravatar.com/profile/<hash-sha256>
```

Al cargar el perfil, observamos que pertenece a **Lambo**. El perfil contiene:
- Un avatar personalizado.
- Información básica de perfil.
- Una **biografía** con una cadena de texto larga y sospechosa.

---

## Decodificación de la flag

La biografía del perfil de Gravatar contiene una cadena codificada en **Base64**. Para decodificarla, podemos utilizar herramientas como **CyberChef**, la línea de comandos o cualquier decodificador online.

### Usando la terminal de Linux/macOS:

```bash
echo "VGhlIGZsYWcgaXM6IFRITXtTM2NyMVRfUHIwZmlsM19INXNfYjMzbl9JZGVudDFmaTNkfQ==" | base64 -d
```

### Usando CyberChef:

1. Abre [CyberChef](https://gchq.github.io/CyberChef/).
2. Arrastra la operación **"From Base64"** al panel de recetas.
3. Pega la cadena extraída de la biografía.
4. El resultado aparece en el panel de salida.

### Resultado:

```text
THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```

> **Flag obtenida:** `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}`
{: .prompt-tip }

---

## Conclusión / Retroalimentación

El reto **Overheard at Breakfast** es un excelente ejercicio introductorio al **OSINT** que demuestra cómo una simple conversación casual puede convertirse en una cadena de exposición de información sensible. Los puntos clave de aprendizaje son:

1. **La importancia del análisis detallado:** No basta con "leer" una captura de pantalla; hay que analizar cada fragmento de texto en busca de datos identificables (emails, nombres de usuario, referencias a plataformas).

2. **El email como pivote OSINT:** Una dirección de correo electrónico es uno de los identificadores más poderosos en investigaciones OSINT. Servicios como Gravatar, Have I Been Pwned, y motores de búsqueda avanzados pueden revelar una cantidad sorprendente de información a partir de un solo email.

3. **Conciencia sobre la exposición de perfiles públicos:** Muchos usuarios desconocen que plataformas como Gravatar exponen perfiles públicos vinculados a sus emails. Este reto sirve como recordatorio de revisar regularmente qué información pública está asociada a nuestros identificadores digitales.

En cuanto a la dificultad, el reto califica correctamente como **Easy**: no requiere herramientas complejas ni técnicas avanzadas, solo paciencia, atención al detalle y conocimiento de servicios comunes de identidad digital. Es ideal para quienes están comenzando en el mundo del OSINT y quieren entender cómo pequeñas filtraciones de información pueden escalarse rápidamente.

---

> "La seguridad no es un producto, sino un proceso." — Bruce Schneier
{: .prompt-info }
