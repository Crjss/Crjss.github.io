---
title: "Management Wants a Word"
date: 2026-08-09 15:42:00 -0400
description: "Análisis forense de un triage KAPE de Windows: extracción de credenciales de Chrome mediante DPAPI, descifrado de contenedores VeraCrypt y recuperación de evidencia oculta."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [Forensics, Windows, DPAPI, Chrome, VeraCrypt, Cryptography, Hard]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays — Management Wants a Word
> - **Dificultad:** Hard
> - **Categoría:** Forensics / Windows / Cryptography
> - **Técnicas Clave:** DPAPI Master Key decryption, Chrome credential extraction (AES-256-GCM), VeraCrypt container mounting, Windows Registry forensics (SAM/SYSTEM/SECURITY), KAPE triage analysis

---

## Introducción

Este reto nos presenta un escenario de **housekeeping forense**: el equipo de limpieza encontró una laptop olvidada en la habitación 214, registrada a nombre de **Vera**. El departamento de IT realizó un triage completo con **KAPE** antes de limpiar el equipo. Nuestra misión es reconstruir la cadena de evidencia a partir de los artefactos dispersos en la imagen forense.

La narrativa del reto insinúa que Vera no era solo una huésped común, sino alguien con secretos bien guardados. La clave está en entender cómo Windows protege los secretos de Chrome mediante **DPAPI** y cómo un contenedor **VeraCrypt** puede ocultar la evidencia definitiva.

> El hint de la comunidad mencionaba la versión `1.26.29`. Ese número no era un PIM, sino la versión exacta de VeraCrypt utilizada para crear el contenedor.
{: .prompt-info }

---

## Reconocimiento Inicial

Tras descomprimir el archivo descargado, obtenemos un árbol de directorios generado por **KAPE** con los artefactos típicos de un sistema Windows:

```bash
tree -a management-wants-a-word-forensics-hh-day-14/
```

Los artefactos más relevantes identificados fueron:

| Artefacto | Ruta | Propósito |
|---|---|---|
| `SYSTEM` / `SAM` / `SECURITY` | `Windows/System32/config/` | Hives del registro para extraer DPAPI_SYSTEM |
| `NTUSER.DAT` | `Users/vera/` | Actividad del usuario Vera |
| `Login Data` | `Users/vera/.../Chrome/.../Default/` | Base de datos SQLite con credenciales de Chrome |
| `Local State` | `Users/vera/.../Chrome/.../` | Clave AES de Chrome encriptada con DPAPI |
| Master Keys DPAPI | `Roaming/Microsoft/Protect/<SID>/` | Claves maestras para descifrar blobs DPAPI |
| `backup` | `Users/vera/Documents/` | Archivo de 100 MiB, sospechoso de ser contenedor |

```bash
ls -la management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/Documents/backup
# Resultado: 104857600 bytes (exactamente 100 MiB)
```

> Un tamaño redondo como 100 MiB es un indicador clásico de un contenedor cifrado (VeraCrypt, TrueCrypt, etc.).
{: .prompt-tip }

---

## Extracción de la DPAPI_SYSTEM Key

El **Data Protection API (DPAPI)** de Windows protege secretos a nivel de usuario y máquina. Para descifrar los secretos de Vera offline, necesitamos la **DPAPI_SYSTEM key**, almacenada en el hive `SYSTEM`.

Utilizamos **Impacket** para extraerla:

```bash
secretsdump.py   -system management-wants-a-word-forensics-hh-day-14/KAPE/C/Windows/System32/config/SYSTEM   -security management-wants-a-word-forensics-hh-day-14/KAPE/C/Windows/System32/config/SECURITY   LOCAL
```

La salida reveló dos piezas críticas:

```
[*] DefaultPassword
(Unknown User):minivera

[*] DPAPI_SYSTEM
dpapi_machinekey:0x875427f6426f5dc4e318d1e6cfed17291295e4f7
dpapi_userkey:0xb0536fa518944b2520b5a5b9f5b513e3892224a1
```

- **`minivera`**: Contraseña del usuario Vera.
- **`dpapi_machinekey`** / **`dpapi_userkey`**: Claves necesarias para descifrar las Master Keys DPAPI.

---

## Descifrado de la Master Key DPAPI

Cada usuario tiene un directorio de **Master Keys** bajo `Protect/<SID>/`. Identificamos el SID y el GUID de la master key de Vera:

```bash
find management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/AppData/Roaming/Microsoft/Protect   -type f -printf '%f\n'
```

- **SID:** `S-1-5-21-2529683458-431225740-1723070931-1000`
- **Master Key GUID:** `c90719ef-5b98-474e-b934-136d606a702a`

Desciframos la master key utilizando la contraseña del usuario:

```bash
dpapi.py masterkey   -file 'management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/AppData/Roaming/Microsoft/Protect/S-1-5-21-2529683458-431225740-1723070931-1000/c90719ef-5b98-474e-b934-136d606a702a'   -sid 'S-1-5-21-2529683458-431225740-1723070931-1000'   -password 'minivera'
```

Resultado:

```
Decrypted key with User Key (SHA1)
Decrypted key: 0x5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c978c07e5004a0179d3a96df2468885a28175b0b02cc064445f116a752d2b3e9d40
```

Guardamos esta clave, ya que es el pilar para descifrar todo lo protegido por DPAPI en el perfil de Vera.

---

## Extracción y Descifrado de la Clave AES de Chrome

Chrome almacena una **clave AES de 32 bytes** en el archivo `Local State`, protegida por un blob DPAPI. El blob está codificado en Base64 y prefijado con los bytes literales `DPAPI`.

### Paso 1: Extraer el blob DPAPI

```bash
jq -r '.os_crypt.encrypted_key'   "management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/AppData/Local/Google/Chrome For Testing/User Data/Local State" |   base64 -d |   tail -c +6 > /tmp/chrome_blob.bin
```

### Paso 2: Descifrar con la Master Key

```python
from impacket.dpapi import DPAPI_BLOB

with open("/tmp/chrome_blob.bin", "rb") as f:
    blob = DPAPI_BLOB(f.read())

masterkey = bytes.fromhex(
    "5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c978c07e5004a0179d3a96df2468885a28175b0b02cc064445f116a752d2b3e9d40"
)

decrypted = blob.decrypt(masterkey)
print(f"Chrome AES Key: {decrypted.hex()}")
# Resultado: 206a39a0971327ea9487e4aea9844f5d3670162456982276939a712646da0b02
```

> Chrome v80+ utiliza el prefijo `v10` o `v11` en las contraseñas encriptadas, seguido de un nonce de 12 bytes y el ciphertext con tag de autenticación GCM.
{: .prompt-info }

---

## Descifrado de Credenciales Guardadas en Chrome

Con la clave AES de 32 bytes, procedemos a descifrar la base de datos `Login Data` de Chrome. Las contraseñas se almacenan con el formato:

```
[v10/v11][nonce:12 bytes][ciphertext][tag:16 bytes]
```

Utilizamos **AES-256-GCM** para descifrar:

```python
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_PATH = "management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/AppData/Local/Google/Chrome For Testing/User Data/Default/Login Data"
KEY = bytes.fromhex("206a39a0971327ea9487e4aea9844f5d3670162456982276939a712646da0b02")

db = sqlite3.connect(DB_PATH)

for url, username, encrypted in db.execute("""
    SELECT origin_url, username_value, password_value FROM logins
"""):
    blob = bytes(encrypted)
    if not blob.startswith((b"v10", b"v11")):
        continue

    nonce = blob[3:15]
    ciphertext_and_tag = blob[15:]

    password = AESGCM(KEY).decrypt(nonce, ciphertext_and_tag, None).decode("utf-8")
    print(f"URL:      {url}")
    print(f"Username: {username}")
    print(f"Password: {password}")
```

**Resultado:**

```
URL:      http://bytelotus.thm:8080/
Username: VeraSecretVault
Password: Wh4t1sV3raD0inG0nTh1sH0st
```

> La contraseña `Wh4t1sV3raD0inG0nTh1sH0st` es la llave que abre el contenedor final. El historial de Chrome confirmaba que Vera visitaba un portal llamado "SecureVault" en `bytelotus.thm:8080`.
{: .prompt-tip }

---

## Montaje del Contenedor VeraCrypt

El archivo `backup` (100 MiB) no tenía firma de ZIP ni 7z. Dado el nombre del personaje (**Vera**) y el hint de versión `1.26.29`, identificamos un contenedor **VeraCrypt**.

En Linux, podemos usar el binario de consola de VeraCrypt. Primero lo descargamos y extraemos:

```bash
cd /tmp
wget "https://launchpad.net/veracrypt/trunk/1.26.29/+download/veracrypt-1.26.29-setup.tar.bz2"
tar -xjf veracrypt-1.26.29-setup.tar.bz2
# Seleccionar opción 2 para extraer sin instalar
tar -xzf veracrypt_1.26.29_console_amd64.tar.gz
```

Creamos el punto de montaje y montamos el volumen:

```bash
sudo mkdir -p /mnt/vera

sudo /tmp/usr/bin/veracrypt -t   ~/tryhackme/hackerHoliday/managementWantsAWord/management-wants-a-word-forensics-hh-day-14/KAPE/C/Users/vera/Documents/backup   /mnt/vera
```

Parámetros interactivos:
- **Password:** `Wh4t1sV3raD0inG0nTh1sH0st`
- **PIM:** *(Enter para usar el valor por defecto)*
- **Keyfile:** *(Enter para ninguno)*
- **Protect hidden volume:** `n`

> Aunque Linux tiene `cryptsetup` con soporte para `tcrypt`, en este caso el binario oficial de VeraCrypt fue necesario porque la versión de `cryptsetup` disponible no reconoció la cabecera del contenedor con los parámetros estándar.
{: .prompt-warning }

---

## Recuperación de la Evidencia Final

Una vez montado, exploramos el contenido del volumen:

```bash
tree /mnt/vera
```

Estructura encontrada:

```
/mnt/vera/
├── $RECYCLE.BIN/
├── secret_financial_documents/
│   ├── important_invoice_byte_lotus.pdf
│   └── transactions_q3.csv
└── System Volume Information/
```

La evidencia definitiva estaba en el PDF. Al extraer las cadenas de texto del documento, encontramos la flag:

```bash
strings /mnt/vera/secret_financial_documents/important_invoice_byte_lotus.pdf | grep "THM{"
```

**Flag:**

```
THM{1t_w4s_V3r4_A11_Al0ng?!}
```

---

## Limpieza y Cierre

Tras recuperar la flag, es buena práctica desmontar el volumen y eliminar artefactos temporales:

```bash
sudo umount /mnt/vera
sudo /tmp/usr/bin/veracrypt -t -d
rm -rf /tmp/usr /tmp/veracrypt* /tmp/chrome_blob.bin
```

---

## Conclusión / Retroalimentación

**Management Wants a Word** es un reto forense excepcionalmente bien diseñado que simula una cadena de evidencia realista. La dificultad radica no en la complejidad individual de cada paso, sino en **ensamblar correctamente la cadena de descifrado**:

1. **Registry Hives → DPAPI_SYSTEM**
2. **DPAPI_SYSTEM + Password → Master Key**
3. **Master Key → Chrome AES Key**
4. **Chrome AES Key → Vault Password**
5. **Vault Password → VeraCrypt Container → Flag**

### Aprendizajes clave

- **DPAPI** es el mecanismo central de protección de secretos en Windows. Comprender cómo se encadenan las claves (System → User → Master → Application) es fundamental para forense en Windows.
- **Chrome** no almacena contraseñas en texto plano; requiere descifrar primero la clave del perfil (`Local State`) antes de poder atacar `Login Data`.
- **VeraCrypt** deja muy pocas huellas forenses. Sin el historial de navegación y la contraseña extraída, identificar el contenedor como tal sería extremadamente difícil.
- El hint de la versión `1.26.29` fue crucial. En retos de CTF, los números de versión no son decorativos; apuntan a herramientas, exploits o formatos específicos.

### Feedback de la sala

La narrativa del reto (la concierge Vera, los tickets de quejas, el "business model") añade una capa de inmersión que eleva la experiencia más allá de un simple ejercicio técnico. La progresión de pistas es justa: cada artefacto descubierto naturalmente conduce al siguiente. Altamente recomendado para practicar **análisis de triage KAPE** y **criptografía aplicada a forense**.

---

*¡Gracias por leer! Si tienes dudas o encontraste otra forma de resolverlo, déjala en los comentarios.*
