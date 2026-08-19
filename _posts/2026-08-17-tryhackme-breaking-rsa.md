---
title: "Breaking RSA"
date: 2026-08-17 17:25:00 -0400
description: "Analisis y explotacion de una implementacion debil de RSA donde los primos p y q son cercanos, permitiendo la factorizacion mediante el Metodo de Fermat para obtener la clave privada y acceder al sistema."
categories: [TryHackMe, Cyber Security 101]
tags: [RSA, Fermat, Cryptography, SSH, Python, Facil]
math: true
---

> **Ficha Tecnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Cyber Security 101 — Breaking RSA
> - **Dificultad:** Facil
> - **Categoria:** Cryptography / Boot2Root
> - **Tecnicas Clave:** Reconocimiento de servicios, enumeracion web, extraccion de clave publica RSA, factorizacion de Fermat, generacion de clave privada, acceso SSH
{: .prompt-info }

---

## Introduccion

Este writeup documenta la resolucion de la sala **Breaking RSA** de TryHackMe, perteneciente a la ruta *Cyber Security 101*. La sala simula un escenario donde la organizacion **JackFruit** utiliza una libreria criptografica obsoleta que genera claves RSA de forma insegura: los primos `p` y `q` elegidos para construir el modulo `n = p \times q` son **muy cercanos entre si**. Esta debilidad permite factorizar `n` mediante el **Metodo de Factorizacion de Fermat** y, a partir de `p` y `q`, reconstruir la clave privada completa.

> El objetivo no es solo obtener la flag, sino entender **por que** la proximidad de los primos destruye la seguridad de RSA.
{: .prompt-tip }

---

## Reconocimiento

### Escaneo de puertos

Iniciamos con un escaneo completo de puertos para identificar los servicios expuestos en la maquina objetivo:

```bash
nmap -sC -sV -p- 10.67.169.91
```

| Flag | Descripcion |
|------|-------------|
| `-sC` | Ejecuta scripts de deteccion por defecto (banners, versiones, etc.) |
| `-sV` | Detecta versiones de los servicios activos |
| `-p-` | Escanea el rango completo de puertos TCP (1-65535) |

**Resultado del escaneo:**

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

La maquina expone **dos servicios**: SSH en el puerto 22 y un servidor web nginx en el puerto 80.

---

## Enumeracion Web

### Descubrimiento de directorios ocultos

Con el servicio HTTP identificado, procedemos a enumerar directorios y archivos ocultos:

```bash
gobuster dir -u http://10.67.169.91/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100
```

| Flag | Descripcion |
|------|-------------|
| `dir` | Modo de enumeracion de directorios |
| `-u` | URL objetivo |
| `-w` | Wordlist utilizada para la fuerza bruta de rutas |
| `-t 100` | 100 hilos en paralelo para acelerar el proceso |

**Hallazgo:**

```text
/development          (Status: 301) [Size: 178]
```

Dentro del directorio `/development` se encuentran dos archivos:

- `id_rsa.pub` — Clave publica RSA vulnerable.
- `log.txt` — Registro que confirma el uso de una libreria obsoleta y revela que **el login SSH como root esta habilitado**.

Descargamos la clave publica:

```bash
wget http://10.67.169.91/development/id_rsa.pub
```

---

## Analisis de la Clave Publica RSA

### Longitud del modulo

Verificamos la longitud de la clave publica:

```bash
ssh-keygen -lf id_rsa.pub
```

**Salida:**

```text
4096 SHA256:DIqTDIhboydTh2QU6i58JP+5aDRnLBPT8GwVun1n0Co no comment (RSA)
```

La clave tiene una longitud de **4096 bits**. A priori, esto deberia ser seguro; sin embargo, la debilidad reside en la **implementacion**, no en el tamano.

### Extraccion del modulo n

Para trabajar con la clave en un entorno criptografico, extraemos el modulo `n` en formato hexadecimal:

```bash
ssh-keygen -e -m PKCS8 -f id_rsa.pub | openssl rsa -pubin -noout -modulus
```

| Componente | Descripcion |
|------------|-------------|
| `ssh-keygen -e -m PKCS8` | Exporta la clave publica al formato estandar PKCS#8 |
| `openssl rsa -pubin -noout -modulus` | Interpreta la clave publica y extrae unicamente el valor del modulo `n` |

**Resultado (truncado):**

```text
Modulus=EB661F287BC43C8FA92DDBA219F74EA467B5F2277B05095733B351AA7BCC3B66...
```

### Conversion a decimal

Convertimos el valor hexadecimal a decimal para poder operar con el en Python:

```bash
echo "ibase=16; EB661F287BC43C8FA92DDBA219F74EA4..." | BC_LINE_LENGTH=0 bc
```

| Componente | Descripcion |
|------------|-------------|
| `ibase=16` | Indica a `bc` que el numero de entrada esta en base 16 (hexadecimal) |
| `BC_LINE_LENGTH=0` | Evita que `bc` inserte saltos de linea en numeros de gran longitud |

El numero decimal resultante termina en: `...1225222383`.

---

## La Matematica del Ataque: Factorizacion de Fermat

### Por que funciona?

La seguridad de RSA se basa en la dificultad practica de factorizar $n = p \times q$ cuando $p$ y $q$ son primos grandes y **aleatorios**. Sin embargo, si ambos primos son **cercanos entre si**, existe una debilidad matematica explotable.

La identidad algebraica clave es:

$$a^2 - b^2 = (a + b)(a - b)$$

Si reescribimos $n$ como una diferencia de cuadrados:

$$n = a^2 - b^2$$

Entonces:
- $p = a + b$
- $q = a - b$

El **Metodo de Fermat** busca el primer entero $a > \sqrt{n}$ tal que $a^2 - n$ sea un **cuadrado perfecto** ($b^2$). Cuando $p$ y $q$ estan cercanos, su promedio $a = (p+q)/2$ esta muy cerca de $\sqrt{n}$, y su diferencia $b = (p-q)/2$ es pequena. Por tanto, el algoritmo converge en **pocas iteraciones**.

> En una implementacion correcta de RSA, $p$ y $q$ se eligen con una diferencia de miles de bits, haciendo que Fermat requiera millones de iteraciones y sea computacionalmente inviable.
{: .prompt-warning }

---

## Explotacion: Factorizacion y Generacion de la Clave Privada

### Script de ataque

Instalamos las dependencias necesarias:

```bash
pip install pycryptodome gmpy2
```

Creamos el script `break_rsa.py`:

```python
#!/usr/bin/env python3
from gmpy2 import isqrt
from Crypto.PublicKey import RSA


def factorize(n):
    """Factoriza n usando el Metodo de Factorizacion de Fermat."""
    # Si n es par, uno de los factores es 2
    if (n & 1) == 0:
        return (n // 2, 2)

    a = isqrt(n)

    # Si n es un cuadrado perfecto
    if a * a == n:
        return a, a

    # Busqueda iterativa desde sqrt(n)
    while True:
        a += 1
        bsq = a * a - n
        b = isqrt(bsq)
        if b * b == bsq:
            break

    return a + b, a - b


# Cargar la clave publica
pub_key = RSA.importKey(open("id_rsa.pub", "rb").read())
n = pub_key.n
e = pub_key.e

print(f"[+] Longitud de la clave: {pub_key.size_in_bits()} bits")
print(f"[+] Ultimos 10 digitos de n: {str(n)[-10:]}")
print(f"[+] e = {e}")

# Factorizar n
print("\n[*] Factorizando n con Fermat...")
p, q = factorize(n)

print(f"[+] p = {p}")
print(f"[+] q = {q}")
print(f"[+] Diferencia |p - q| = {abs(p - q)}")

# Calcular la clave privada d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print(f"[+] d (clave privada) calculado")

# Generar y exportar la clave privada en formato PEM
priv_key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))
with open("id_rsa", "wb") as f:
    f.write(priv_key.export_key("PEM"))

print("[+] Clave privada guardada en 'id_rsa'")
```

> **Nota sobre la correccion:** En algunas versiones de `pycryptodome`, los objetos de `gmpy2` pueden causar errores de tipo. Por ello, es necesario convertirlos explicitamente a `int` nativo de Python al construir la clave: `RSA.construct((int(n), int(e), int(d), int(p), int(q)))`
{: .prompt-tip }

### Ejecucion

```bash
python3 break_rsa.py
```

**Salida:**

```text
[+] Longitud de la clave: 4096 bits
[+] Ultimos 10 digitos de n: 1225222383
[+] e = 65537

[*] Factorizando n con Fermat...
[+] p = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408518123
[+] q = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408516621
[+] Diferencia |p - q| = 1502
[+] d (clave privada) calculado
[+] Clave privada guardada en 'id_rsa'
```

La diferencia entre `p` y `q` es unicamente **1502**, una distancia insignificante para primos de 2048 bits. Esto explica por que Fermat factorizo `n` casi instantaneamente.

---

## Acceso al Sistema y Obtencion de la Flag

Con la clave privada generada, nos conectamos via SSH como el usuario `root`:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@10.67.169.91
```

| Comando | Descripcion |
|---------|-------------|
| `chmod 600 id_rsa` | Asigna permisos estrictos (solo lectura para el propietario), requerido por SSH |
| `ssh -i id_rsa` | Especifica la clave privada a utilizar para la autenticacion |

Una vez dentro del sistema:

```bash
root@ip-10-67-169-91:~# ls
flag  snap
root@ip-10-67-169-91:~# cat flag
breakingRSAissuperfun20220809134031
```

---

## Conclusion / Retroalimentacion

### Aprendizajes clave

1. **El tamano de la clave no lo es todo:** Una clave RSA de 4096 bits puede ser completamente insegura si la implementacion subyacente es defectuosa. La fortaleza de RSA depende tanto del tamano como de la **calidad de los primos** generados.

2. **La proximidad de primos destruye RSA:** Cuando $p$ y $q$ son cercanos, el Metodo de Fermat convierte un problema de factorizacion aparentemente imposible en una tarea trivial. La diferencia de solo **1502** entre primos de 2048 bits es una falla catastrofica.

3. **No reinventar la criptografia:** El uso de librerias obsoletas o implementaciones propias de algoritmos criptograficos es uno de los errores mas peligrosos en seguridad. Siempre se debe utilizar librerias auditadas y mantenidas (OpenSSL, libsodium, etc.).

4. **Reconocimiento exhaustivo:** El escaneo completo de puertos (`-p-`) y la enumeracion web (`gobuster`) fueron fundamentales para descubrir el vector de ataque. Sin el directorio `/development`, no habriamos tenido acceso a la clave publica vulnerable.

### Feedback de la sala

La sala **Breaking RSA** es un excelente ejercicio introductorio para comprender las consecuencias practicas de una mala implementacion criptografica. A diferencia de otros retos donde la dificultad radica en la complejidad tecnica, aqui el valor educativo reside en **entender el porque matematico** del fallo. Es altamente recomendable para cualquier persona que este construyendo sus fundamentos en criptografia aplicada y pentesting.

---

*Writeup redactado con fines educativos. Practica unicamente en entornos autorizados.*

