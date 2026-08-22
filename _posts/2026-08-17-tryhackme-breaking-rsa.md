---
title: "Breaking RSA"
date: 2026-08-17 17:25:00 -0400
description: "Analisis y explotacion de una implementacion debil de RSA donde los primos p y q son cercanos, permitiendo la factorizacion mediante el Metodo de Fermat para obtener la clave privada y acceder al sistema."
categories: [TryHackMe, Cyber Security 101]
tags: [RSA, Fermat, Cryptography, SSH, Python, Facil]
math: true
---

> 📌 **Ficha Tecnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala/Reto:** Cyber Security 101 — Breaking RSA
> - **Dificultad:** Facil
> - **Categoria:** Cryptography / Boot2Root
> - **Tecnicas Clave:** Reconocimiento de servicios, enumeracion web, extraccion de clave publica RSA, factorizacion de Fermat, generacion de clave privada, acceso SSH

---

## Introduccion

Este writeup documenta la resolucion completa de la sala **Breaking RSA** de TryHackMe, perteneciente a la ruta *Cyber Security 101*. La sala simula un escenario en el que la organizacion ficticia **JackFruit** utiliza una libreria criptografica obsoleta que genera claves RSA de forma insegura. Especificamente, los primos `p` y `q` elegidos para construir el modulo `n = p \times q` son **muy cercanos entre si**. Esta debilidad permite factorizar `n` mediante el **Metodo de Factorizacion de Fermat** y, a partir de `p` y `q`, reconstruir la clave privada completa, rompiendo asi la seguridad del sistema.

> 💡 **Tip:** El objetivo de este reto no es unicamente obtener la flag. El verdadero valor educativo reside en entender **por que** la proximidad de los primos destruye la seguridad de RSA, y como una mala implementacion criptografica puede invalidar incluso las claves de mayor tamano.
{: .prompt-tip }

---

## Reconocimiento

### Escaneo de puertos con Nmap

El primer paso en cualquier evaluacion de seguridad es identificar que servicios estan expuestos en la maquina objetivo. Para ello, utilizamos Nmap, el escaner de puertos mas utilizado en el mundo del pentesting.

```bash
nmap -sC -sV -p- 10.67.169.91
```

A continuacion, desgloso cada flag utilizada y su proposito:

| Flag | Significado | Proposito en este escaneo |
|------|-------------|---------------------------|
| `-sC` | Script scan (NSE default scripts) | Ejecuta los scripts de deteccion por defecto de Nmap, que identifican banners, versiones de servicios, configuraciones comunes y posibles vulnerabilidades conocidas sin ser intrusivos. |
| `-sV` | Version detection | Fuerza a Nmap a identificar la version exacta del software que corre en cada puerto abierto. Esto es critico porque versiones especificas pueden tener CVEs asociados. |
| `-p-` | Scan all ports | Indica a Nmap que escanee el rango completo de puertos TCP, desde el 1 hasta el 65535. Por defecto, Nmap solo escanea los 1000 puertos mas comunes, lo que podria omitir servicios en puertos no estandar. |

**Resultado del escaneo:**

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c4:e0:d7:93:56:4c:89:d3:ab:78:49:d7:6b:d7:49:7f (RSA)
|   256 68:95:6e:0b:a7:72:fe:ed:b2:c7:57:c1:2c:24:8f:e3 (ECDSA)
|_  256 42:d8:74:68:a7:55:6c:0d:e0:d9:95:23:87:00:7f:e0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Jack Of All Trades
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

**Analisis de los hallazgos:**

- **Puerto 22 (SSH):** Corre OpenSSH 8.2p1 sobre Ubuntu. El host key incluye tres algoritmos: RSA (3072 bits), ECDSA y ED25519. La presencia de SSH significa que, si logramos obtener credenciales o una clave privada, podriamos acceder al sistema de forma remota.
- **Puerto 80 (HTTP):** Corre nginx 1.18.0 sobre Ubuntu. El titulo de la pagina es "Jack Of All Trades", lo cual es coherente con el nombre de la organizacion ficticia "JackFruit" mencionada en la descripcion del reto.

**Conclusion del reconocimiento:** La maquina expone exactamente **dos servicios**: SSH y HTTP. Esto responde a la primera pregunta del reto. El vector de ataque probable pasa por el servidor web, ya que es la superficie mas amplia para la enumeracion.

---

## Enumeracion Web

### Descubrimiento de directorios con Gobuster

Con el servicio HTTP identificado, el siguiente paso logico es buscar directorios, archivos y rutas ocultas que el servidor web pueda estar sirviendo. Para esto utilizamos Gobuster, una herramienta de fuerza bruta de directorios extremadamente rapida.

```bash
gobuster dir -u http://10.67.169.91/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100
```

Desglose de los parametros:

| Parametro | Descripcion | Razon de uso |
|-----------|-------------|--------------|
| `dir` | Modo de enumeracion de directorios | Especifica que queremos buscar directorios y archivos, no subdominios ni DNS. |
| `-u` | URL objetivo | La direccion base sobre la cual se construiran las peticiones. |
| `-w` | Wordlist | La lista de palabras que Gobuster probara como posibles rutas. Se utilizo `big.txt` de SecLists, una de las wordlists mas completas para descubrimiento web. |
| `-t 100` | Threads | Numero de hilos concurrentes. 100 hilos acelera significativamente el escaneo sin sobrecargar excesivamente el servidor ni la red. |

**Resultado del escaneo:**

```text
/development          (Status: 301) [Size: 178] [--> http://10.67.169.91/development/]
```

**Analisis del hallazgo:**

- El codigo de estado HTTP **301** indica una redireccion permanente. Esto confirma que el directorio `/development` existe y el servidor redirige automaticamente a `/development/` (con la barra final).
- La palabra "development" es altamente sugestiva: en entornos reales, los directorios de desarrollo suelen contener archivos sensibles, backups, codigo fuente, configuraciones o claves que nunca deberian estar expuestos en produccion.

### Exploracion del directorio descubierto

Accedemos al directorio via navegador:

```bash
curl http://10.67.169.91/development/
```

Dentro encontramos dos archivos:

1. **`id_rsa.pub`** — Una clave publica RSA. Este es el artefacto critico del reto.
2. **`log.txt`** — Un archivo de registro que confirma el uso de una libreria criptografica obsoleta y revela que **el login SSH como root esta habilitado**.

Descargamos ambos archivos para analisis local:

```bash
wget http://10.67.169.91/development/id_rsa.pub
wget http://10.67.169.91/development/log.txt
```

> 💡 **Tip:** El archivo `log.txt` es una pista narrativa clave. Confirma que la organizacion usa una libreria que genera primos cercanos, validando asi el vector de ataque que debemos seguir.
{: .prompt-tip }

---

## Analisis de la Clave Publica RSA

### Longitud del modulo

Antes de intentar cualquier ataque criptografico, debemos caracterizar la clave. Verificamos su longitud en bits:

```bash
ssh-keygen -lf id_rsa.pub
```

| Parametro | Descripcion |
|-----------|-------------|
| `-l` | Muestra la huella (fingerprint) de la clave |
| `-f` | Especifica el archivo de clave a analizar |

**Salida:**

```text
4096 SHA256:DIqTDIhboydTh2QU6i58JP+5aDRnLBPT8GwVun1n0Co no comment (RSA)
```

**Interpretacion:** La clave tiene una longitud de **4096 bits**. En teoria, una clave RSA de 4096 bits es computacionalmente imposible de romper por fuerza bruta o metodos de factorizacion generales. Sin embargo, la descripcion del reto y el archivo `log.txt` nos advierten que la implementacion es defectuosa. Esto nos ensena una leccion fundamental: **el tamano de la clave no compensa una implementacion insegura**.

### Extraccion del modulo n

Para atacar la clave, necesitamos extraer sus parametros publicos: el exponente `e` y el modulo `n`. La clave publica SSH esta codificada en formato OpenSSH, que no es directamente procesable por herramientas criptograficas estandar como OpenSSL. Por tanto, primero la convertimos a formato PKCS#8 y luego extraemos el modulo.

```bash
ssh-keygen -e -m PKCS8 -f id_rsa.pub | openssl rsa -pubin -noout -modulus
```

Desglose del pipeline:

| Comando / Flag | Funcion |
|----------------|---------|
| `ssh-keygen -e` | Exporta la clave publica a un formato diferente |
| `-m PKCS8` | Especifica el formato de salida PKCS#8 (Public-Key Cryptography Standards #8), un estandar ampliamente soportado |
| `-f id_rsa.pub` | Archivo de entrada |
| `\| openssl rsa -pubin` | Pipea la salida a OpenSSL, interpretandola como una clave publica RSA |
| `-noout` | No muestra la clave completa, solo los datos solicitados |
| `-modulus` | Extrae y muestra unicamente el valor del modulo `n` en hexadecimal |

**Resultado (truncado por brevedad):**

```text
Modulus=EB661F287BC43C8FA92DDBA219F74EA467B5F2277B05095733B351AA7BCC3B66...
```

### Conversion del modulo a decimal

El valor del modulo `n` se obtiene en hexadecimal. Para operar con el en Python, lo convertimos a decimal usando la calculadora `bc` (basic calculator), que soporta precision arbitraria.

```bash
echo "ibase=16; EB661F287BC43C8FA92DDBA219F74EA4..." | BC_LINE_LENGTH=0 bc
```

| Componente | Descripcion |
|------------|-------------|
| `ibase=16` | Instruccion para `bc`: el numero de entrada esta en base 16 (hexadecimal) |
| `BC_LINE_LENGTH=0` | Variable de entorno que desactiva el salto de linea automatico en numeros largos. Sin esto, `bc` insertaria saltos de linea cada 70 caracteres, rompiendo el numero. |

El numero decimal resultante es extremadamente largo (4096 bits = ~1234 digitos decimales). Sus ultimos 10 digitos son: **`1225222383`**.

---

## La Matematica del Ataque: Factorizacion de Fermat

### Fundamento teorico

La seguridad de RSA se basa en la dificultad practica de factorizar el modulo `n = p \times q`, donde `p` y `q` son primos grandes. Cuando `p` y `q` se eligen de forma aleatoria y suficientemente distantes, no existe ningun algoritmo conocido que pueda factorizar `n` en un tiempo razonable.

Sin embargo, cuando `p` y `q` son **cercanos entre si**, aparece una debilidad matematica que el **Metodo de Factorizacion de Fermat** puede explotar eficientemente.

La base del metodo es la identidad algebraica de diferencia de cuadrados:

$$a^2 - b^2 = (a + b)(a - b)$$

Si logramos expresar `n` como una diferencia de cuadrados:

$$n = a^2 - b^2$$

Entonces podemos factorizarlo directamente como:
- $p = a + b$
- $q = a - b$

### Por que funciona cuando p y q estan cercanos

Supongamos que `p` y `q` son primos cercanos. Definimos:
- $a = \frac{p + q}{2}$ (el promedio de p y q)
- $b = \frac{p - q}{2}$ (la mitad de la diferencia)

Entonces:

$$n = p \times q = (a + b)(a - b) = a^2 - b^2$$

Como `p` y `q` estan cercanos, su promedio `a` esta muy cerca de $\sqrt{n}$, y su diferencia `b` es **pequena**. Esto significa que si comenzamos a probar valores de `a` desde $\lceil\sqrt{n}\rceil$ e incrementamos de uno en uno, encontraremos rapidamente un valor donde $a^2 - n$ sea un cuadrado perfecto.

> ⚠️ **Advertencia:** En una implementacion correcta de RSA, `p` y `q` se generan con una diferencia de miles de bits. Esto hace que `b` sea enorme y el Metodo de Fermat requiera millones de iteraciones, volviendolo computacionalmente inviable.
{: .prompt-warning }

### Visualizacion del algoritmo

El algoritmo de Fermat opera de la siguiente manera:

1. Calcular $a = \lfloor\sqrt{n}\rfloor$ (raiz cuadrada entera de n).
2. Incrementar `a` en 1.
3. Calcular $b^2 = a^2 - n$.
4. Verificar si $b^2$ es un cuadrado perfecto (es decir, si $\sqrt{b^2}$ es entero).
5. Si no lo es, volver al paso 2.
6. Si lo es, calcular $p = a + b$ y $q = a - b$.

Cuanto mas cercanos sean `p` y `q`, menos iteraciones se necesitan. En este reto, la diferencia entre `p` y `q` es solo **1502**, lo que hace que el algoritmo converja casi instantaneamente.

---

## Explotacion: Factorizacion y Generacion de la Clave Privada

### Instalacion de dependencias

Para implementar el ataque, necesitamos dos librerias de Python:

- **`pycryptodome`**: Permite importar, manipular y exportar claves RSA en formato estandar.
- **`gmpy2`**: Proporciona operaciones aritmeticas de precision arbitraria en C, incluyendo `isqrt` (raiz cuadrada entera), que es miles de veces mas rapida que la implementacion nativa de Python para numeros grandes.

```bash
pip install pycryptodome gmpy2
```

### Script de ataque completo

A continuacion se presenta el script `break_rsa.py` con explicaciones detalladas de cada seccion:

```python
#!/usr/bin/env python3
"""
Script para romper una implementacion debil de RSA usando
el Metodo de Factorizacion de Fermat.

Prerrequisitos:
    pip install pycryptodome gmpy2
"""

from gmpy2 import isqrt
from Crypto.PublicKey import RSA


def factorize(n):
    """
    Factoriza n usando el Metodo de Factorizacion de Fermat.

    El algoritmo busca el primer entero a > sqrt(n) tal que
    a^2 - n sea un cuadrado perfecto. Si p y q son cercanos,
    esto ocurre en muy pocas iteraciones.
    """
    # Caso especial: si n es par, uno de los factores es 2
    if (n & 1) == 0:
        return (n // 2, 2)

    # a = raiz cuadrada entera de n
    a = isqrt(n)

    # Caso especial: si n es un cuadrado perfecto
    if a * a == n:
        return a, a

    # Bucle principal de Fermat
    while True:
        a += 1                    # Incrementamos a desde sqrt(n)
        bsq = a * a - n           # Calculamos b^2 = a^2 - n
        b = isqrt(bsq)            # Raiz cuadrada entera de b^2
        if b * b == bsq:          # Verificamos si b^2 es cuadrado perfecto
            break

    # Una vez encontrado, p = a + b y q = a - b
    return a + b, a - b


# ===================================================================
# PASO 1: Cargar la clave publica y extraer parametros
# ===================================================================
pub_key = RSA.importKey(open("id_rsa.pub", "rb").read())
n = pub_key.n    # Modulo publico
 e = pub_key.e    # Exponente publico (tipicamente 65537)

print(f"[+] Longitud de la clave: {pub_key.size_in_bits()} bits")
print(f"[+] Ultimos 10 digitos de n: {str(n)[-10:]}")
print(f"[+] Exponente publico e = {e}")

# ===================================================================
# PASO 2: Factorizar n en primos p y q
# ===================================================================
print("\n[*] Factorizando n con el Metodo de Fermat...")
p, q = factorize(n)

print(f"[+] Primo p encontrado")
print(f"[+] Primo q encontrado")
print(f"[+] Diferencia |p - q| = {abs(p - q)}")

# ===================================================================
# PASO 3: Calcular la clave privada d
# ===================================================================
# La funcion totiente de Euler: phi(n) = (p - 1) * (q - 1)
phi = (p - 1) * (q - 1)

# d es el inverso modular de e modulo phi(n)
# Es decir: d * e ≡ 1 (mod phi(n))
# En Python 3.8+, pow(e, -1, phi) calcula esto directamente
d = pow(e, -1, phi)

print(f"[+] Clave privada d calculada")

# ===================================================================
# PASO 4: Reconstruir y exportar la clave privada
# ===================================================================
# RSA.construct() requiere los parametros: (n, e, d, p, q)
# Nota: gmpy2 devuelve objetos de tipo mpz. Es necesario convertirlos
# a int nativo de Python para evitar errores con pycryptodome.
priv_key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))

with open("id_rsa", "wb") as f:
    f.write(priv_key.export_key("PEM"))

print("[+] Clave privada exportada a 'id_rsa' en formato PEM")
```

> 💡 **Tip sobre la correccion de tipos:** En algunas versiones de `pycryptodome`, los objetos `mpz` de `gmpy2` no son compatibles directamente con `RSA.construct()`. La solucion es convertirlos explicitamente a `int` nativo de Python: `RSA.construct((int(n), int(e), int(d), int(p), int(q)))`. Este fue un error comun que aparecio durante la resolucion del reto.
{: .prompt-tip }

### Ejecucion y resultados

```bash
python3 break_rsa.py
```

**Salida completa:**

```text
[+] Longitud de la clave: 4096 bits
[+] Ultimos 10 digitos de n: 1225222383
[+] Exponente publico e = 65537

[*] Factorizando n con el Metodo de Fermat...
[+] Primo p encontrado
[+] Primo q encontrado
[+] Diferencia |p - q| = 1502
[+] Clave privada d calculada
[+] Clave privada exportada a 'id_rsa' en formato PEM
```

**Analisis de los resultados:**

- La diferencia entre `p` y `q` es de **1502**. Para primos de 2048 bits, esto es practicamente cero. Es como tener dos numeros del tamano del universo observable que difieren solo en 1502 unidades.
- Gracias a esta cercania, el Metodo de Fermat encontro la factorizacion en una cantidad de iteraciones despreciable, demostrando la catastrofica debilidad de la implementacion.
- Con `p` y `q` conocidos, calculamos `phi(n) = (p-1)(q-1)` y luego `d = e^{-1} mod phi(n)`, que es el componente secreto de la clave privada.

---

## Acceso al Sistema y Obtencion de la Flag

### Preparacion de la clave privada para SSH

Antes de usar la clave privada generada con SSH, debemos establecer los permisos correctos. SSH exige que las claves privadas tengan permisos restrictivos por razones de seguridad; de lo contrario, rechazara la conexion.

```bash
chmod 600 id_rsa
```

| Permiso | Significado |
|---------|-------------|
| `600` | Lectura y escritura unicamente para el propietario (`rw-------`). Ni grupo ni otros tienen ningun acceso. |

### Conexion SSH como root

Con la clave privada lista, nos autenticamos como el usuario `root`:

```bash
ssh -i id_rsa root@10.67.169.91
```

| Parametro | Descripcion |
|-----------|-------------|
| `-i id_rsa` | Especifica el archivo de identidad (clave privada) a utilizar para la autenticacion basada en clave publica. |
| `root@10.67.169.91` | Usuario y direccion del host remoto. El archivo `log.txt` confirmo que el acceso root via SSH esta habilitado. |

**Salida de la conexion:**

```text
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 17 Aug 2026 09:48:44 PM UTC

  System load:  0.16              Processes:             106
  Usage of /:   81.5% of 4.84GB   Users logged in:       0
  Memory usage: 16%               IPv4 address for ens5: 10.67.169.91
  Swap usage:   0%
```

### Obtencion de la flag

Una vez dentro del sistema con privilegios de root, localizamos y leemos la flag:

```bash
root@ip-10-67-169-91:~# ls
flag  snap
root@ip-10-67-169-91:~# cat flag
breakingRSAissuperfun20220809134031
```

---

## Resumen de Respuestas

A continuacion se resumen las respuestas a cada una de las preguntas planteadas en el reto:

| Pregunta | Respuesta |
|----------|-----------|
| ¿Cuantos servicios corren en la caja? | **2** (SSH en puerto 22 y HTTP en puerto 80) |
| ¿Cual es el nombre del directorio oculto? | **development** |
| ¿Cual es la longitud de la clave RSA? | **4096** bits |
| ¿Cuales son los ultimos 10 digitos de n? | **1225222383** |
| Factorizar n en primos p y q | *(Script Python)* |
| ¿Cual es la diferencia numerica entre p y q? | **1502** |
| Generar la clave privada usando p y q (e = 65537) | *(Script Python genera `id_rsa`)* |
| ¿Cual es la flag? | **breakingRSAissuperfun20220809134031** |

---

## Conclusion y Aprendizajes

### Lecciones tecnicas fundamentales

1. **El tamano de la clave no garantiza seguridad:** Una clave RSA de 4096 bits es teoricamente imposible de romper por metodos de factorizacion generales. Sin embargo, una implementacion defectuosa que genere primos cercanos invalida por completo esa fortaleza. La seguridad criptografica depende tanto del algoritmo como de su implementacion.

2. **La proximidad de primos es una falla catastrofica:** Cuando $p$ y $q$ son cercanos, el Metodo de Fermat convierte un problema de factorizacion aparentemente imposible en una tarea trivial que se resuelve en milisegundos. La diferencia de solo **1502** entre primos de 2048 bits es una debilidad que destruye por completo la seguridad de RSA.

3. **No reinventar la criptografia:** El uso de librerias obsoletas, no auditadas o implementaciones caseras de algoritmos criptograficos es uno de los errores mas peligrosos en seguridad de la informacion. Siempre se deben utilizar librerias ampliamente auditadas y mantenidas como OpenSSL, libsodium o las implementaciones estandar de los sistemas operativos modernos.

4. **El reconocimiento exhaustivo es indispensable:** El escaneo completo de puertos (`nmap -p-`) y la enumeracion web sistematica (`gobuster`) fueron fundamentales para descubrir el directorio `/development`. Sin este hallazgo inicial, no habriamos tenido acceso a la clave publica vulnerable y el ataque no habria sido posible.

### Retroalimentacion sobre la sala

La sala **Breaking RSA** es un ejercicio pedagogico excepcional. A diferencia de otros retos donde la dificultad radica en la complejidad tecnica o la cantidad de pasos, aqui el valor educativo reside en la **profundidad conceptual**: obliga al participante a comprender el porque matematico del fallo, no solo a ejecutar un exploit.

El reto conecta de manera brillante conceptos teoricos de criptografia (factorizacion de enteros, funcion totiente de Euler, inverso modular) con tecnicas practicas de pentesting (reconocimiento, enumeracion, scripting en Python). Es altamente recomendable para cualquier persona que este construyendo sus fundamentos en criptografia aplicada, seguridad ofensiva o auditoria de implementaciones criptograficas.

---

*Writeup redactado con fines exclusivamente educativos. Practica unicamente en entornos autorizados y nunca en sistemas ajenos sin permiso explicito.*
