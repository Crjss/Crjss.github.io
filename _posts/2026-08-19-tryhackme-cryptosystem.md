---
title: "Cryptosystem - TryHackMe"
date: 2026-08-19 16:23:00 -0400
math: true
description: "Analisis y explotacion de una implementacion RSA vulnerable donde los primos p y q estan correlacionados, permitiendo una factorizacion trivial mediante el metodo de Fermat."
categories: [TryHackMe, Criptografia]
tags: [RSA, Fermat Factorization, Cryptography, Python, Facil]
---

> 📌 **Ficha Tecnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala/Reto:** Cryptosystem
> - **Dificultad:** Facil
> - **Categoria:** Criptografia
> - **Tecnicas Clave:** RSA Weak Key Generation, Fermat Factorization, Cryptanalysis, Modular Arithmetic

---

## Introduccion

**Cryptosystem** es una sala de TryHackMe disenada como continuacion natural al modulo de **John the Ripper** dentro de la ruta *Cyber Security 101*. El reto nos presenta un archivo con una implementacion de RSA que, a primera vista, parece robusta —utiliza claves de 1024 bits, lo cual deberia ofrecer una seguridad teorica enorme—, pero esconde una vulnerabilidad critica en la generacion de los primos $p$ y $q$.

El objetivo es claro: **recuperar la clave privada y descifrar la flag** a partir del archivo interceptado. Sin embargo, el verdadero valor de este reto no reside unicamente en obtener la flag, sino en comprender **por que** una implementacion aparentemente correcta de RSA puede colapsar por completo debido a un error de diseno aparentemente menor.

> 💡 **Tip:** Este writeup esta pensado para quienes estan dando sus primeros pasos en criptografia aplicada a CTFs. Cada concepto se explica desde cero, pero sin perder el rigor tecnico.
{: .prompt-tip }

---

## Marco Teorico: Que es RSA y por que funciona?

Antes de analizar el codigo vulnerable, es fundamental entender los pilares de RSA. RSA es un sistema criptografico de clave publica inventado en 1977 por Ron **R**ivest, Adi **S**hamir y Leonard **A**dleman (de ahi el nombre). Su seguridad se basa en la dificultad computacional de factorizar numeros enteros grandes.

### Generacion de claves

1. Se eligen dos numeros primos grandes y distintos: $p$ y $q$.
2. Se calcula el modulo $n = p \times q$. Este valor $n$ es publico.
3. Se calcula la funcion totiente de Euler: $\varphi(n) = (p-1)(q-1)$. Este valor **debe mantenerse en secreto**.
4. Se elige un exponente publico $e$ (tipicamente $65537$, es decir, `0x10001`) tal que $1 < e < \varphi(n)$ y $\gcd(e, \varphi(n)) = 1$.
5. Se calcula el exponente privado $d$ como el inverso multiplicativo de $e$ modulo $\varphi(n)$:

$$
d \equiv e^{-1} \pmod{\varphi(n)}
$$

Esto significa que $d$ es el numero que cumple $(d \times e) \equiv 1 \pmod{\varphi(n)}$.

### Cifrado y descifrado

- **Cifrado:** Dado un mensaje $m$ (convertido a numero), el texto cifrado $c$ se calcula como:

$$
c \equiv m^e \pmod{n}
$$

- **Descifrado:** El mensaje original se recupera con la clave privada $d$:

$$
m \equiv c^d \pmod{n}
$$

### Donde reside la seguridad?

La seguridad de RSA depende exclusivamente de que un atacante que conoce $n$, $e$ y $c$ **no pueda calcular $d$**. Y la unica forma conocida de calcular $d$ es conocer $\varphi(n)$, lo cual a su vez requiere conocer $p$ y $q$. Por lo tanto: **factorizar $n$ es equivalente a romper RSA**.

Cuando $p$ y $q$ son primos aleatorios e independientes de aproximadamente 1024 bits cada uno, $n$ tiene 2048 bits. Factorizar un numero de 2048 bits con los algoritmos conocidos y el hardware actual es computacionalmente inviable.

> ⚠️ **Advertencia:** El tamano de la clave no garantiza seguridad si la implementacion tiene fallas en la generacion de primos. Este reto es la prueba perfecta de ello.
{: .prompt-warning }

---

## Analisis del Codigo Vulnerable

Al inspeccionar el archivo recuperado, encontramos el siguiente script en Python:

```python
from Crypto.Util.number import *
from flag import FLAG

def primo(n):
    n += 2 if n & 1 else 1
    while not isPrime(n):
        n += 2
    return n

p = getPrime(1024)
q = primo(p)
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(bytes_to_long(FLAG.encode()), e, n)
```

Vamos a analizar este codigo linea por linea para entender exactamente que esta ocurriendo.

### Importaciones y funcion `primo(n)`

```python
from Crypto.Util.number import *
```

Esta linea importa funciones utiles del modulo `Crypto.Util.number` de la libreria `pycryptodome`, entre ellas:
- `getPrime(bits)`: Genera un numero primo aleatorio del tamano especificado en bits.
- `isPrime(n)`: Verifica si un numero es primo utilizando pruebas probabilisticas.
- `inverse(a, m)`: Calcula el inverso multiplicativo modular de $a$ modulo $m$.
- `bytes_to_long(data)`: Convierte una secuencia de bytes a un entero largo.

```python
def primo(n):
    n += 2 if n & 1 else 1
    while not isPrime(n):
        n += 2
    return n
```

Esta es la funcion critica. Desglosemos su comportamiento paso a paso:

1. `n & 1` realiza una operacion **AND bit a bit** con `1`. Si el resultado es `1`, el numero es impar; si es `0`, es par.
2. Si `n` es impar (`n & 1` es verdadero), le suma `2`: `n += 2`.
3. Si `n` es par (`n & 1` es falso), le suma `1`: `n += 1`.
4. El bucle `while not isPrime(n)` incrementa `n` de `2` en `2` hasta encontrar un numero primo.

> 💡 **Tip:** La operacion `n & 1` es equivalente a `n % 2`, pero mas eficiente a nivel de bits. Es una forma comun en programacion de verificar la paridad de un numero entero.
{: .prompt-tip }

### La generacion de claves: donde esta el error?

```python
p = getPrime(1024)
q = primo(p)
```

Aqui reside la vulnerabilidad:

- `p` es un primo aleatorio de 1024 bits generado correctamente.
- `q` NO es un primo aleatorio independiente. Es el resultado de llamar a `primo(p)`, lo que significa que es **el siguiente primo impar despues de $p$**.

Como `p` ya es un primo impar (todos los primos mayores que 2 son impares), la funcion `primo(p)` simplemente busca el siguiente primo impar comenzando desde $p + 2$. Esto implica que $q$ esta extremadamente cerca de $p$.

> ⚠️ **Advertencia:** En una implementacion segura de RSA, `p` y `q` deben ser generados de manera **independiente y aleatoria**. Cualquier correlacion matematica entre ellos puede introducir vulnerabilidades graves.
{: .prompt-warning }

### Que tan cerca estan $p$ y $q$?

La distancia entre dos primos consecutivos de 1024 bits es, en la gran mayoria de los casos, muy pequena. Esto se debe al **Teorema de los Numeros Primos**, que nos dice que la densidad de primos alrededor de un numero $x$ es aproximadamente $1 / \ln(x)$. Para numeros de 1024 bits, $\ln(x) \approx 710$, por lo que el gap promedio entre primos consecutivos es de aproximadamente 710. En la practica, muchos gaps son mucho menores (2, 4, 6, etc.).

En este reto, la distancia resulto ser de solo **170**, lo cual es ridiculamente pequena para primos de este tamano.

---

## Fundamento Matematico: Factorizacion de Fermat

Cuando los factores $p$ y $q$ de un numero $n$ estan muy cercanos entre si, existe un metodo de factorizacion extremadamente eficiente conocido como el **Metodo de Factorizacion de Fermat**, desarrollado por Pierre de Fermat en el siglo XVII.

### La idea central

El metodo se basa en la identidad algebraica de la diferencia de cuadrados:

$$
n = a^2 - b^2 = (a - b)(a + b)
$$

Si logramos expresar $n$ de esta manera, entonces automaticamente obtenemos los factores:

$$
p = a - b \quad \text{y} \quad q = a + b
$$

Despejando $a$ y $b$ en funcion de $p$ y $q$:

$$
a = \frac{p + q}{2} \quad \text{y} \quad b = \frac{q - p}{2}
$$

### Por que funciona cuando $p \approx q$?

Si $p$ y $q$ estan muy cerca, entonces:

- $a = \frac{p + q}{2}$ es aproximadamente igual a $\sqrt{n}$, ya que:

$$
\sqrt{n} = \sqrt{p \times q} \approx \sqrt{\left(\frac{p+q}{2}\right)^2} = \frac{p+q}{2} = a
$$

- $b = \frac{q - p}{2}$ es un numero **pequeno**.

Esto significa que podemos comenzar a probar valores de $a$ a partir de $\lceil\sqrt{n}\rceil$ (el entero inmediatamente superior a la raiz cuadrada de $n$) y verificar si $a^2 - n$ es un cuadrado perfecto. Como $b$ es pequeno, encontraremos la solucion en muy pocas iteraciones —en este caso, **cero iteraciones adicionales**.

### Algoritmo paso a paso

1. Calcular $a = \lceil\sqrt{n}\rceil$.
2. Calcular $b^2 = a^2 - n$.
3. Verificar si $b^2$ es un cuadrado perfecto (es decir, si $\sqrt{b^2}$ es un numero entero).
4. Si lo es, calcular $b = \sqrt{a^2 - n}$ y obtener $p = a - b$ y $q = a + b$.
5. Si no lo es, incrementar $a$ en 1 y volver al paso 2.

> 💡 **Tip:** La funcion `isqrt(n)` de Python (disponible desde Python 3.8 en el modulo `math`) calcula la raiz cuadrada entera de $n$, es decir, el mayor entero $x$ tal que $x^2 \leq n$. Esto es exactamente lo que necesitamos para implementar este algoritmo de forma eficiente.
{: .prompt-tip }

---

## Explotacion Paso a Paso

### Paso 1: Extraer los valores publicos del archivo

Del script interceptado, extraemos los valores que el atacante conoceria en un escenario real (ya que son publicos o se filtran):

```python
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891
c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510
e = 0x10001  # 65537 en decimal
```

- $n$ es el modulo publico. Tiene 2047 bits, lo cual normalmente seria imposible de factorizar.
- $c$ es el texto cifrado (la flag cifrada).
- $e$ es el exponente publico, un valor estandar en RSA.

### Paso 2: Factorizar $n$ mediante el metodo de Fermat

Implementamos el ataque en Python. Cada linea esta comentada para claridad:

```python
from math import isqrt

# Valor del modulo n extraido del script interceptado
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891

# --- Metodo de Fermat ---
# Calculamos a = ceil(sqrt(n)). Como isqrt(n) devuelve el entero truncado,
# sumamos 1 para obtener el siguiente entero.
a = isqrt(n) + 1

while True:
    # Calculamos b^2 = a^2 - n. Si b^2 es un cuadrado perfecto,
    # entonces hemos encontrado los factores.
    b_squared = a * a - n
    b = isqrt(b_squared)

    # Verificamos si b^2 es realmente un cuadrado perfecto.
    # Esto ocurre cuando b * b == b_squared (sin decimales).
    if b * b == b_squared:
        p = a - b
        q = a + b
        print(f"[+] Factorizacion exitosa!")
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        print(f"[+] Diferencia q - p = {q - p}")
        break

    # Si no es cuadrado perfecto, probamos con el siguiente a.
    a += 1
```

**Resultado de la ejecucion:**

```text
[+] Factorizacion exitosa!
[+] p = 126318051608086363086436167670344263394080470820595614431601340322770842077281561270430546458181927047035107171495443733059446197321213039114058879074116435004275746677895184166416072439425851436685237749376105428613752816760479906270662609845420347955146870576553890171297646523338757410772905372711647921869
[+] q = 126318051608086363086436167670344263394080470820595614431601340322770842077281561270430546458181927047035107171495443733059446197321213039114058879074116435004275746677895184166416072439425851436685237749376105428613752816760479906270662609845420347955146870576553890171297646523338757410772905372711647922039
[+] Diferencia q - p = 170
```

Observamos que $q - p = 170$. Para primos de 1024 bits, esta distancia es insignificante. Como $b = \frac{q - p}{2} = 85$, el valor de $b$ es tan pequeno que $a^2 - n$ fue un cuadrado perfecto **inmediatamente**, sin necesidad de iterar.

### Paso 3: Calcular la clave privada y descifrar el mensaje

Con $p$ y $q$ conocidos, recuperamos la clave privada $d$ y desciframos el mensaje siguiendo el protocolo RSA estandar:

```python
from Crypto.Util.number import long_to_bytes, inverse

# Valores ya factorizados en el paso anterior
p = 126318051608086363086436167670344263394080470820595614431601340322770842077281561270430546458181927047035107171495443733059446197321213039114058879074116435004275746677895184166416072439425851436685237749376105428613752816760479906270662609845420347955146870576553890171297646523338757410772905372711647921869
q = 126318051608086363086436167670344263394080470820595614431601340322770842077281561270430546458181927047035107171495443733059446197321213039114058879074116435004275746677895184166416072439425851436685237749376105428613752816760479906270662609845420347955146870576553890171297646523338757410772905372711647922039
c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510
e = 0x10001

# --- Paso 3.1: Calcular phi(n) ---
# phi(n) = (p-1)(q-1) es el orden del grupo multiplicativo modulo n.
# Este valor es secreto y es la base para calcular la clave privada.
phi = (p - 1) * (q - 1)

# --- Paso 3.2: Calcular la clave privada d ---
# d es el inverso multiplicativo de e modulo phi(n).
# Es decir, d * e ≡ 1 (mod phi(n)).
# La funcion inverse() de pycryptodome resuelve esto eficientemente
# usando el Algoritmo Extendido de Euclides.
d = inverse(e, phi)

# --- Paso 3.3: Descifrar el mensaje ---
# m = c^d mod n. Esto revierte la operacion de cifrado.
m = pow(c, d, n)

# --- Paso 3.4: Convertir a texto legible ---
# El mensaje m es un numero entero. Lo convertimos a bytes y luego a string.
flag = long_to_bytes(m)
print(f"[+] FLAG: {flag.decode()}")
```

**Salida:**

```text
[+] FLAG: THM{Just_s0m3_small_amount_of_RSA!}
```

> 💡 **Tip:** La funcion `pow(c, d, n)` de Python es fundamental aqui. No calcula $c^d$ directamente (lo cual seria un numero astronomicamente grande) sino que utiliza **exponenciacion modular**, calculando $(c^d) \bmod n$ de forma eficiente mediante el metodo de exponenciacion por cuadrados.
{: .prompt-tip }

---

## Script Completo de Solucion

A continuacion, el script consolidado que ejecuta todo el ataque de principio a fin:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Solucion para Cryptosystem - TryHackMe
Tecnica: Factorizacion de Fermat (primos cercanos en RSA)

Este script realiza un ataque completo a una implementacion RSA vulnerable
 donde los primos p y q estan correlacionados (q es el siguiente primo despues de p).
'''

from math import isqrt
from Crypto.Util.number import long_to_bytes, inverse

# --- Datos publicos extraidos del archivo interceptado ---
c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891
e = 0x10001

# --- Paso 1: Factorizacion de Fermat ---
print("[*] Iniciando factorizacion de Fermat...")
a = isqrt(n) + 1  # ceil(sqrt(n))

while True:
    b_squared = a * a - n
    b = isqrt(b_squared)

    if b * b == b_squared:
        p = a - b
        q = a + b
        iteraciones = a - isqrt(n) - 1
        print(f"[+] Factorizacion exitosa en {iteraciones} iteraciones adicionales")
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        print(f"[+] Diferencia q - p = {q - p}")
        break

    a += 1

# --- Paso 2: Descifrado RSA ---
print("\n[*] Calculando clave privada y descifrando...")
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print(f"\n[+] FLAG: {flag.decode()}")
```

---

## Conclusion y Aprendizajes

### Lecciones fundamentales

1. **La aleatoriedad e independencia son pilares innegociables en criptografia.**
   La correlacion entre $p$ y $q$ —donde $q$ dependia algoritmicamente de $p$ mediante la funcion `primo(p)`— fue la unica vulnerabilidad necesaria para colapsar por completo la seguridad de un sistema RSA con un modulo de 2047 bits. Un solo error de diseno anulo decadas de avances en criptografia computacional.

2. **El tamano de la clave no compensa una mala implementacion.**
   Un modulo de 2047 bits es, en teoria, computacionalmente imposible de factorizar con el hardware y algoritmos conocidos actuales. Sin embargo, una mala generacion de primos redujo el problema a una simple resta y una raiz cuadrada, resoluble en milisegundos con Python estandar.

3. **Los ataques clasicos nunca mueren.**
   El metodo de factorizacion de Fermat data del siglo XVII, pero sigue siendo extremadamente relevante cuando los desarrolladores cometen errores en la generacion de claves RSA. La criptografia moderna no solo exige algoritmos robustos, sino tambien implementaciones impecables.

### Recomendaciones para implementaciones seguras de RSA

> 🛡️ **Recomendacion de seguridad:** Para generar claves RSA seguras, los primos $p$ y $q$ deben seleccionarse de manera **independiente, aleatoria y uniforme** dentro del rango de bits especificado. Nunca debe existir una relacion matematica, algoritmica o deterministica directa entre ambos primos. Ademas, es una buena practica verificar que $|p - q|$ sea suficientemente grande y que ambos primos pasen pruebas de primalidad robustas.
{: .prompt-warning }

### Retroalimentacion sobre la sala

**Cryptosystem** es una sala excelente para consolidar conceptos de criptografia asimetrica, especialmente para quienes provienen del modulo de John the Ripper. La transicion desde el analisis de hashes (fuerza bruta) hacia el analisis de implementaciones criptograficas vulnerables es natural, didactica y extremadamente valiosa.

La sala no requiere herramientas externas complejas ni entornos de explotacion elaborados. Todo el ataque puede ejecutarse con Python puro y la libreria `pycryptodome`, lo que permite al participante centrarse exclusivamente en comprender la naturaleza de la vulnerabilidad en lugar de perder tiempo en configuraciones de entorno.

La flag obtenida fue:

```text
THM{Just_s0m3_small_amount_of_RSA!}
```

---

*Writeup redactado el 19 de agosto de 2026. Si encuentras algun error, tienes sugerencias o deseas discutir algun concepto tecnico, no dudes en dejar un comentario.*
