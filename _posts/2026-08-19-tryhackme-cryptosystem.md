---
title: "Cryptosystem"
date: 2026-08-19 16:23:00 -0400
math: true
description: "Analisis y explotacion de una implementacion RSA vulnerable donde los primos p y q estan correlacionado
s, permitiendo una factorizacion trivial mediante el metodo de Fermat."
categories: [TryHackMe, Cyber Security 101]
tags: [RSA, Fermat Factorization, Cryptography, Python, Facil]
---

> 📌 **Ficha Tecnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Cryptosystem
> - **Dificultad:** Facil
> - **Categoria:** Criptografia
> - **Tecnicas Clave:** RSA Weak Key Generation, Fermat Factorization, Cryptanalysis

---

## Introduccion

**Cryptosystem** es una sala de TryHackMe disenada como continuacion natural al modulo de **John the Ripper** dentro 
de la ruta *Cyber Security 101*. El reto nos presenta un archivo con una implementacion de RSA que, a primera vista, 
parece robusta (claves de 1024 bits), pero esconde una vulnerabilidad critica en la generacion de los primos `p` y `q
`.

El objetivo es claro: **recuperar la clave privada y descifrar la flag** a partir del archivo interceptado.

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

### Que hace la funcion `primo(n)`?

La funcion recibe un numero `n` y realiza lo siguiente:

1. Si `n` es impar (`n & 1` es verdadero), le suma `2`.
2. Si `n` es par, le suma `1` para hacerlo impar.
3. Luego entra en un bucle `while` que incrementa de `2` en `2` hasta encontrar el siguiente numero primo.

> Dado que `p` es generado por `getPrime(1024)`, ya es un numero primo impar. Por lo tanto, `primo(p)` simplemente bu
sca **el siguiente primo impar despues de `p`**.
{: .prompt-info }

### La Vulnerabilidad

En una implementacion segura de RSA, los primos `p` y `q` deben ser generados de manera **independiente y aleatoria**
. Sin embargo, en este reto:

- `p` es un primo aleatorio de 1024 bits.
- `q` es el siguiente primo impar despues de `p`.

Esto significa que `p` y `q` estan **extremadamente cercanos**. La distancia entre dos primos consecutivos de 1024 bi
ts es, en la mayoria de los casos, muy pequena (tipicamente entre 2 y unos pocos cientos).

> **Impacto:** Cuando $$p \approx q$$ en RSA, el modulo $$n = p \times q$$ puede factorizarse eficientemente utilizan
do el **Metodo de Factorizacion de Fermat**, un algoritmo que data del siglo XVII.
{: .prompt-warning }

---

## Fundamento Matematico: Factorizacion de Fermat

El metodo de Fermat se basa en expresar un numero impar `n` como una diferencia de dos cuadrados:

$$
n = a^2 - b^2 = (a - b)(a + b)
$$

Donde:
- `a = (p + q) / 2` (el punto medio entre `p` y `q`)
- `b = (q - p) / 2` (la mitad de la distancia entre `p` y `q`)

Si `p` y `q` estan cercanos, entonces `b` es un numero pequeno y podemos aproximar:

$$
a \approx \sqrt{n}
$$

El algoritmo consiste en:
1. Calcular `a = ceil(sqrt(n))`.
2. Verificar si `a^2 - n` es un **cuadrado perfecto**.
3. Si lo es, hemos encontrado `b = sqrt(a^2 - n)`.
4. Recuperar los factores: `p = a - b` y `q = a + b`.
5. Si no lo es, incrementar `a` en 1 y repetir.

> En este reto, la diferencia entre `p` y `q` resulto ser de solo **170**, lo que hizo que la factorizacion fuera pra
cticamente inmediata (0 iteraciones adicionales despues de calcular `a = ceil(sqrt(n))`).
{: .prompt-tip }

---

## Explotacion Paso a Paso

### Paso 1: Extraer los valores del archivo

Del script interceptado, extraemos los valores publicos:

```python
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713
930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699
807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968
004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174
918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714
700796569746488209438597446475170891
c = 35911166643119869768822993855981354474352464607065008872417695550884163596827878445324149435737949936999760355048
846628349568468498631996431042544238860404893071772402008774433250364690207377347352520098902038607035654670274949061
784552574875609025998233645710726276732746634601672589944449997321641634130697056039189129180293419067312496183905606
312945164600720602820963381883632180183105582563335020754811325934747842725293181419830166847626118533500581354201774
365116465937035419949046324058916758489873554444903381626363608064378626793216121361474375787996966306319332777672635
30526354532898655937702383789647510
e = 0x10001  # 65537 en decimal
```

### Paso 2: Factorizar `n` con el metodo de Fermat

Implementamos el ataque en Python:

```python
from math import isqrt

# Valores del reto
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713
930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699
807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968
004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174
918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714
700796569746488209438597446475170891

# Metodo de Fermat
a = isqrt(n) + 1  # ceil(sqrt(n))

while True:
    b_squared = a * a - n
    b = isqrt(b_squared)

    if b * b == b_squared:
        p = a - b
        q = a + b
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        print(f"[+] q - p = {q - p}")
        break

    a += 1
```

**Resultado de la ejecucion:**

```text
[+] p = 1263180516080863630864361676703442633940804708205956144316013403227708420772815612704305464581819270470351071
714954437330594461973212130391140588790741164350042757466778951841664160724394258514366852377493761054286137528167604
79906270662609845420347955146870576553890171297646523338757410772905372711647921869
[+] q = 1263180516080863630864361676703442633940804708205956144316013403227708420772815612704305464581819270470351071
714954437330594461973212130391140588790741164350042757466778951841664160724394258514366852377493761054286137528167604
79906270662609845420347955146870576553890171297646523338757410772905372711647922039
[+] q - p = 170
```

Observamos que `q - p = 170`. Para primos de 1024 bits, esta distancia es insignificante, lo que confirma la vulnerab
ilidad.

### Paso 3: Calcular la clave privada y descifrar

Con `p` y `q` conocidos, procedemos con el flujo estandar de descifrado RSA:

```python
from Crypto.Util.number import long_to_bytes, inverse

# Valores ya factorizados
p = 12631805160808636308643616767034426339408047082059561443160134032277084207728156127043054645818192704703510717149
544373305944619732121303911405887907411643500427574667789518416641607243942585143668523774937610542861375281676047990
6270662609845420347955146870576553890171297646523338757410772905372711647921869
q = 12631805160808636308643616767034426339408047082059561443160134032277084207728156127043054645818192704703510717149
544373305944619732121303911405887907411643500427574667789518416641607243942585143668523774937610542861375281676047990
6270662609845420347955146870576553890171297646523338757410772905372711647922039
c = 35911166643119869768822993855981354474352464607065008872417695550884163596827878445324149435737949936999760355048
846628349568468498631996431042544238860404893071772402008774433250364690207377347352520098902038607035654670274949061
784552574875609025998233645710726276732746634601672589944449997321641634130697056039189129180293419067312496183905606
312945164600720602820963381883632180183105582563335020754811325934747842725293181419830166847626118533500581354201774
365116465937035419949046324058916758489873554444903381626363608064378626793216121361474375787996966306319332777672635
30526354532898655937702383789647510
e = 0x10001

# 1. Calcular phi(n) = (p-1)(q-1)
phi = (p - 1) * (q - 1)

# 2. Calcular la clave privada d = e^(-1) mod phi(n)
d = inverse(e, phi)

# 3. Descifrar: m = c^d mod n
m = pow(c, d, n)

# 4. Convertir a bytes
flag = long_to_bytes(m)
print(f"[+] FLAG: {flag.decode()}")
```

**Salida:**

```text
[+] FLAG: THM{Just_s0m3_small_amount_of_RSA!}
```

---

## Script Completo de Solucion

A continuacion, el script consolidado para resolver el reto de una sola ejecucion:

```python
#!/usr/bin/env python3
# Solucion para Cryptosystem - TryHackMe
# Tecnica: Factorizacion de Fermat (primos cercanos en RSA)

from math import isqrt
from Crypto.Util.number import long_to_bytes, inverse

# --- Datos del reto ---
c = 35911166643119869768822993855981354474352464607065008872417695550884163596827878445324149435737949936999760355048
846628349568468498631996431042544238860404893071772402008774433250364690207377347352520098902038607035654670274949061
784552574875609025998233645710726276732746634601672589944449997321641634130697056039189129180293419067312496183905606
312945164600720602820963381883632180183105582563335020754811325934747842725293181419830166847626118533500581354201774
365116465937035419949046324058916758489873554444903381626363608064378626793216121361474375787996966306319332777672635
30526354532898655937702383789647510
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713
930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699
807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968
004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174
918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714
700796569746488209438597446475170891
e = 0x10001

# --- Paso 1: Factorizacion de Fermat ---
print("[*] Iniciando factorizacion de Fermat...")
a = isqrt(n) + 1

while True:
    b_squared = a * a - n
    b = isqrt(b_squared)

    if b * b == b_squared:
        p = a - b
        q = a + b
        print(f"[+] Factorizacion exitosa en {a - isqrt(n) - 1} iteraciones adicionales")
        print(f"[+] p = {p}")
        print(f"[+] q = {q}")
        print(f"[+] Diferencia q-p = {q - p}")
        break

    a += 1

# --- Paso 2: Descifrado RSA ---
print("\n[*] Descifrando mensaje...")
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print(f"\n[+] FLAG: {flag.decode()}")
```

---

## Conclusion / Retroalimentacion

### Aprendizajes Clave

1. **La aleatoriedad e independencia son fundamentales en criptografia.** La correlacion entre `p` y `q` (donde `q` d
ependia directamente de `p`) fue la unica vulnerabilidad que colapso toda la seguridad de un sistema RSA de 2047 bits
.

2. **El tamano de la clave no importa si la implementacion es mala.** Un modulo de 2047 bits es, en teoria, computaci
onalmente imposible de factorizar con hardware actual. Sin embargo, una mala generacion de primos lo redujo a un prob
lema resoluble en milisegundos.

3. **El metodo de Fermat es un ataque clasico pero efectivo.** Aunque data del siglo XVII, sigue siendo relevante cua
ndo los desarrolladores cometen errores en la generacion de claves RSA.

### Recomendaciones para Implementaciones Seguras de RSA

> Para generar claves RSA seguras, `p` y `q` deben ser seleccionados de manera **independiente, aleatoria y uniforme*
* dentro del rango de bits especificado. Nunca debe existir una relacion matematica o algoritmica directa entre ambos
 primos.
{: .prompt-warning }

### Feedback de la Sala

**Cryptosystem** es una sala excelente para consolidar conceptos de criptografia asimetrica. La transicion desde el m
odulo de John the Ripper (fuerza bruta de hashes) hacia este analisis de implementacion criptografica vulnerable es n
atural y didactica. La sala no requiere herramientas externas complejas; todo el ataque puede ejecutarse con Python p
uro y la libreria `pycryptodome`, lo que permite centrarse en comprender la vulnerabilidad en lugar de lidiar con con
figuraciones de entorno.

La flag obtenida fue:

```text
THM{Just_s0m3_small_amount_of_RSA!}
```

---

*Writeup redactado el 19 de agosto de 2026. Si encuentras algun error o tienes sugerencias, no dudes en dejar un come
ntario.*

