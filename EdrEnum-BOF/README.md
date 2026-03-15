# EDR-Enum-BOF — AdaptixC2 Extension

Service and driver enumeration BOF for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2), ported from [CS-EDR-Enumeration](https://github.com/VirtualAlllocEx/CS-EDR-Enumeration) by VirtualAllocEx.

Enumerates running Win32 services and kernel drivers via the Service Control Manager (SCM), then automatically cross-references the results against a signature database of **444 signatures across 48 security vendors** to identify AV, EDR, and EPP products present on the target.

**NOISE: \* MINIMAL** — runs entirely in-process inside the agent. No child processes, no PowerShell, no CLR load, no ETW providers triggered.

---

## Commands

| Command | Description |
|---|---|
| `edr_both` | Enumerate services + drivers (default) |
| `edr_svc` | Enumerate Win32 services only |
| `edr_drv` | Enumerate kernel drivers only |
| `edr_remote` | Enumerate Remote LsarLookupNames + SCM |


---

## Output example `edr_both`

```
====================================================
  [~] THREAT LEVEL: MODERATE - AV + Telemetry
====================================================

Services matched (6):
  [AV]        Microsoft - Defender Core Service  (MDCoreSvc)
  [AV]        Microsoft - Defender Firewall  (mpssvc)
  [AV]        Microsoft - Security Health  (SecurityHealthService)
  [Telemetry] Microsoft - Sysmon 64  (Sysmon64)
  [AV]        Microsoft - Windows Defender AV  (WinDefend)
  [AV]        Microsoft - Security Center  (wscsvc)

Drivers matched (2):
  [Telemetry] Microsoft - Sysmon Driver  (SysmonDrv)
  [AV]        Microsoft - Defender Minifilter  (WdFilter)

88 services + 121 drivers enumerated  |  6 svc + 2 drv hits
```

## Output example `edr_remote`

```
=== EDR Remote Enum: \\DC.redtops.htb ===
[*] Using current beacon token

[*] Checking installed services via LsarLookupNames...
  [INSTALLED][AV ] Microsoft | Windows Defender AV | AV  (svc: WinDefend)
  [INSTALLED][EDR] Microsoft | Defender for Endpoint | EDR  (svc: Sense)
  [INSTALLED][AV ] Microsoft | Defender Network Inspection | AV  (svc: WdNisSvc)
  [INSTALLED][AV ] Microsoft | Defender Firewall | AV  (svc: mpssvc)
  [INSTALLED][AV ] Microsoft | Security Health | AV  (svc: securityhealthservice)

[*] Checking kernel drivers via remote SCM...
  [INSTALLED][EDR] Microsoft | Defender for Endpoint Minifilter | EDR  (drv: MsSecFlt)
  [INSTALLED][AV ] Microsoft | Defender Boot Driver | AV  (drv: WdBoot)
  [INSTALLED][AV ] Microsoft | Defender Minifilter | AV  (drv: WdFilter)
  [INSTALLED][AV ] Microsoft | Defender NIS Driver | AV  (drv: WdNisDrv)

====================================================
  Target: \\DC.redtops.htb
  [INSTALLED] = registered in SCM (may be stopped)
====================================================
```

### Threat levels

| Level | Meaning |
|---|---|
| `HIGH` | EDR detected — kernel callbacks, behavioral engine, cloud analytics likely active |
| `MODERATE` | AV + Telemetry — scanning and event forwarding to SOC |
| `LOW-MOD` | AV only — file scanning and heuristics |
| `LOW` | EPP / non-EDR — minimal real-time capability |
| `UNKNOWN` | No matches — may be agentless EDR, NDR, or custom service names |

### Signature database

444 signatures across 48 vendors including: CrowdStrike, SentinelOne, Carbon Black, Microsoft Defender/MDE, Cortex XDR, Elastic, Symantec, Sophos, Trend Micro, Trellix/McAfee, ESET, Kaspersky, Bitdefender, Cylance, Fortinet, Cybereason, HarfangLab, Avast/AVG, Malwarebytes, Avira, Norton/Gen Digital, Check Point, Comodo/Xcitium, G Data, Emsisoft, Dr.Web, AhnLab, VIPRE, Cisco Secure Endpoint, Zscaler, and more.

---

## Requirements

- `x86_64-w64-mingw32-gcc` (MinGW cross-compiler)

---

## Build

```bash
# Install MinGW if needed
sudo apt install mingw-w64

# Compile
make clean; make all        # _bin/edr_enum_bof.x64.o, _bin/edr_enum_bof.x86.o, edr_remote_bof.x64.o & edr_remote_bof.x86.o
make local        # produces _bin/edr_enum_bof.x64.o & _bin/edr_enum_bof.x86.o
make remote       # produces edr_remote_bof.x64.o & edr_remote_bof.x86.o
```

---

## Installation

1. Load the edr_enum.axs script into your Adaptix client.

<img width="1215" height="755" alt="image" src="https://github.com/user-attachments/assets/60754b2f-eb0a-4c65-9159-7dafec14e026" />


2. Run against any Windows beacon:

```
edr_both
edr_svc
edr_drv
edr_remote
```

<img width="1651" height="706" alt="image" src="https://github.com/user-attachments/assets/6f0f2a4f-e51f-43b2-9878-306e6e949703" />

<img width="1685" height="876" alt="image" src="https://github.com/user-attachments/assets/dbb35754-6256-4734-aabe-10ab52ebfef4" />

<img width="1651" height="583" alt="image" src="https://github.com/user-attachments/assets/7eb6988d-dd77-42bc-af26-c56bf5284d09" />


---

## Project structure

```
edr_enum/
├── edr_enum.axs          # AdaptixC2 extension (JS) — load this in the C2
├── Makefile
├── _bin/
│   └── edr_enum_bof.x64.o
│   └── edr_enum_bof.x86.o
│   └── edr_remote_bof.x64.o
│   └── edr_remote_bof.x86.o
└── src/
    ├── edr_enum_bof.c
    ├── edr_remote_bof.c    
    ├── beacon.h          
    ├── bofdefs.h         
    └── base.c           
```

---

## Credits

- original [CS-EDR-Enumeration](https://github.com/VirtualAlllocEx/CS-EDR-Enumeration) for Cobalt Strike (signature database + BOF logic)
