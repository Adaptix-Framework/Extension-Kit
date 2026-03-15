#include <windows.h>
#include "beacon.h"

void printoutput(BOOL done);

#include "base.c"

#ifndef SC_MANAGER_ENUMERATE_SERVICE
#define SC_MANAGER_ENUMERATE_SERVICE 0x0004
#endif
#ifndef SERVICE_WIN32
#define SERVICE_WIN32    0x00000030
#endif
#ifndef SERVICE_DRIVER
#define SERVICE_DRIVER   0x0000000B
#endif
#ifndef SERVICE_ACTIVE
#define SERVICE_ACTIVE   0x00000001
#endif
#ifndef SC_ENUM_PROCESS_INFO
#define SC_ENUM_PROCESS_INFO 0
#endif
#ifndef HEAP_ZERO_MEMORY
#define HEAP_ZERO_MEMORY 0x00000008
#endif

#define MODE_BOTH     0
#define MODE_SVC_ONLY 1
#define MODE_DRV_ONLY 2
#define MODE_PROC_ONLY 3

/* ======== API imports ======== */

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(
    LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte( UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar( UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

DECLSPEC_IMPORT HANDLE WINAPI WTSAPI32$WTSOpenServerW(LPWSTR pServerName);
DECLSPEC_IMPORT VOID   WINAPI WTSAPI32$WTSCloseServer(HANDLE hServer);
DECLSPEC_IMPORT BOOL   WINAPI WTSAPI32$WTSEnumerateProcessesW(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_PROCESS_INFOW *ppProcessInfo, DWORD *pCount);

/* ============================================================
 *  SCM enumeration — works for both local and remote.
 *  Pass NULL as machine name for local, or L"\\\\host" for remote.
 *  Outputs raw lines: SERVICE_NAME: / DRIVER_NAME:
 *  All signature matching is done in the .axs PostHandler.
 * ============================================================ */

static DWORD enum_scm_type( SC_HANDLE hSCM, HANDLE hHeap, DWORD dwServiceType, const char *linePrefix, const char *phaseLabel)
{
    DWORD  dwBytesNeeded      = 0;
    DWORD  dwServicesReturned = 0;
    DWORD  dwResumeHandle     = 0;
    DWORD  dwBufSize          = 0;
    LPBYTE lpBuffer           = NULL;
    DWORD  i;
    char   name[512];

    ADVAPI32$EnumServicesStatusExW( hSCM, (DWORD)SC_ENUM_PROCESS_INFO, dwServiceType, (DWORD)SERVICE_ACTIVE, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
    if (dwBytesNeeded == 0) {
        BeaconPrintf(CALLBACK_ERROR, "EnumServicesStatusExW sizing for %s failed: %lu", phaseLabel, KERNEL32$GetLastError());
        return 0;
    }

    dwBufSize = dwBytesNeeded + 8192;
    lpBuffer  = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufSize);
    if (!lpBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc for %s failed: %lu bytes", phaseLabel, dwBufSize);
        return 0;
    }

    dwResumeHandle = 0; dwServicesReturned = 0;
    if (!ADVAPI32$EnumServicesStatusExW( hSCM, (DWORD)SC_ENUM_PROCESS_INFO, dwServiceType, (DWORD)SERVICE_ACTIVE, lpBuffer, dwBufSize, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "EnumServicesStatusExW for %s failed: %lu", phaseLabel, KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    if (dwServicesReturned == 0) {
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    ENUM_SERVICE_STATUS_PROCESSW *pEntries = (ENUM_SERVICE_STATUS_PROCESSW *)lpBuffer;
    for (i = 0; i < dwServicesReturned; i++) {
        name[0] = '\0';
        KERNEL32$WideCharToMultiByte(65001, 0, pEntries[i].lpServiceName, -1, name, sizeof(name) - 1, NULL, NULL);
        name[sizeof(name) - 1] = '\0';
        internal_printf("%s: %s\n", linePrefix, name);
    }

    KERNEL32$HeapFree(hHeap, 0, lpBuffer);
    return dwServicesReturned;
}

/* ============================================================
 *  Process enumeration — local + remote via WTS API
 *  Outputs raw lines: PROCESS_NAME: <exe>
 * ============================================================ */

static DWORD enum_processes(const wchar_t *target_w)
{
    HANDLE hServer = NULL;
    BOOL is_remote = (target_w && MSVCRT$wcslen(target_w) > 0);

    if (is_remote) {
        const wchar_t *server_name = target_w;
        while (*server_name == L'\\') server_name++;
        hServer = WTSAPI32$WTSOpenServerW((LPWSTR)server_name);
        if (!hServer) {
            BeaconPrintf(CALLBACK_ERROR, "WTSOpenServerW failed: %lu", KERNEL32$GetLastError());
            return 0;
        }
    }

    PWTS_PROCESS_INFOW pProcs = NULL;
    DWORD count = 0;
    HANDLE server = hServer ? hServer : WTS_CURRENT_SERVER_HANDLE;

    if (!WTSAPI32$WTSEnumerateProcessesW(server, 0, 1, &pProcs, &count)) {
        BeaconPrintf(CALLBACK_ERROR, "WTSEnumerateProcessesW failed: %lu", KERNEL32$GetLastError());
        if (hServer) WTSAPI32$WTSCloseServer(hServer);
        return 0;
    }

    DWORD printed = 0;
    for (DWORD i = 0; i < count; i++) {
        if (!pProcs[i].pProcessName || pProcs[i].pProcessName[0] == L'\0') continue;
        char name_mb[512];
        name_mb[0] = '\0';
        KERNEL32$WideCharToMultiByte(65001, 0, pProcs[i].pProcessName, -1, name_mb, sizeof(name_mb) - 1, NULL, NULL);
        name_mb[sizeof(name_mb) - 1] = '\0';
        internal_printf("PROCESS_NAME: %s\n", name_mb);
        printed++;
    }

    WTSAPI32$WTSFreeMemory(pProcs);
    if (hServer) WTSAPI32$WTSCloseServer(hServer);
    return printed;
}

/* ======== Entry point ======== */

void go(char *args, int alen)
{
    datap parser;

    bofstart();

    BeaconDataParse(&parser, args, alen);

    short mode = BeaconDataShort(&parser);
    wchar_t *target_w = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (mode < MODE_BOTH || mode > MODE_PROC_ONLY) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid mode %d. Use: 0=all, 1=svc, 2=drv, 3=proc", mode);
        printoutput(TRUE);
        bofstop();
        return;
    }

    BOOL is_remote = (target_w && MSVCRT$wcslen(target_w) > 0);
    LPCWSTR scm_machine = is_remote ? target_w : NULL;

    DWORD nSvc = 0, nDrv = 0, nProc = 0;

    if (mode == MODE_BOTH || mode == MODE_SVC_ONLY || mode == MODE_DRV_ONLY) {
        SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(scm_machine, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM) {
            BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerW failed: %lu", KERNEL32$GetLastError());
            printoutput(TRUE);
            bofstop();
            return;
        }

        HANDLE hHeap = KERNEL32$GetProcessHeap();

        if (mode == MODE_BOTH || mode == MODE_SVC_ONLY)
            nSvc = enum_scm_type(hSCM, hHeap, SERVICE_WIN32, "SERVICE_NAME", "services");

        if (mode == MODE_BOTH || mode == MODE_DRV_ONLY)
            nDrv = enum_scm_type(hSCM, hHeap, SERVICE_DRIVER, "DRIVER_NAME", "drivers");

        ADVAPI32$CloseServiceHandle(hSCM);
    }

    if (mode == MODE_BOTH || mode == MODE_PROC_ONLY)
        nProc = enum_processes(target_w);

    internal_printf("--- END (services: %lu, drivers: %lu, processes: %lu) ---\n",
        (unsigned long)nSvc, (unsigned long)nDrv, (unsigned long)nProc);

    printoutput(TRUE);
    bofstop();
}