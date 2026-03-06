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
/* SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER */
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

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(
    LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);


DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte,
    LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);

static DWORD enum_scm_type(
    SC_HANDLE hSCM,
    HANDLE    hHeap,
    DWORD     dwServiceType,
    char     *linePrefix,   
    char     *phaseLabel    
)
{
    DWORD  dwBytesNeeded      = 0;
    DWORD  dwServicesReturned = 0;
    DWORD  dwResumeHandle     = 0;
    DWORD  dwBufSize          = 0;
    LPBYTE lpBuffer           = NULL;
    DWORD  i;
    char   name[512];
    ENUM_SERVICE_STATUS_PROCESSW *pEntries = NULL;

    /* Primera llamada: obtener tamaño requerido */
    ADVAPI32$EnumServicesStatusExW(
        hSCM, (DWORD)SC_ENUM_PROCESS_INFO,
        dwServiceType, (DWORD)SERVICE_ACTIVE,
        NULL, 0,
        &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

    if (dwBytesNeeded == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "EnumServicesStatusExW sizing for %s failed: %lu",
            phaseLabel, KERNEL32$GetLastError());
        return 0;
    }

    dwBufSize = dwBytesNeeded + 8192;
    lpBuffer  = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufSize);
    if (!lpBuffer) {
        BeaconPrintf(CALLBACK_ERROR,
            "HeapAlloc for %s failed: %lu bytes", phaseLabel, dwBufSize);
        return 0;
    }

    /* Segunda llamada: enumerar */
    dwResumeHandle = 0; dwServicesReturned = 0;
    if (!ADVAPI32$EnumServicesStatusExW(
            hSCM, (DWORD)SC_ENUM_PROCESS_INFO,
            dwServiceType, (DWORD)SERVICE_ACTIVE,
            lpBuffer, dwBufSize,
            &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL))
    {
        BeaconPrintf(CALLBACK_ERROR,
            "EnumServicesStatusExW for %s failed: %lu",
            phaseLabel, KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    if (dwServicesReturned == 0) {
        internal_printf("--- %s: 0 found ---\n", phaseLabel);
        KERNEL32$HeapFree(hHeap, 0, lpBuffer);
        return 0;
    }

    pEntries = (ENUM_SERVICE_STATUS_PROCESSW *)lpBuffer;
    internal_printf("--- %s (%lu entries) ---\n", phaseLabel, (unsigned long)dwServicesReturned);

    for (i = 0; i < dwServicesReturned; i++) {
        name[0] = '\0';
        KERNEL32$WideCharToMultiByte(
            65001, 0,                        
            pEntries[i].lpServiceName, -1,
            name, sizeof(name) - 1, NULL, NULL);
        name[sizeof(name) - 1] = '\0';

        internal_printf("%s: %s\n", linePrefix, name);
    }

    KERNEL32$HeapFree(hHeap, 0, lpBuffer);
    return dwServicesReturned;
}

void go(char *args, int alen)
{
    SC_HANDLE hSCM  = NULL;
    HANDLE    hHeap = NULL;
    DWORD     nSvc  = 0;
    DWORD     nDrv  = 0;
    short     mode  = MODE_BOTH;
    datap     parser;

    bofstart();

    BeaconDataParse(&parser, args, alen);
    if (alen > 0)
        mode = BeaconDataShort(&parser);

    if (mode < MODE_BOTH || mode > MODE_DRV_ONLY) {
        BeaconPrintf(CALLBACK_ERROR,
            "Invalid mode %d. Use: 0=both, 1=svc, 2=drv", mode);
        printoutput(TRUE);
        bofstop();
        return;
    }

    hSCM = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR,
            "OpenSCManagerW failed: %lu", KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    hHeap = KERNEL32$GetProcessHeap();

    if (mode == MODE_BOTH)
        internal_printf("--- BOF Service & Driver Enumeration ---\n");
    else if (mode == MODE_SVC_ONLY)
        internal_printf("--- BOF Service Enumeration ---\n");
    else
        internal_printf("--- BOF Driver Enumeration ---\n");

    if (mode == MODE_BOTH || mode == MODE_SVC_ONLY)
        nSvc = enum_scm_type(hSCM, hHeap, SERVICE_WIN32,  "SERVICE_NAME", "services");

    if (mode == MODE_BOTH || mode == MODE_DRV_ONLY)
        nDrv = enum_scm_type(hSCM, hHeap, SERVICE_DRIVER, "DRIVER_NAME",  "drivers");

    internal_printf("--- END (services: %lu, drivers: %lu) ---\n",
        (unsigned long)nSvc, (unsigned long)nDrv);

    printoutput(TRUE);
    bofstop();

    ADVAPI32$CloseServiceHandle(hSCM);
}
