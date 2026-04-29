/*
 * svcmgr_bof.c — Service Manager BOF para AdaptixC2
 *
 * Operaciones: list, query, create, delete, start, stop
 * Soporte:     local y remoto via SCM (SMB/RPC)
 * Tipos:       Win32 y Kernel Driver
 */

#include <windows.h>

void printoutput(BOOL done);
#define DYNAMIC_LIB_COUNT 1
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

/* ── ADVAPI32 — SCM imports ───────────────────────────────── */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(
    LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(
    SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess);

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(
    SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName,
    DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType,
    DWORD dwErrorControl, LPCWSTR lpBinaryPathName,
    LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
    LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceW(
    SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR *lpServiceArgVectors);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ControlService(
    SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceStatusEx(
    SC_HANDLE hService, SC_STATUS_TYPE InfoLevel,
    LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$QueryServiceConfigW(
    SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig,
    DWORD cbBufSize, LPDWORD pcbBytesNeeded);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EnumServicesStatusExW(
    SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType, DWORD dwServiceState,
    LPBYTE lpServices, DWORD cbBufSize,
    LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle, LPCWSTR pszGroupName);

/* ── Helpers ──────────────────────────────────────────────── */
#define HEAP_ZERO 0x00000008

static void mb_to_wc(const char *src, wchar_t *dst, int maxwc)
{
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, maxwc);
}

static void wc_to_mb(const wchar_t *src, char *dst, int maxmb)
{
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, maxmb, NULL, NULL);
}

/* strcmp simple sin depender de MSVCRT */
static int my_strcmp(const char *a, const char *b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

/* strcasecmp simple (solo ASCII) */
static int my_stricmp(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static const char *svc_type_str(DWORD t)
{
    if (t & SERVICE_KERNEL_DRIVER)       return "KERNEL_DRIVER";
    if (t & SERVICE_FILE_SYSTEM_DRIVER)  return "FS_DRIVER";
    if (t & SERVICE_WIN32_OWN_PROCESS)   return "WIN32_OWN";
    if (t & SERVICE_WIN32_SHARE_PROCESS) return "WIN32_SHARE";
    return "UNKNOWN";
}

static const char *svc_start_str(DWORD s)
{
    switch (s) {
        case SERVICE_BOOT_START:   return "BOOT";
        case SERVICE_SYSTEM_START: return "SYSTEM";
        case SERVICE_AUTO_START:   return "AUTO";
        case SERVICE_DEMAND_START: return "DEMAND";
        case SERVICE_DISABLED:     return "DISABLED";
        default:                   return "UNKNOWN";
    }
}

static const char *svc_state_str(DWORD s)
{
    switch (s) {
        case SERVICE_STOPPED:          return "STOPPED";
        case SERVICE_START_PENDING:    return "START_PENDING";
        case SERVICE_STOP_PENDING:     return "STOP_PENDING";
        case SERVICE_RUNNING:          return "RUNNING";
        case SERVICE_CONTINUE_PENDING: return "CONTINUE_PENDING";
        case SERVICE_PAUSE_PENDING:    return "PAUSE_PENDING";
        case SERVICE_PAUSED:           return "PAUSED";
        default:                       return "UNKNOWN";
    }
}

/* ── Operaciones ──────────────────────────────────────────── */

static void op_list(SC_HANDLE hScm, const char *target, DWORD type_filter)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD dwBytesNeeded = 0, dwReturned = 0, dwResume = 0;

    ADVAPI32$EnumServicesStatusExW(
        hScm, SC_ENUM_PROCESS_INFO,
        type_filter, SERVICE_STATE_ALL,
        NULL, 0, &dwBytesNeeded, &dwReturned, &dwResume, NULL);

    if (dwBytesNeeded == 0) {
        internal_printf("[-] EnumServicesStatusExW sizing failed: %lu\n",
            KERNEL32$GetLastError());
        return;
    }

    LPBYTE buf = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO, dwBytesNeeded + 4096);
    if (!buf) { internal_printf("[-] HeapAlloc failed\n"); return; }

    dwResume = 0; dwReturned = 0;
    if (!ADVAPI32$EnumServicesStatusExW(
            hScm, SC_ENUM_PROCESS_INFO,
            type_filter, SERVICE_STATE_ALL,
            buf, dwBytesNeeded + 4096,
            &dwBytesNeeded, &dwReturned, &dwResume, NULL))
    {
        internal_printf("[-] EnumServicesStatusExW failed: %lu\n",
            KERNEL32$GetLastError());
        KERNEL32$HeapFree(hHeap, 0, buf);
        return;
    }

    internal_printf("=== Services on [%s] - %lu entries ===\n\n",
        target, (unsigned long)dwReturned);
    internal_printf("%-40s %-14s %-12s %s\n",
        "NAME", "STATE", "TYPE", "DISPLAY NAME");
    internal_printf("%-40s %-14s %-12s %s\n",
        "----------------------------------------",
        "--------------", "------------",
        "-----------------------------------");

    ENUM_SERVICE_STATUS_PROCESSW *pEntry = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    for (DWORD i = 0; i < dwReturned; i++) {
        char name[256] = {0}, disp[256] = {0};
        wc_to_mb(pEntry[i].lpServiceName, name, sizeof(name));
        wc_to_mb(pEntry[i].lpDisplayName, disp, sizeof(disp));
        DWORD state = pEntry[i].ServiceStatusProcess.dwCurrentState;
        DWORD type  = pEntry[i].ServiceStatusProcess.dwServiceType;
        internal_printf("%-40s %-14s %-12s %s\n",
            name, svc_state_str(state), svc_type_str(type), disp);
    }
    internal_printf("\nTotal: %lu services\n", (unsigned long)dwReturned);
    KERNEL32$HeapFree(hHeap, 0, buf);
}

static void op_query(SC_HANDLE hScm, const char *svc_name_mb)
{
    wchar_t svc_w[256] = {0};
    mb_to_wc(svc_name_mb, svc_w, 256);

    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, svc_w,
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        internal_printf("[-] OpenServiceW('%s') failed: %lu\n",
            svc_name_mb, KERNEL32$GetLastError());
        return;
    }

    SERVICE_STATUS_PROCESS ssp;
    MSVCRT$memset(&ssp, 0, sizeof(ssp));
    DWORD dwNeeded = 0;
    ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &dwNeeded);

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    ADVAPI32$QueryServiceConfigW(hSvc, NULL, 0, &dwNeeded);
    LPQUERY_SERVICE_CONFIGW pCfg = (LPQUERY_SERVICE_CONFIGW)
        KERNEL32$HeapAlloc(hHeap, HEAP_ZERO, dwNeeded + 512);

    char bin_path[512] = {0}, display[256] = {0}, start_name[256] = {0};
    if (pCfg && ADVAPI32$QueryServiceConfigW(hSvc, pCfg, dwNeeded + 512, &dwNeeded)) {
        if (pCfg->lpBinaryPathName)   wc_to_mb(pCfg->lpBinaryPathName,   bin_path,   sizeof(bin_path));
        if (pCfg->lpDisplayName)      wc_to_mb(pCfg->lpDisplayName,      display,    sizeof(display));
        if (pCfg->lpServiceStartName) wc_to_mb(pCfg->lpServiceStartName, start_name, sizeof(start_name));
    }

    internal_printf("=== Service: %s ===\n", svc_name_mb);
    internal_printf("  Display Name : %s\n", display);
    internal_printf("  State        : %s  (PID: %lu)\n",
        svc_state_str(ssp.dwCurrentState), (unsigned long)ssp.dwProcessId);
    internal_printf("  Type         : %s\n", svc_type_str(ssp.dwServiceType));
    if (pCfg)
    internal_printf("  Start Type   : %s\n", svc_start_str(pCfg->dwStartType));
    internal_printf("  Binary Path  : %s\n", bin_path);
    internal_printf("  Run As       : %s\n", start_name[0] ? start_name : "LocalSystem");

    if (pCfg) KERNEL32$HeapFree(hHeap, 0, pCfg);
    ADVAPI32$CloseServiceHandle(hSvc);
}

static void op_create(SC_HANDLE hScm,
    const char *svc_name_mb, const char *disp_name_mb,
    const char *bin_path_mb, DWORD svc_type, DWORD start_type)
{
    wchar_t svc_w[256]  = {0};
    wchar_t disp_w[256] = {0};
    wchar_t bin_w[512]  = {0};

    mb_to_wc(svc_name_mb, svc_w, 256);
    mb_to_wc(disp_name_mb[0] ? disp_name_mb : svc_name_mb, disp_w, 256);
    mb_to_wc(bin_path_mb, bin_w, 512);

    SC_HANDLE hSvc = ADVAPI32$CreateServiceW(
        hScm,
        svc_w, disp_w,
        SERVICE_ALL_ACCESS,
        svc_type, start_type,
        SERVICE_ERROR_NORMAL,
        bin_w,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        internal_printf("[-] CreateServiceW failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    internal_printf("[+] Service '%s' created successfully.\n", svc_name_mb);
    internal_printf("    Display   : %s\n", disp_name_mb[0] ? disp_name_mb : svc_name_mb);
    internal_printf("    Type      : %s\n", svc_type_str(svc_type));
    internal_printf("    Start     : %s\n", svc_start_str(start_type));
    internal_printf("    Binary    : %s\n", bin_path_mb);
    ADVAPI32$CloseServiceHandle(hSvc);
}

static void op_delete(SC_HANDLE hScm, const char *svc_name_mb)
{
    wchar_t svc_w[256] = {0};
    mb_to_wc(svc_name_mb, svc_w, 256);

    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, svc_w,
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        internal_printf("[-] OpenServiceW('%s') failed: %lu\n",
            svc_name_mb, KERNEL32$GetLastError());
        return;
    }

    SERVICE_STATUS ss;
    MSVCRT$memset(&ss, 0, sizeof(ss));
    ADVAPI32$ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);

    if (!ADVAPI32$DeleteService(hSvc))
        internal_printf("[-] DeleteService failed: %lu\n", KERNEL32$GetLastError());
    else
        internal_printf("[+] Service '%s' deleted (effective on next restart).\n", svc_name_mb);

    ADVAPI32$CloseServiceHandle(hSvc);
}

static void op_start(SC_HANDLE hScm, const char *svc_name_mb)
{
    wchar_t svc_w[256] = {0};
    mb_to_wc(svc_name_mb, svc_w, 256);

    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, svc_w,
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        internal_printf("[-] OpenServiceW('%s') failed: %lu\n",
            svc_name_mb, KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$StartServiceW(hSvc, 0, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            internal_printf("[~] Service '%s' is already running.\n", svc_name_mb);
        else
            internal_printf("[-] StartServiceW failed: %lu\n", err);
    } else {
        internal_printf("[+] Service '%s' start requested...\n", svc_name_mb);
        SERVICE_STATUS_PROCESS ssp;
        MSVCRT$memset(&ssp, 0, sizeof(ssp));
        DWORD dwNeeded = 0;
        for (int i = 0; i < 10; i++) {
            ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp, sizeof(ssp), &dwNeeded);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
            KERNEL32$WaitForSingleObject((HANDLE)(LONG_PTR)-1, 500);
        }
        internal_printf("[+] State: %s  (PID: %lu)\n",
            svc_state_str(ssp.dwCurrentState), (unsigned long)ssp.dwProcessId);
    }
    ADVAPI32$CloseServiceHandle(hSvc);
}

static void op_stop(SC_HANDLE hScm, const char *svc_name_mb)
{
    wchar_t svc_w[256] = {0};
    mb_to_wc(svc_name_mb, svc_w, 256);

    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hScm, svc_w,
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        internal_printf("[-] OpenServiceW('%s') failed: %lu\n",
            svc_name_mb, KERNEL32$GetLastError());
        return;
    }

    SERVICE_STATUS ss;
    MSVCRT$memset(&ss, 0, sizeof(ss));
    if (!ADVAPI32$ControlService(hSvc, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE)
            internal_printf("[~] Service '%s' is not running.\n", svc_name_mb);
        else
            internal_printf("[-] ControlService(STOP) failed: %lu\n", err);
    } else {
        internal_printf("[+] Service '%s' stop requested...\n", svc_name_mb);
        SERVICE_STATUS_PROCESS ssp;
        MSVCRT$memset(&ssp, 0, sizeof(ssp));
        DWORD dwNeeded = 0;
        for (int i = 0; i < 10; i++) {
            ADVAPI32$QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp, sizeof(ssp), &dwNeeded);
            if (ssp.dwCurrentState == SERVICE_STOPPED) break;
            KERNEL32$WaitForSingleObject((HANDLE)(LONG_PTR)-1, 500);
        }
        internal_printf("[+] State: %s\n", svc_state_str(ssp.dwCurrentState));
    }
    ADVAPI32$CloseServiceHandle(hSvc);
}

/* ── Entry Point ──────────────────────────────────────────── */
void go(char *args, int alen)
{
    bofstart();

    datap parser;
    BeaconDataParse(&parser, args, alen);

    char *op     = BeaconDataExtract(&parser, NULL);
    char *target = BeaconDataExtract(&parser, NULL);

    if (!op || !target) {
        internal_printf("[-] Missing arguments.\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    /* "localhost" -> NULL = SCM local */
    wchar_t target_w[256] = {0};
    wchar_t *pTarget = NULL;
    if (my_stricmp(target, "localhost") != 0) {
        mb_to_wc(target, target_w, 256);
        pTarget = target_w;
    }

    /* Para create necesitamos SC_MANAGER_CREATE_SERVICE */
    DWORD scm_access = SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT;
    if (op[0] == 'c' && op[1] == 'r') scm_access |= SC_MANAGER_CREATE_SERVICE;

    SC_HANDLE hScm = ADVAPI32$OpenSCManagerW(pTarget, NULL, scm_access);
    if (!hScm) {
        internal_printf("[-] OpenSCManagerW('%s') failed: %lu\n",
            target, KERNEL32$GetLastError());
        printoutput(TRUE);
        bofstop();
        return;
    }

    /* Despacho */
    if (my_strcmp(op, "list") == 0) {
        char *filter = BeaconDataExtract(&parser, NULL);
        DWORD type_filter = SERVICE_WIN32 | SERVICE_DRIVER;
        if (filter) {
            if (filter[0] == 'w' || filter[0] == 'W') type_filter = SERVICE_WIN32;
            else if (filter[0] == 'd' || filter[0] == 'D') type_filter = SERVICE_DRIVER;
        }
        op_list(hScm, target, type_filter);
    }
    else if (my_strcmp(op, "query") == 0) {
        char *svc = BeaconDataExtract(&parser, NULL);
        if (!svc) { internal_printf("[-] Missing service name.\n"); goto done; }
        op_query(hScm, svc);
    }
    else if (my_strcmp(op, "create") == 0) {
        char *svc_name  = BeaconDataExtract(&parser, NULL);
        char *disp_name = BeaconDataExtract(&parser, NULL);
        char *bin_path  = BeaconDataExtract(&parser, NULL);
        char *type_str  = BeaconDataExtract(&parser, NULL);
        char *start_str = BeaconDataExtract(&parser, NULL);

        if (!svc_name || !bin_path) {
            internal_printf("[-] Missing svc_name or bin_path.\n");
            goto done;
        }

        DWORD svc_type   = SERVICE_WIN32_OWN_PROCESS;
        DWORD start_type = SERVICE_DEMAND_START;

        if (type_str && (type_str[0] == 'd' || type_str[0] == 'D'))
            svc_type = SERVICE_KERNEL_DRIVER;

        if (start_str) {
            if      (start_str[0] == 'a' || start_str[0] == 'A') start_type = SERVICE_AUTO_START;
            else if (start_str[0] == 'b' || start_str[0] == 'B') start_type = SERVICE_BOOT_START;
            else if (start_str[0] == 's' || start_str[0] == 'S') start_type = SERVICE_SYSTEM_START;
            else if (my_stricmp(start_str, "disabled") == 0)      start_type = SERVICE_DISABLED;
        }

        op_create(hScm, svc_name,
            disp_name ? disp_name : svc_name,
            bin_path, svc_type, start_type);
    }
    else if (my_strcmp(op, "delete") == 0) {
        char *svc = BeaconDataExtract(&parser, NULL);
        if (!svc) { internal_printf("[-] Missing service name.\n"); goto done; }
        op_delete(hScm, svc);
    }
    else if (my_strcmp(op, "start") == 0) {
        char *svc = BeaconDataExtract(&parser, NULL);
        if (!svc) { internal_printf("[-] Missing service name.\n"); goto done; }
        op_start(hScm, svc);
    }
    else if (my_strcmp(op, "stop") == 0) {
        char *svc = BeaconDataExtract(&parser, NULL);
        if (!svc) { internal_printf("[-] Missing service name.\n"); goto done; }
        op_stop(hScm, svc);
    }
    else {
        internal_printf("[-] Unknown operation: '%s'\n", op);
        internal_printf("    Valid ops: list | query | create | delete | start | stop\n");
    }

done:
    ADVAPI32$CloseServiceHandle(hScm);
    printoutput(TRUE);
    bofstop();
}
