#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

void go() {
    HKEY hKey;
    DWORD alwaysInstallElevated = 0;
    DWORD bufferSize = sizeof(DWORD);
    const TCHAR* subkeys[] = {
        TEXT("HKEY_CURRENT_USER"),
        TEXT("HKEY_LOCAL_MACHINE")
    };

    for (int i = 0; i < ARRAY_SIZE(subkeys); i++) {
        if (Advapi32$RegOpenKeyExA((i == 0) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE,
            TEXT("Software\\Policies\\Microsoft\\Windows\\Installer"),
            0,
            KEY_QUERY_VALUE,
            &hKey) == ERROR_SUCCESS) {

            if (Advapi32$RegQueryValueExA(hKey,
                TEXT("AlwaysInstallElevated"),
                NULL,
                NULL,
                (LPBYTE)&alwaysInstallElevated,
                &bufferSize) == ERROR_SUCCESS) {

                if (alwaysInstallElevated == 1) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Always Install Elevated Check Result: Vulnerable\n", subkeys[i]);
                }
                else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Always Install Elevated Check Result: Not Vulnerable\n", subkeys[i]);
                }
            }
            else {
                BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Unable to query AlwaysInstallElevated value.\n", subkeys[i]);
            }
            Advapi32$RegCloseKey(hKey);
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Registry key for AlwaysInstallElevated does not seem to exist.\n", subkeys[i]);
        }
    }
}
