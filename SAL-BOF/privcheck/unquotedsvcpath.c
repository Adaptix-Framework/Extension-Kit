#include <windows.h>
#include <string.h>
#include <shlwapi.h>
#include "bofdefs.h"
#include "beacon.h"


void go() {
    HKEY servicesKey;
    BOOL foundVulnerablePath = FALSE;
    if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        while (TRUE) {
            subkeyNameSize = sizeof(serviceSubkeyName);
            if (Advapi32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                break;
            }
                HKEY imagePathKey;
                if (Advapi32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                    char imagePathValue[1024] = { 0 };
                    DWORD valueSize = sizeof(imagePathValue);
                    if (Advapi32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) != ERROR_SUCCESS) {
                        Advapi32$RegCloseKey(imagePathKey);
                        continue;
                    }

                    if (Shlwapi$StrStrIA(imagePathValue, " ") == NULL || Shlwapi$StrStrIA(imagePathValue, "\"") != NULL) {
                        Advapi32$RegCloseKey(imagePathKey);
                        continue;
                    }

                    if (Shlwapi$StrStrIA(imagePathValue, "System32") != NULL ||
                        Shlwapi$StrStrIA(imagePathValue, "SysWow64") != NULL ||
                        Shlwapi$StrStrIA(imagePathValue, ".sys") != NULL)
                    {
                        Advapi32$RegCloseKey(imagePathKey);
                        continue;
                    }

                    BeaconPrintf(CALLBACK_OUTPUT, "[SERVICE_PATH] Service '%s' has an unquoted executable path: %s\n", serviceSubkeyName, imagePathValue);
                    foundVulnerablePath = TRUE;

                    Advapi32$RegCloseKey(imagePathKey);
                }
        }
        Advapi32$RegCloseKey(servicesKey);
    }

    if (!foundVulnerablePath) {
        BeaconPrintf(CALLBACK_OUTPUT, "[SERVICE_PATH] No unquoted service paths found");
    }
}