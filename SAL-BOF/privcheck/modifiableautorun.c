#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    HKEY hKey = NULL;
    LONG lResult = 0;
    char szValueName[256];
    char szValueData[512];
    char szPath[512];
    DWORD dwValueNameSize = 0;
    DWORD dwValueDataSize = 0;
    DWORD dwType = 0;
    DWORD dwIndex = 0;
    int nFound = 0;
    int p = 0;
    int q = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    const char* pszHives[] = { "HKLM", "HKCU" };
    HKEY hRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

    const char* pszSubkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    for (int i = 0; i < 2; i++) {
        for (int k = 0; k < 4; k++) {
            lResult = ADVAPI32$RegOpenKeyExA(hRoots[i], pszSubkeys[k], 0, KEY_READ, &hKey);
            if (lResult != ERROR_SUCCESS) {
                continue;
            }

            dwIndex = 0;
            while (1) {
                dwValueNameSize = sizeof(szValueName);
                dwValueDataSize = sizeof(szValueData);

                lResult = ADVAPI32$RegEnumValueA(hKey, dwIndex, szValueName, &dwValueNameSize,
                    NULL, &dwType, (LPBYTE)szValueData, &dwValueDataSize);

                if (lResult != ERROR_SUCCESS) {
                    break;
                }

                if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                    szValueData[dwValueDataSize] = '\0';

                    p = 0;
                    q = 0;

                    while (szValueData[p] == ' ') p++;

                    if (szValueData[p] == '"') {
                        p++;
                        while (szValueData[p] != '\0' && szValueData[p] != '"' && q < 510) {
                            szPath[q++] = szValueData[p++];
                        }
                    } else {
                        while (szValueData[p] != '\0' && szValueData[p] != ' ' && q < 510) {
                            szPath[q++] = szValueData[p++];
                        }
                    }
                    szPath[q] = '\0';

                    hFile = KERNEL32$CreateFileA(szPath, GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);

                    if (hFile != INVALID_HANDLE_VALUE) {
                        KERNEL32$CloseHandle(hFile);
                        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN] WRITABLE: %s\\%s\n", pszHives[i], pszSubkeys[k]);
                        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN]   Name: %s\n", szValueName);
                        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN]   Path: %s\n", szValueData);
                        nFound++;
                    }
                }

                dwIndex++;
            }

            ADVAPI32$RegCloseKey(hKey);
            hKey = NULL;
        }
    }

    if (nFound > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN] VULNERABLE: %d modifiable autorun(s) found!\n", nFound);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTORUN] Not vulnerable: No modifiable autoruns found\n");
    }
}
