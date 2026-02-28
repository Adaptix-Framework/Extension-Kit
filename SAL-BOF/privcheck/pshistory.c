#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    char szPath[MAX_PATH];
    char szAppData[MAX_PATH];
    DWORD dwSize = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER liFileSize;
    int i = 0;
    int j = 0;

    const char* pszSubPath = "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    dwSize = KERNEL32$GetEnvironmentVariableA("APPDATA", szAppData, sizeof(szAppData));
    if (dwSize == 0 || dwSize >= sizeof(szAppData)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] Failed to get APPDATA path. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    i = 0;
    while (szAppData[i] != '\0' && i < MAX_PATH - 1) {
        szPath[i] = szAppData[i];
        i++;
    }

    j = 0;
    while (pszSubPath[j] != '\0' && i < MAX_PATH - 1) {
        szPath[i] = pszSubPath[j];
        i++;
        j++;
    }
    szPath[i] = '\0';

    hFile = KERNEL32$CreateFileA(szPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErr = KERNEL32$GetLastError();
        if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND) {
            BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] PowerShell history file not found\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Path: %s\n", szPath);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] Error accessing file. Error: %lu\n", dwErr);
        }
        return;
    }

    liFileSize.QuadPart = 0;
    KERNEL32$GetFileSizeEx(hFile, &liFileSize);

    BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] PowerShell history file found!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Path: %s\n", szPath);

    if (liFileSize.QuadPart >= 1048576) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu MB\n", (DWORD)(liFileSize.QuadPart / 1048576));
    } else if (liFileSize.QuadPart >= 1024) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu KB\n", (DWORD)(liFileSize.QuadPart / 1024));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu bytes\n", (DWORD)liFileSize.QuadPart);
    }

    if (liFileSize.QuadPart == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] History file is empty\n");
    }

    KERNEL32$CloseHandle(hFile);
}
