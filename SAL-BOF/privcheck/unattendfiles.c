#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    char szWinDir[MAX_PATH * 2];
    int NumOfFoundFiles = 0;
    HANDLE hFile;

    // Resolve Windows Directory path
    if (Kernel32$GetWindowsDirectoryA(szWinDir, sizeof(szWinDir)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Failed to resolve Windows directory\n");
        return;
    }

    // List of common Unattend Setup Files
    static const char * UnattendFiles[] = {
            "\\sysprep\\sysprep.xml",
            "\\sysprep\\sysprep.inf",
            "\\sysprep.inf",
            "\\Panther\\Unattended.xml",
            "\\Panther\\Unattend.xml",
            "\\Panther\\Unattend\\Unattend.xml",
            "\\Panther\\Unattend\\Unattended.xml",
            "\\System32\\Sysprep\\unattend.xml",
            "\\System32\\Sysprep\\Panther\\unattend.xml",
            NULL
    };

    // Iterate over each potential file
    for (int i = 0; UnattendFiles[i] != NULL; i++) {
        char FullPath[MAX_PATH * 2];

        // Prepend the Windows directory to the path
        User32$wsprintfA(FullPath, "%s%s", szWinDir, UnattendFiles[i]);

        // Check if file exists
        hFile = Kernel32$CreateFileA(FullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Unattend file found: %s\n", FullPath);
            NumOfFoundFiles++;
            Kernel32$CloseHandle(hFile);
        }

    }
    BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Found a total of %d unattend files\n", NumOfFoundFiles);
}
