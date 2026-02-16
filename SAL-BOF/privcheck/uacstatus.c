#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

void go() {
    HKEY hKey = NULL;
    LONG lResult = 0;
    DWORD dwEnableLUA = 0;
    DWORD dwConsentPrompt = 0;
    DWORD dwSecureDesktop = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType = 0;
    HANDLE hToken = NULL;
    DWORD dwIntegrityLevel = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    DWORD dwLengthNeeded = 0;
    HANDLE hHeap = NULL;
    BOOL bIsAdmin = FALSE;
    BOOL bIsElevated = FALSE;
    PSID pAdminSid = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    lResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Failed to open registry key. Error: %ld\n", lResult);
        return;
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, &dwType, (LPBYTE)&dwEnableLUA, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] UAC Enabled (EnableLUA): %s\n", dwEnableLUA ? "Yes" : "No");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] UAC Enabled (EnableLUA): Unknown (not found)\n");
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", NULL, &dwType, (LPBYTE)&dwConsentPrompt, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        const char* desc = "Unknown";
        switch (dwConsentPrompt) {
            case 0: desc = "Elevate without prompting"; break;
            case 1: desc = "Prompt for credentials on secure desktop"; break;
            case 2: desc = "Prompt for consent on secure desktop"; break;
            case 3: desc = "Prompt for credentials"; break;
            case 4: desc = "Prompt for consent"; break;
            case 5: desc = "Prompt for consent for non-Windows binaries"; break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] ConsentPromptBehaviorAdmin: %lu (%s)\n", dwConsentPrompt, desc);
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "PromptOnSecureDesktop", NULL, &dwType, (LPBYTE)&dwSecureDesktop, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] PromptOnSecureDesktop: %s\n", dwSecureDesktop ? "Yes" : "No");
    }

    ADVAPI32$RegCloseKey(hKey);
    hKey = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Failed to open process token. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    hHeap = KERNEL32$GetProcessHeap();

    dwLengthNeeded = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0) {
        pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTIL) {
            if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
                PUCHAR pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
                if (pCount && *pCount > 0) {
                    PDWORD pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*pCount - 1));
                    if (pLevel) {
                        dwIntegrityLevel = *pLevel;
                    }
                }
            }
        }
    }

    if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Untrusted\n");
    } else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Low\n");
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Medium\n");
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: High (Elevated)\n");
        bIsElevated = TRUE;
    } else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: System\n");
        bIsElevated = TRUE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSid)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Failed to create Admin SID. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    dwLengthNeeded = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0) {
        pTokenGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTokenGroups) {
            if (ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLengthNeeded, &dwLengthNeeded)) {
                for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                    if (ADVAPI32$EqualSid(pAdminSid, pTokenGroups->Groups[i].Sid)) {
                        bIsAdmin = TRUE;
                        break;
                    }
                }
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Local Admin Group Member: %s\n", bIsAdmin ? "Yes" : "No");

    if (bIsElevated) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Process is running with elevated privileges\n");
    } else if (bIsAdmin && dwEnableLUA) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is local admin but NOT elevated (UAC filtered token)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] UAC bypass may be possible\n");
    } else if (bIsAdmin && !dwEnableLUA) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is local admin and UAC is disabled\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is NOT a local admin\n");
    }

cleanup:
    if (pAdminSid) ADVAPI32$FreeSid(pAdminSid);
    if (pTokenGroups) KERNEL32$HeapFree(hHeap, 0, pTokenGroups);
    if (pTIL) KERNEL32$HeapFree(hHeap, 0, pTIL);
    if (hToken) KERNEL32$CloseHandle(hToken);
    if (hKey) ADVAPI32$RegCloseKey(hKey);
}
