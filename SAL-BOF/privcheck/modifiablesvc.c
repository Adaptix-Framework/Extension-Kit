#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

BOOL HasModifyRights(ACCESS_MASK mask) {
    if (mask & SERVICE_CHANGE_CONFIG)  return TRUE;
    if (mask & WRITE_DAC)              return TRUE;
    if (mask & WRITE_OWNER)            return TRUE;
    if (mask & GENERIC_ALL)            return TRUE;
    if (mask & GENERIC_WRITE)          return TRUE;
    if (mask & SERVICE_ALL_ACCESS)     return TRUE;
    return FALSE;
}

void go() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hToken = NULL;
    HANDLE hHeap = NULL;
    LPBYTE pServices = NULL;
    LPENUM_SERVICE_STATUS_PROCESSA pServiceStatus = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPQUERY_SERVICE_CONFIGA pConfig = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwBufferSize = 0;
    DWORD dwSDSize = 0;
    DWORD dwConfigSize = 0;
    DWORD dwTokenInfoSize = 0;
    int nVulnerable = 0;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    PACL pDacl = NULL;

    hHeap = KERNEL32$GetProcessHeap();

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to open process token. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwTokenInfoSize);
    if (!pTokenUser) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Memory allocation failed\n");
        goto cleanup;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to get token user. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to open Service Control Manager. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);

    dwBufferSize = dwBytesNeeded;
    pServices = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    if (!pServices) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Memory allocation failed\n");
        goto cleanup;
    }

    dwResumeHandle = 0;
    if (!ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, pServices, dwBufferSize, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to enumerate services. Error: %lu\n", KERNEL32$GetLastError());
        goto cleanup;
    }

    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESSA)pServices;

    for (DWORD i = 0; i < dwServicesReturned; i++) {
        hService = ADVAPI32$OpenServiceA(hSCManager, pServiceStatus[i].lpServiceName, READ_CONTROL | SERVICE_QUERY_CONFIG);
        if (!hService) continue;

        dwSDSize = 0;
        ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &dwSDSize);
        if (dwSDSize == 0) {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pSD = (PSECURITY_DESCRIPTOR)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSDSize);
        if (!pSD) {
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        if (!ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, dwSDSize, &dwSDSize)) {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        pDacl = NULL;
        if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted) || !bDaclPresent || !pDacl) {
            KERNEL32$HeapFree(hHeap, 0, pSD);
            pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService);
            hService = NULL;
            continue;
        }

        for (DWORD j = 0; j < pDacl->AceCount; j++) {
            PACE_HEADER pAceHeader = NULL;
            if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader)) continue;
            if (pAceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

            PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
            PSID pAceSid = (PSID)&pAce->SidStart;

            if (!HasModifyRights(pAce->Mask)) continue;

            BOOL bMatch = FALSE;
            if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid)) {
                bMatch = TRUE;
            } else {
                ADVAPI32$CheckTokenMembership(hToken, pAceSid, &bMatch);
            }

            if (bMatch) {
                dwConfigSize = 0;
                ADVAPI32$QueryServiceConfigA(hService, NULL, 0, &dwConfigSize);
                if (dwConfigSize > 0) {
                    pConfig = (LPQUERY_SERVICE_CONFIGA)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwConfigSize);
                    if (pConfig && ADVAPI32$QueryServiceConfigA(hService, pConfig, dwConfigSize, &dwConfigSize)) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] VULNERABLE: %s\n", pServiceStatus[i].lpServiceName);
                        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC]   Display: %s\n", pConfig->lpDisplayName ? pConfig->lpDisplayName : "N/A");
                        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC]   Binary:  %s\n", pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : "N/A");
                        nVulnerable++;
                    }
                    if (pConfig) {
                        KERNEL32$HeapFree(hHeap, 0, pConfig);
                        pConfig = NULL;
                    }
                }
                break;
            }
        }

        KERNEL32$HeapFree(hHeap, 0, pSD);
        pSD = NULL;
        ADVAPI32$CloseServiceHandle(hService);
        hService = NULL;
    }

    if (nVulnerable > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Found %d modifiable service(s)!\n", nVulnerable);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] No modifiable services found\n");
    }

cleanup:
    if (pConfig) KERNEL32$HeapFree(hHeap, 0, pConfig);
    if (pSD) KERNEL32$HeapFree(hHeap, 0, pSD);
    if (pServices) KERNEL32$HeapFree(hHeap, 0, pServices);
    if (pTokenUser) KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    if (hService) ADVAPI32$CloseServiceHandle(hService);
    if (hSCManager) ADVAPI32$CloseServiceHandle(hSCManager);
    if (hToken) KERNEL32$CloseHandle(hToken);
}
