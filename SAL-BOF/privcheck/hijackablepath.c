#include <windows.h>
#include <string.h>
#include "bofdefs.h"
#include "beacon.h"
#include <processthreadsapi.h>

void go() {
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

    openResult = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, KEY_READ, &hKey);
    if (openResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,"[WRITABLE_PATH] Error opening registry key: %d\n", openResult);
    }

    queryResult = Advapi32$RegQueryValueExA(hKey, "Path", NULL, &valueType, (LPBYTE)data, &dataSize);
    if (queryResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,"[WRITABLE_PATH] Error querying registry value: %d\n", queryResult);
        Advapi32$RegCloseKey(hKey);
        return;
    }

    char* pathToken = MSVCRT$strtok(data, ";");
    while (pathToken != NULL) {
        DWORD attributes = Kernel32$GetFileAttributesA(pathToken);
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {

            // Get length needed to allocate for the security descriptor.
            if (!Advapi32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0, &len) && ERROR_INSUFFICIENT_BUFFER == Kernel32$GetLastError()) {
                // Allocate space needed for security descriptor
                PSECURITY_DESCRIPTOR security = MSVCRT$malloc(len);
                // If space allocated, then obtain the security descriptor
                if (security && Advapi32$GetFileSecurityA(pathToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, security, len, &len)) {
                    // The AccessCheck API requires an impersonation token
                    if (Advapi32$OpenProcessToken(Kernel32$GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken)) {
                        // Duplicate the necessary token
                        if (Advapi32$DuplicateToken(hToken, SecurityImpersonation, &hImpersonatedToken)) {
                            GENERIC_MAPPING mapping = {
                                    FILE_GENERIC_READ,
                                    FILE_GENERIC_WRITE,
                                    FILE_GENERIC_EXECUTE,
                                    FILE_ALL_ACCESS
                            };

                            PRIVILEGE_SET privileges = { 0 };
                            DWORD grantedAccess = 0, privilegesLength = sizeof(privileges);
                            BOOL result = FALSE;

                            // Check if we have FILE_ADD_FILE access
                            if (Advapi32$AccessCheck(security, hImpersonatedToken, GenericAccess, &mapping, &privileges, &privilegesLength, &grantedAccess, &result)) {
                                if (result) {
                                    BeaconPrintf(CALLBACK_OUTPUT,"[WRITABLE_PATH] Found writable directory in PATH: %s\n", pathToken);
                                    NumOfWritablePaths++;
                                }
                            }
                            Kernel32$CloseHandle(hImpersonatedToken);
                        }
                        Kernel32$CloseHandle(hToken); 
                    }
                    MSVCRT$free(security);
                }
                
            }
        }
        pathToken = MSVCRT$strtok(NULL, ";");
    }
    Advapi32$RegCloseKey(hKey);
    BeaconPrintf(CALLBACK_OUTPUT,"[WRITABLE_PATH] Found %d writable directories in PATH\n", NumOfWritablePaths);
}
