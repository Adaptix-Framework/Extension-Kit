#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#include "bofdefs.h"
#include "beacon.h"
#include "vulndrivers.h"

#define BUFSIZE		1024
#define SHA256LEN	32
#define SHA1LEN		20
#define MD5LEN		16

// Compare calculated hash to all known vulnerable hashes
BOOL CompareHashToVuln(char* DriverHash) {
    int i = 0;

    // Check if vulnerable hash exists in list
    while (VulnerableHashes[i]) {
        if (MSVCRT$_stricmp(VulnerableHashes[i], DriverHash) == 0) {
            return TRUE;
        }
        i++;
    }
    // If not, just continue
    return FALSE;
}


// Resolve the absolute path of drivers
void resolveDriverImagePath(char* imagePath, char* resolvedPath, size_t pathSize) {
    char szSystemRoot[MAX_PATH * 2];

    // Resolve the SystemRoot variable to path
    if (!Kernel32$GetEnvironmentVariableA("SystemRoot", szSystemRoot, sizeof(szSystemRoot))) {
        BeaconPrintf(CALLBACK_OUTPUT,"[ERROR] Failed to resolve SystemRoot for path: %s\n", imagePath);
    }

    if (MSVCRT$_strnicmp(imagePath, "\\SystemRoot\\", 12) == 0) {
        // Replace "\SystemRoot" with the SystemRoot environment variable
        User32$wsprintfA(resolvedPath, "%s%s", szSystemRoot, imagePath + 11);
    }
    else if (MSVCRT$_strnicmp(imagePath, "System32\\", 9) == 0) {
        // Prepend SystemRoot to paths starting with "System32\"
        User32$wsprintfA(resolvedPath, "%s\\%s", szSystemRoot, imagePath);
    }
    else if (MSVCRT$_strnicmp(imagePath, "\\??\\", 4) == 0) {
        // Remove the "\\??\\" prefix
        MSVCRT$strncpy(resolvedPath, imagePath + 4, pathSize - 1);
        resolvedPath[pathSize - 1] = '\0';  // Ensure null-termination
    }
    else {
        // Otherwise, leave it as is
        MSVCRT$strncpy(resolvedPath, imagePath, pathSize - 1);
        resolvedPath[pathSize - 1] = '\0';  // Ensure null-termination
    }
}

BOOL CalculateHash(char * szFilePath, char szFileHash[65], const char * szHashAlg) {

    HANDLE hFile;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL bResult;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead;
    DWORD cbHash;
    BYTE rgbHash[SHA256LEN];
    CHAR rgbDigits[] = "0123456789abcdef";
    ALG_ID hashAlgId;
    DWORD hashLen;

    if (MSVCRT$_stricmp(szHashAlg, "SHA1") == 0) {
        hashAlgId	= CALG_SHA1;
        hashLen = SHA1LEN;
    }
    else if (MSVCRT$_stricmp(szHashAlg, "SHA256") == 0) {
        hashAlgId = CALG_SHA_256;
        hashLen = SHA256LEN;
    }
    else if (MSVCRT$_stricmp(szHashAlg, "MD5") == 0) {
        hashAlgId = CALG_MD5;
        hashLen = MD5LEN;
    }
    else {
        return FALSE;
    }

    cbHash = hashLen;

    // Open file to hash
    hFile = Kernel32$CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,"Error opening %s\n", szFilePath);
        return FALSE;
    }



    // Get handle to crypto provider
    if (!Advapi32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_OUTPUT,"Advapi32$CryptAcquireContextA failed\n");
        Kernel32$CloseHandle(hFile);
        return FALSE;
    }

    // Initialize hash
    if (!Advapi32$CryptCreateHash(hProv, hashAlgId, 0, 0, &hHash)) {
        BeaconPrintf(CALLBACK_OUTPUT,"Advapi32$CryptCreateHash failed\n");
        Kernel32$CloseHandle(hFile);
        Advapi32$CryptReleaseContext(hProv, 0);
        return FALSE;
    }


    while ((bResult = Kernel32$ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL))) {
        if (cbRead == 0) {
            break;
        }

        if (!Advapi32$CryptHashData(hHash, rgbFile, cbRead, 0)) {
            BeaconPrintf(CALLBACK_OUTPUT,"Advapi32$CryptHashData failed\n");
            Advapi32$CryptReleaseContext(hProv, 0);
            Advapi32$CryptDestroyHash(hHash);
            Kernel32$CloseHandle(hFile);
            return FALSE;
        }
    }


    if (!bResult) {
        BeaconPrintf(CALLBACK_OUTPUT,"ReadFile failed\n");
        Advapi32$CryptReleaseContext(hProv, 0);
        Advapi32$CryptDestroyHash(hHash);
        Kernel32$CloseHandle(hFile);
        return FALSE;
    }



    // Hash the file
    if (Advapi32$CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (DWORD i = 0; i < cbHash; i++) {
            szFileHash[i * 2] = rgbDigits[rgbHash[i] >> 4];
            szFileHash[i * 2 + 1] = rgbDigits[rgbHash[i] & 0xf];
        }

        // null terminate string
        szFileHash[cbHash * 2] = '\0';

        Advapi32$CryptDestroyHash(hHash);
        Advapi32$CryptReleaseContext(hProv, 0);
        Kernel32$CloseHandle(hFile);

        return TRUE;
    }
    else {
        BeaconPrintf(CALLBACK_OUTPUT,"Advapi32$CryptGetHashParam failed\n");
        Advapi32$CryptDestroyHash(hHash);
        Advapi32$CryptReleaseContext(hProv, 0);
        Kernel32$CloseHandle(hFile);
        return FALSE;
    }

}


void go() {
    HKEY servicesKey;
    char resolvedPath[MAX_PATH];
    int NumOfVulnDrivers = 0;

    // Extract all drivers from services
    if (Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\", 0, KEY_READ, &servicesKey) == ERROR_SUCCESS) {
        char serviceSubkeyName[256];
        DWORD subkeyIndex = 0;
        DWORD subkeyNameSize = sizeof(serviceSubkeyName);
        // Iterate over each service
        while (Advapi32$RegEnumKeyExA(servicesKey, subkeyIndex++, serviceSubkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY imagePathKey;
            if (Advapi32$RegOpenKeyExA(servicesKey, serviceSubkeyName, 0, KEY_READ, &imagePathKey) == ERROR_SUCCESS) {
                char imagePathValue[1024];
                DWORD valueSize = sizeof(imagePathValue);
                // Obtain value of the "ImagePath"
                if (Advapi32$RegGetValueA(imagePathKey, NULL, "ImagePath", RRF_RT_REG_SZ, NULL, &imagePathValue, &valueSize) == ERROR_SUCCESS) {
                    // Check if imagePathValue is empty
                    if (imagePathValue[0] == '\0') {
                        Advapi32$RegCloseKey(imagePathKey);
                        continue;
                    }

                    // Check if value ends in '.sys'
                    if (MSVCRT$strstr(imagePathValue, ".sys") != NULL) {
                        // Resolve the absolute path of the driver
                        resolveDriverImagePath(imagePathValue, resolvedPath, sizeof(resolvedPath));

                        char FileHash[65];
                        const char* HashAlgos[] = {
                                "SHA1",
                                "SHA256",
                                "MD5"
                        };

                        for (int i = 0; i < sizeof(HashAlgos) / sizeof(HashAlgos[i]); i++) {
                            // Calculate hashes for driver
                            if (CalculateHash(resolvedPath, FileHash, HashAlgos[i])) {
                                if (CompareHashToVuln(FileHash)) {
                                    BeaconPrintf(CALLBACK_OUTPUT,"[VULN_DRIVER] Service \"%s\" has a vulnerable driver: %s - Hash: %s\n", serviceSubkeyName, resolvedPath, FileHash);
                                    NumOfVulnDrivers++;
                                    break;
                                }
                            } else {
                                BeaconPrintf(CALLBACK_OUTPUT, "[VULN_DRIVER] Failed to calculate hash for driver: %s\n", resolvedPath);
                            }
                        }
                    }
                }
                Advapi32$RegCloseKey(imagePathKey);
            }
            subkeyNameSize = sizeof(serviceSubkeyName);
        }
        Advapi32$RegCloseKey(servicesKey);
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[VULN_DRIVER] Found a total of %d vulnerable drivers\n", NumOfVulnDrivers);
}