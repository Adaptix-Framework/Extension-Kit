#include <windows.h>

DECLSPEC_IMPORT LPVOID WINAPI Kernel32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI Kernel32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT SIZE_T WINAPI Kernel32$VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

// std funcs
DECLSPEC_IMPORT int __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
DECLSPEC_IMPORT int __cdecl MSVCRT$fseek(FILE *stream, long offset, int origin);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
DECLSPEC_IMPORT unsigned long int __cdecl MSVCRT$strtoul(const char *str, char **endptr, int base);
DECLSPEC_IMPORT FILE *__cdecl MSVCRT$fopen(const char *filename, const char *mode);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$fread(void *buffer, size_t size, size_t count, FILE *stream);
DECLSPEC_IMPORT int __cdecl MSVCRT$fclose(FILE *stream);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void *ptr1, const void *ptr2, size_t num);
DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int seed);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$strcpy_s(char *dest, rsize_t destsz, const char *src);
DECLSPEC_IMPORT time_t __cdecl MSVCRT$time(time_t *timer);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf_s(char *restrict s, size_t n, const char *restrict format, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);
DECLSPEC_IMPORT errno_t __cdecl MSVCRT$wcscat_s(wchar_t *dest, size_t destsz, const wchar_t *src);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char* str, const char* format, ...);
// DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t* buffer, size_t count, const wchar_t* format, ...);



DECLSPEC_IMPORT BOOL WINAPI Advapi32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT LONG WINAPI Advapi32$RegSaveKeyA(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT HRESULT WINAPI Shlwapi$StringCchPrintfA(LPSTR pszDest, size_t cchDest, LPCSTR pszFormat, ...);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$_snprintf(char *buffer, size_t count, const char *format, ...);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegLoadKeyA(HKEY, LPCSTR, LPCSTR);
DECLSPEC_IMPORT int __cdecl MSVCRT$swscanf_s(const wchar_t *buffer, const wchar_t *format, ...);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegUnLoadKeyA(HKEY hKey, LPCSTR lpSubKey);
DECLSPEC_IMPORT LONG WINAPI Advapi32$RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys, LPDWORD lpcMaxSubKeyLen, LPDWORD lpcMaxClassLen, LPDWORD lpcValues, LPDWORD lpcMaxValueNameLen, LPDWORD lpcMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT LSTATUS WINAPI Advapi32$RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);

DECLSPEC_IMPORT HRESULT WINAPI Shell32$SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);

// Bcrypt
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptSetProperty(BCRYPT_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE *phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);
DECLSPEC_IMPORT NTSTATUS WINAPI bcrypt$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
