#pragma once
#pragma intrinsic(memcmp, memcpy, memset, strcpy, strcmp, _stricmp, strlen)
#include <stdio.h>
#include <windows.h>

#ifdef BOF

WINBASEAPI void *WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$IsBadWritePtr(LPVOID lp, UINT_PTR ucb);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                                                   LPWSTR lpWideCharStr, int cchWideChar);

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)                                                                                          \
    (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size)                               \
          : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr, size) MSVCRT$memset((addr), 0, size)

WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void *_Buf1, const void *_Buf2, size_t _Size);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char *__restrict__ d, size_t n, const char *__restrict__ format, va_list arg);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strcat(char *__restrict__ _Dest, const char *__restrict__ _Source);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1, const char *_Str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char *string1, const char *string2);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strcpy(char *__restrict__ __dst, const char *__restrict__ __src);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strncpy(char *__restrict__ __dst, const char *__restrict__ __src, size_t __n);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strchr(const char *haystack, int needle);
DECLSPEC_IMPORT char *__cdecl MSVCRT$strtok(char *__restrict__ _Str, const char *__restrict__ _Delim);
WINBASEAPI wchar_t *__cdecl MSVCRT$strncat(char *__restrict__ _Dest, const char *__restrict__ _Source, size_t _Count);

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA(int NameFormat, LPSTR lpNameBuffer, PULONG nSize);

typedef struct addrinfo
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;

DECLSPEC_IMPORT int __stdcall WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int __stdcall WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int __stdcall WS2_32$connect(SOCKET sock, const struct sockaddr *name, int namelen);
DECLSPEC_IMPORT int __stdcall WS2_32$closesocket(SOCKET sock);
DECLSPEC_IMPORT void __stdcall WS2_32$freeaddrinfo(struct addrinfo *ai);
DECLSPEC_IMPORT int __stdcall WS2_32$getaddrinfo(char *host, char *port, const struct addrinfo *hints,
                                                 struct addrinfo **result);
DECLSPEC_IMPORT int __stdcall WS2_32$send(SOCKET s, const char *buf, int len, int flags);
DECLSPEC_IMPORT int __stdcall WS2_32$recv(SOCKET s, char *buf, int len, int flags);
DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int __stdcall WS2_32$WSAGetLastError();

#else

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)                                                                                          \
    (ptr) ? KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size)                               \
          : KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)
#define intZeroMemory(addr, size) MSVCRT$memset((addr), 0, size)

#define KERNEL32$HeapAlloc HeapAlloc
#define KERNEL32$HeapReAlloc HeapReAlloc
#define KERNEL32$GetProcessHeap GetProcessHeap
#define KERNEL32$HeapFree HeapFree
#define KERNEL32$IsBadWritePtr IsBadWritePtr
#define KERNEL32$MultiByteToWideChar MultiByteToWideChar
#define MSVCRT$calloc calloc
#define MSVCRT$memcpy memcpy
#define MSVCRT$memcmp memcmp
#define MSVCRT$free free
#define MSVCRT$memset memset
#define MSVCRT$sprintf sprintf
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$strcat strcat
#define MSVCRT$strlen strlen
#define MSVCRT$strcmp strcmp
#define MSVCRT$strncmp strncmp
#define MSVCRT$_stricmp _stricmp
#define MSVCRT$strcpy strcpy
#define MSVCRT$strncpy strncpy
#define MSVCRT$strstr strstr
#define MSVCRT$strchr strchr
#define MSVCRT$strtok strtok
#define MSVCRT$strncat strncat
#define WS2_32$closesocket closesocket
#define WS2_32$connect connect
#define WS2_32$freeaddrinfo freeaddrinfo
#define WS2_32$getaddrinfo getaddrinfo
#define WS2_32$socket socket
#define WS2_32$WSAGetLastError WSAGetLastError
#define WS2_32$WSAStartup WSAStartup
#define WS2_32$WSACleanup WSACleanup
#define WS2_32$send send
#define WS2_32$recv recv
#define SECUR32$AcquireCredentialsHandleW AcquireCredentialsHandleW
#define SECUR32$InitializeSecurityContextW InitializeSecurityContextW
#define SECUR32$QueryContextAttributesW QueryContextAttributesW
#define SECUR32$EncryptMessage EncryptMessage
#define SECUR32$DecryptMessage DecryptMessage
#define SECUR32$FreeCredentialsHandle FreeCredentialsHandle
#define SECUR32$DeleteSecurityContext DeleteSecurityContext
#define SECUR32$FreeContextBuffer FreeContextBuffer
#define SECUR32$GetUserNameExA GetUserNameExA
#define RPCRT4$UuidCreate UuidCreate
#define NETAPI32$DsGetDcNameA DsGetDcNameA
#define NETAPI32$NetApiBufferFree NetApiBufferFree
#define BeaconPrintf(x, y, ...) printf(y, ##__VA_ARGS__)
#define internal_printf printf
#endif
