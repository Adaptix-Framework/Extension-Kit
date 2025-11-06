#define SECURITY_WIN32
#include "beacon.h"
#include "bofdefs.h"
#include <dsgetdc.h>
#include <lm.h>
#include <rpc.h>
#include <security.h>

#include "adws_parser.h"
#include "nbfse.h"
#include "nmf.h"
#include "nns.h"

#ifdef BOF
void ___chkstk_ms(void){}
void __chkstk_ms(void){}
#endif

#ifndef bufsize
#define bufsize 10485760
#endif

char *output __attribute__((section(".data"))) = 0;
DWORD currentoutsize __attribute__((section(".data"))) = 0;
HANDLE trash __attribute__((section(".data"))) = NULL;
BOOL g_useBeaconFormat __attribute__((section(".data"))) = -1;

#ifdef BOF
int bofstart()
{
    output = (char *)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void printoutput(BOOL done)
{
    char *msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if (done)
    {
        MSVCRT$free(output);
        output = NULL;
    }
}

void internal_printf(const char *format, ...)
{
    int buffersize = 0;
    int transfersize = 0;
    char *curloc = NULL;
    char *intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1)
        return;

    char *transferBuffer = (char *)intAlloc(bufsize);
    intBuffer = (char *)intAlloc(buffersize);
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);
    if (buffersize + currentoutsize < bufsize)
    {
        MSVCRT$memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    }
    else
    {
        curloc = intBuffer;
        while (buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
            {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
            {
                printoutput(FALSE);
            }
            MSVCRT$memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}
#else
#define bofstart()
#define printoutput(x)
#define internal_printf printf
#endif

#ifdef BOF
void DetectBeaconFormatSupport()
{
    if (g_useBeaconFormat != -1)
        return;

    formatp test;
    BeaconFormatAlloc(&test, 1024);
    BeaconFormatPrintf(&test, "test");
    char *testOutput = BeaconFormatToString(&test, NULL);
    g_useBeaconFormat = (testOutput != NULL && test.original != NULL) ? 1 : 0;
    BeaconFormatFree(&test);
}

void OutputInit(OutputBuffer *out)
{
    out->initialized = FALSE;
    if (g_useBeaconFormat)
    {
        BeaconFormatAlloc(&out->buffer, 64 * 1024);
        out->initialized = TRUE;
    }
}

void OutputPrintf(OutputBuffer *out, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    if (g_useBeaconFormat && out->initialized)
    {
        char temp[4096];
        MSVCRT$vsnprintf(temp, sizeof(temp), format, args);
        BeaconFormatPrintf(&out->buffer, "%s", temp);
    }
    else
    {
        char temp[4096];
        MSVCRT$vsnprintf(temp, sizeof(temp), format, args);
        internal_printf("%s", temp);
    }

    va_end(args);
}

void OutputFlush(OutputBuffer *out, DWORD objIdx)
{
    if (g_useBeaconFormat && out->initialized)
    {
        char *objectOutput = BeaconFormatToString(&out->buffer, NULL);
        if (objectOutput)
        {
            internal_printf("%s", objectOutput);
        }
        BeaconFormatFree(&out->buffer);
    }

    if ((objIdx + 1) % 5 == 0)
    {
        printoutput(FALSE);
    }
}
#endif

#ifdef BOF
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(LPWSTR, LPWSTR, ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, LPWSTR, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$QueryContextAttributesW(PCtxtHandle, ULONG, PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$EncryptMessage(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DecryptMessage(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);

DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$UuidCreate(UUID *);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$IsBadWritePtr(LPVOID lp, UINT_PTR ucb);
#endif

void Phase5_FullEnumeration(const char *target, const char *ldapFilter, const char *attrFilter);
BOOL ConnectToADWS(SOCKET *pSocket, const char *target);

BOOL GetDistinguishedName(char *distinguishedName, DWORD size)
{
    char tempBuffer[512];
    ULONG ulSize = sizeof(tempBuffer);

    if (!SECUR32$GetUserNameExA(NameFullyQualifiedDN, tempBuffer, &ulSize))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve user's distinguished name");
        return FALSE;
    }

    char *dcPart = MSVCRT$strstr(tempBuffer, "DC=");
    if (!dcPart)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to find DC= in distinguished name");
        return FALSE;
    }

    MSVCRT$strncpy(distinguishedName, dcPart, size - 1);
    distinguishedName[size - 1] = '\0';

    return TRUE;
}

BOOL GetDomainController(char *dcName, DWORD size)
{
    PDOMAIN_CONTROLLER_INFO pdcInfo = NULL;
    DWORD dwRet = 0;

    dwRet = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);

    if (dwRet != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to identify Domain Controller. Are we domain joined?");
        return FALSE;
    }

    if (!pdcInfo || !pdcInfo->DomainControllerName)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] DsGetDcNameA returned no DC information");
        if (pdcInfo)
            NETAPI32$NetApiBufferFree(pdcInfo);
        return FALSE;
    }

    const char *dcAddress = pdcInfo->DomainControllerAddress;
    if (dcAddress[0] == '\\' && dcAddress[1] == '\\')
    {
        dcAddress += 2;
    }

    MSVCRT$strncpy(dcName, dcAddress, size - 1);
    dcName[size - 1] = '\0';

    NETAPI32$NetApiBufferFree(pdcInfo);
    return TRUE;
}

BOOL DeriveBaseDN(const char *target, char *baseDN, DWORD baseDNSize);

BOOL DeriveBaseDN(const char *target, char *baseDN, DWORD baseDNSize)
{

    if (!target || !baseDN || baseDNSize < 10)
        return FALSE;

    baseDN[0] = '\0';

    BOOL isIP = TRUE;
    for (const char *p = target; *p; p++)
    {
        if ((*p < '0' || *p > '9') && *p != '.')
        {
            isIP = FALSE;
            break;
        }
    }

    if (isIP)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot derive base DN from IP address. Please use hostname.");
        return FALSE;
    }

    const char *domainStart = MSVCRT$strchr(target, '.');
    if (!domainStart)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid target format. Expected: hostname.domain.tld");
        return FALSE;
    }

    domainStart++;

    char tempDomain[256];
    MSVCRT$strncpy(tempDomain, domainStart, 255);
    tempDomain[255] = '\0';

    baseDN[0] = '\0';

    char *component = MSVCRT$strtok(tempDomain, ".");
    BOOL first = TRUE;

    while (component != NULL)
    {
        if (!first)
        {
            MSVCRT$strcat(baseDN, ",");
        }
        MSVCRT$strcat(baseDN, "DC=");
        MSVCRT$strcat(baseDN, component);
        first = FALSE;
        component = MSVCRT$strtok(NULL, ".");
    }

    return (MSVCRT$strlen(baseDN) > 0);
}

BOOL ConnectToADWS(SOCKET *pSocket, const char *target)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    int ret;

    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    ret = WS2_32$getaddrinfo((char *)target, "9389", &hints, &result);
    if (ret != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] getaddrinfo failed: %d", ret);
        return FALSE;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        *pSocket = WS2_32$socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (*pSocket == INVALID_SOCKET)
        {
            continue;
        }

        ret = WS2_32$connect(*pSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (ret == SOCKET_ERROR)
        {
            WS2_32$closesocket(*pSocket);
            *pSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    WS2_32$freeaddrinfo(result);
    return (*pSocket != INVALID_SOCKET);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    if (!bofstart()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize output buffer");
        return;
    }

    DetectBeaconFormatSupport();

    datap parser = {};
    BeaconDataParse(&parser, Buffer, Length);

    char *ldapFilter = BeaconDataExtract(&parser, NULL);
    char *attrFilter = BeaconDataExtract(&parser, NULL);
    char *target     = BeaconDataExtract(&parser, NULL);
    char *baseDN     = BeaconDataExtract(&parser, NULL);

    BOOL targetAuto = FALSE;
    BOOL dnAuto     = FALSE;

    if (ldapFilter == 0 || attrFilter == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Note: arguments unknown");
        return;
    }

    if( target && target[0] == 0 ) {
        targetAuto = TRUE;
        target = (char *) intAlloc(256);

        if (!GetDomainController(target, 256))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to auto-discover domain controller");
            intFree(target);
            return;
        }
    }

    if ( baseDN && baseDN[0] == 0 ) {
        dnAuto = TRUE;
        baseDN = (char *) intAlloc(512);

        if (!GetDistinguishedName(baseDN, 512)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Falling back to deriving DN from target hostname...\n");
            if (!DeriveBaseDN(target, baseDN, 512)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to derive base DN from target\n");
                goto cleanup_params;
            }
        }
    }

    internal_printf("[*] Filter:     %s\n", ldapFilter);
    internal_printf("[*] Attributes: %s\n", attrFilter ? attrFilter : "ALL");
    internal_printf("[*] Base DN:    %s\n", baseDN);
    internal_printf("[*] Target DC:  %s\n", target);

    CONNECTION_CONTEXT ctx = {0};
    ctx.socket = INVALID_SOCKET;
    ctx.hCred.dwLower = 0;
    ctx.hCred.dwUpper = 0;
    ctx.hContext.dwLower = 0;
    ctx.hContext.dwUpper = 0;

    int ret = WS2_32$WSAStartup(MAKEWORD(2, 2), &ctx.wsaData);
    if (ret != 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] WSAStartup failed: %d\n", ret);
        return;
    }

    if (!ConnectToADWS(&ctx.socket, target))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to connect to ADWS\n");
        goto cleanup_params;
    }
    internal_printf("[+] Connected to ADWS\n");

    if (!SendNMFHandshake(ctx.socket, target))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] NMF handshake failed\n");
        goto cleanup_params;
    }

    if (!PerformNNSHandshake(&ctx, target))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] NNS authentication failed\n");
        goto cleanup_params;
    }
    internal_printf("[+] Authenticated\n");

    NBFSE_BUFFER *nbfseBuffer = NBFSEBufferCreate(8192);
    if (!nbfseBuffer)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create NBFSE buffer");
        goto cleanup_params;
    }

    if (!BuildEnumerateRequest(nbfseBuffer, ldapFilter, baseDN, target, attrFilter))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build enumerate request");
        NBFSEBufferFree(nbfseBuffer);
        goto cleanup_params;
    }

    if (!SendADWSMessage(&ctx, nbfseBuffer->data, nbfseBuffer->size))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to send ADWS message");
        NBFSEBufferFree(nbfseBuffer);
        goto cleanup_params;
    }

    PBYTE response = NULL;
    DWORD responseLen = 0;
    if (!NNSReceiveEncrypted(&ctx, &response, &responseLen))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to receive response");
        NBFSEBufferFree(nbfseBuffer);
        goto cleanup_params;
    }

    PBYTE nbfsePayload = NULL;
    DWORD nbfseLen = 0;
    if (!UnwrapNMFEnvelope(response, responseLen, &nbfsePayload, &nbfseLen))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to unwrap NMF envelope");
        intFree(response);
        NBFSEBufferFree(nbfseBuffer);
        goto cleanup_params;
    }

    char *enumerationContext = (char *)intAlloc(256);
    if (!enumerationContext)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for enumeration context");
        intFree(response);
        NBFSEBufferFree(nbfseBuffer);
        goto cleanup_params;
    }

    enumerationContext[0] = '\0';
    if (!ParseEnumerateResponse(nbfsePayload, nbfseLen, enumerationContext, 256))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse enumeration context");
        intFree(response);
        NBFSEBufferFree(nbfseBuffer);
        intFree(enumerationContext);
        goto cleanup_params;
    }

    intFree(response);
    NBFSEBufferFree(nbfseBuffer);

    internal_printf("[*] Retrieving objects...\n");

    BOOL hasMore = TRUE;
    int pullCount = 0;
    int totalObjectsRetrieved = 0;

    while (hasMore)
    {
        nbfseBuffer = NBFSEBufferCreate(1024);
        if (!nbfseBuffer)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create buffer for pull request");
            goto cleanup_params;
        }

        if (!BuildPullRequest(nbfseBuffer, enumerationContext, 256, target))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build pull request");
            NBFSEBufferFree(nbfseBuffer);
            goto cleanup_params;
        }

        if (!SendADWSMessage(&ctx, nbfseBuffer->data, nbfseBuffer->size))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to send pull request");
            NBFSEBufferFree(nbfseBuffer);
            goto cleanup_params;
        }
        NBFSEBufferFree(nbfseBuffer);

        response = NULL;
        responseLen = 0;
        if (!NNSReceiveEncrypted(&ctx, &response, &responseLen))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to receive pull response");
            goto cleanup_params;
        }

        nbfsePayload = NULL;
        nbfseLen = 0;
        if (!UnwrapNMFEnvelope(response, responseLen, &nbfsePayload, &nbfseLen))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to unwrap pull response");
            intFree(response);
            goto cleanup_params;
        }

        DWORD objectsInThisPull = 0;
        if (!ParsePullResponse(nbfsePayload, nbfseLen, attrFilter, &hasMore, &objectsInThisPull))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse pull response");
            intFree(response);
            goto cleanup_params;
        }

        totalObjectsRetrieved += objectsInThisPull;
        intFree(response);
        pullCount++;
    }

    internal_printf("\nRetrieved %d results total\n", totalObjectsRetrieved);

    if (enumerationContext)
        intFree(enumerationContext);

cleanup:
    if (ctx.socket != INVALID_SOCKET)
        WS2_32$closesocket(ctx.socket);

    if (ctx.hContext.dwLower || ctx.hContext.dwUpper)
        SECUR32$DeleteSecurityContext(&ctx.hContext);

    if (ctx.hCred.dwLower || ctx.hCred.dwUpper)
        SECUR32$FreeCredentialsHandle(&ctx.hCred);

    WS2_32$WSACleanup();

cleanup_params:
    if (target && targetAuto)
        intFree(target);
    if (baseDN && dnAuto)
        intFree(baseDN);

    printoutput(TRUE);
}
#endif
