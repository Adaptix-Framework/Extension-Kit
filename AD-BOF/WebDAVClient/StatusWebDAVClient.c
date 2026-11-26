#include <windows.h>
#include <stdio.h>
#include "beacon.h"

WINBASEAPI BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI char* WINAPI MSVCRT$strcpy(char* dest, const char* source);
WINBASEAPI char* WINAPI MSVCRT$strcat(char* dest, const char* source);
WINBASEAPI char* WINAPI MSVCRT$strtok(char* str, const char* delim);
WINBASEAPI void WINAPI MSVCRT$free(void*);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, SIZE_T count);

void go(char* args, int length)
{
    datap parser;
    BeaconDataParse(&parser, args, length);

    char* hosts = (char*)BeaconDataExtract(&parser, NULL);
    if (hosts == NULL || MSVCRT$strlen(hosts) == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] No hosts provided");
        return;
    }

    SIZE_T hostsLen = MSVCRT$strlen(hosts) + 1;
    char* hostsCopy = (char*)MSVCRT$malloc(hostsLen);
    if (hostsCopy == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        return;
    }
    MSVCRT$memcpy(hostsCopy, hosts, hostsLen);

    char* pipeNameHead = "\\\\";
    char* pipeNameTail = "\\pipe\\DAV RPC SERVICE";
    BOOL pipeStatus = 0;
    char* singleHost = MSVCRT$strtok(hostsCopy, ",");

    while (singleHost != NULL)
    {
        char* fullPipeName = (char*)MSVCRT$malloc(MSVCRT$strlen(singleHost) + MSVCRT$strlen(pipeNameHead) + MSVCRT$strlen(pipeNameTail) + 1);
        if (fullPipeName == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for pipe name");
            break;
        }
        MSVCRT$strcpy(fullPipeName, pipeNameHead);
        MSVCRT$strcat(fullPipeName, singleHost);
        MSVCRT$strcat(fullPipeName, pipeNameTail);
        pipeStatus = KERNEL32$WaitNamedPipeA(fullPipeName, 3000);
        if (pipeStatus == 0)
            BeaconPrintf(CALLBACK_OUTPUT, "[x] Unable to hit DAV pipe on %s, system is either unreachable or does not have WebClient service running", singleHost);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[+] WebClient service is active on %s", singleHost);
        MSVCRT$free(fullPipeName);
        singleHost = MSVCRT$strtok(NULL, ",");
    }

    MSVCRT$free(hostsCopy);
}
