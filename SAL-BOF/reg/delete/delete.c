#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult);

WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(
    HKEY hKey,
    LPCSTR lpValueName);

WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyA(
    HKEY hKey,
    LPCSTR lpSubKey);

WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryA(
    LPCSTR lpMachineName,
    HKEY hKey,
    PHKEY phkResult);

WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(
    HKEY hKey);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char * gHiveName = 1;
#pragma GCC diagnostic pop

void set_hive_name(DWORD h)
{
    switch(h) {
        case 0: gHiveName = "HKEY_CLASSES_ROOT";   break;
        case 1: gHiveName = "HKEY_CURRENT_USER";   break;
        case 2: gHiveName = "HKEY_LOCAL_MACHINE";  break;
        case 3: gHiveName = "HKEY_USERS";          break;
        case 5: gHiveName = "HKEY_CURRENT_CONFIG"; break;
        default: gHiveName = "UNKNOWN";            break;
    }
}

// Delete a value under a key, or the key itself if valuename is NULL
DWORD Reg_Delete(
    const char * hostname,
    HKEY         hivekey,
    const char * keystring,
    const char * valuename   // NULL = delete the key itself
){
    HKEY  key       = NULL;
    HKEY  RemoteKey = NULL;
    DWORD dwresult  = 0;

    if (hostname == NULL)
    {
        if (valuename)
        {
            // Delete value: need to open parent key first
            dwresult = ADVAPI32$RegOpenKeyExA(hivekey, keystring, 0, KEY_SET_VALUE, &key);
            if (dwresult) { goto END; }

            dwresult = ADVAPI32$RegDeleteValueA(key, valuename);
            if (!dwresult)
                internal_printf("Deleted value: %s\\%s\\%s\n", gHiveName, keystring, valuename);
        }
        else
        {
            // Delete key (must be empty — no subkeys)
            dwresult = ADVAPI32$RegDeleteKeyA(hivekey, keystring);
            if (!dwresult)
                internal_printf("Deleted key: %s\\%s\n", gHiveName, keystring);
        }
    }
    else
    {
        dwresult = ADVAPI32$RegConnectRegistryA(hostname, hivekey, &RemoteKey);
        if (dwresult) { internal_printf("failed to connect\n"); goto END; }

        if (valuename)
        {
            dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, keystring, 0, KEY_SET_VALUE, &key);
            if (dwresult) { internal_printf("failed to open remote key\n"); goto END; }

            dwresult = ADVAPI32$RegDeleteValueA(key, valuename);
            if (!dwresult)
                internal_printf("Deleted value: %s\\%s\\%s\n", gHiveName, keystring, valuename);
        }
        else
        {
            dwresult = ADVAPI32$RegDeleteKeyA(RemoteKey, keystring);
            if (!dwresult)
                internal_printf("Deleted key: %s\\%s\n", gHiveName, keystring);
        }
    }

END:
    if (key)       ADVAPI32$RegCloseKey(key);
    if (RemoteKey) ADVAPI32$RegCloseKey(RemoteKey);
    return dwresult;
}

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
){
    datap       parser    = {0};
    const char *hostname  = NULL;
    const char *path      = NULL;
    const char *key       = NULL;
    HKEY        hive      = (HKEY)0x80000000;
    int         t         = 0;
    DWORD       dwresult  = 0;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    t        = BeaconDataInt(&parser);
    path     = BeaconDataExtract(&parser, NULL);
    key      = BeaconDataExtract(&parser, NULL);

    set_hive_name(t);

    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    hive = (HKEY)((DWORD)hive + (DWORD)t);
    #pragma GCC diagnostic pop

    if (*hostname == 0) hostname = NULL;
    if (*key == 0)      key      = NULL;  // no -k = delete the key itself

    if (!bofstart()) { return; }

    BeaconPrintf(CALLBACK_OUTPUT,
        "Hostname: %s, Hive: %s, Path: %s, Key: %s",
        hostname ? hostname : "NULL", gHiveName, path, key ? key : "NULL");

    dwresult = Reg_Delete(hostname, hive, path, key);

    if (dwresult)
        BeaconPrintf(CALLBACK_ERROR, "Failed to delete, error: %lu", dwresult);

    printoutput(TRUE);
}

#else

int main()
{
    gHiveName = "HKEY_LOCAL_MACHINE";
    // Delete a value
    Reg_Delete(NULL, HKEY_LOCAL_MACHINE, "SOFTWARE\\TestKey", "TestValue");
    // Delete a key
    Reg_Delete(NULL, HKEY_LOCAL_MACHINE, "SOFTWARE\\TestKey", NULL);
    return 0;
}

#endif