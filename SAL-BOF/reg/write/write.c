#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char * gHiveName = 1;
#pragma GCC diagnostic pop

static QWORD parse_qword(const char *s) {
    QWORD result = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        while (*s) {
            char c = *s++;
            QWORD digit;
            if      (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else break;
            result = (result << 4) | digit;
        }
    } else {
        while (*s >= '0' && *s <= '9')
            result = result * 10 + (*s++ - '0');
    }
    return result;
}

static DWORD parse_dword(const char *s) {
    return (DWORD)parse_qword(s);  // reuse, truncate to 32-bit
}


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

// Supported types: REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, REG_QWORD=11
DWORD Reg_WriteValue(
    const char * hostname,
    HKEY         hivekey,
    const char * keystring,
    const char * valuename,
    DWORD        regtype,
    const char * data,
    DWORD        datasz
){
    HKEY  key       = NULL;
    HKEY  RemoteKey = NULL;
    DWORD dwresult  = 0;
    DWORD dwDisp    = 0;  // REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY

    if (hostname == NULL)
    {
        dwresult = ADVAPI32$RegCreateKeyExA(
            hivekey, keystring, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
            NULL, &key, &dwDisp);
        if (dwresult) { goto END; }
    }
    else
    {
        dwresult = ADVAPI32$RegConnectRegistryA(hostname, hivekey, &RemoteKey);
        if (dwresult) { internal_printf("failed to connect\n"); goto END; }

        dwresult = ADVAPI32$RegCreateKeyExA(
            RemoteKey, keystring, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
            NULL, &key, &dwDisp);
        if (dwresult) { internal_printf("failed to open/create remote key\n"); goto END; }
    }

    dwresult = ADVAPI32$RegSetValueExA(key, valuename, 0, regtype, (const BYTE *)data, datasz);

    if (!dwresult)
    {
        internal_printf("%s: %s\\%s\\%s = [type:%lu, sz:%lu]\n",
            (dwDisp == REG_CREATED_NEW_KEY) ? "Created" : "Updated",
            gHiveName, keystring, valuename, regtype, datasz);
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
    datap       parser   = {0};
    const char *hostname = NULL;
    const char *path     = NULL;
    const char *key      = NULL;
    const char *dataStr  = NULL;
    HKEY        hive     = (HKEY)0x80000000;
    int         t        = 0;
    DWORD       regtype  = 0;
    DWORD       dwresult = 0;

    // Buffers for numeric coercion
    DWORD dword_val = 0;
    QWORD qword_val = 0;
    const char *data = NULL;
    DWORD        datasz = 0;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    t        = BeaconDataInt(&parser);
    path     = BeaconDataExtract(&parser, NULL);
    key      = BeaconDataExtract(&parser, NULL);
    regtype  = (DWORD)BeaconDataInt(&parser);
    dataStr  = BeaconDataExtract(&parser, NULL);  // always arrives as cstr

    set_hive_name(t);

    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    hive = (HKEY)((DWORD)hive + (DWORD)t);
    #pragma GCC diagnostic pop

    if (*hostname == 0) hostname = NULL;
    if (*key == 0) { BeaconPrintf(CALLBACK_ERROR, "Value name required\n"); return; }

    // Type coercion — BOF owns conversion from string
    switch (regtype) {
        case REG_DWORD:
            dword_val = parse_dword(dataStr);
            data   = (const char *)&dword_val;
            datasz = sizeof(DWORD);
            break;
        case REG_QWORD:
            qword_val = parse_qword(dataStr);
            data   = (const char *)&qword_val;
            datasz = sizeof(QWORD);
            break;
        case REG_SZ:
        case REG_EXPAND_SZ:
            data   = dataStr;
            datasz = (DWORD)MSVCRT$strlen(dataStr) + 1;
            break;
        case REG_BINARY:
            // For binary, expect hex string: "deadbeef" → bytes
            // Simple implementation: pass raw string bytes as-is
            // For proper hex decode, add a hex2bin helper
            data   = dataStr;
            datasz = (DWORD)MSVCRT$strlen(dataStr);
            break;
        default:
            data   = dataStr;
            datasz = (DWORD)MSVCRT$strlen(dataStr) + 1;
            break;
    }

    if (!bofstart()) return;

    BeaconPrintf(CALLBACK_OUTPUT,
        "Hostname: %s, Hive: %s, Path: %s, Key: %s, Type: %lu, DataSz: %lu",
        hostname ? hostname : "NULL", gHiveName, path, key, regtype, datasz);

    dwresult = Reg_WriteValue(hostname, hive, path, key, regtype, data, datasz);

    if (dwresult)
        BeaconPrintf(CALLBACK_ERROR, "Failed to write registry value, error: %lu", dwresult);

    printoutput(TRUE);
}

#else

int main()
{
    gHiveName = "HKEY_LOCAL_MACHINE";
    // Test REG_SZ write
    Reg_WriteValue(NULL, HKEY_LOCAL_MACHINE,
        "SOFTWARE\\TestKey", "TestValue",
        REG_SZ, "HelloWorld", 11);
    // Test REG_DWORD write
    DWORD dval = 1;
    Reg_WriteValue(NULL, HKEY_LOCAL_MACHINE,
        "SOFTWARE\\TestKey", "DwordValue",
        REG_DWORD, (char*)&dval, sizeof(DWORD));
    return 0;
}

#endif