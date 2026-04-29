#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "anticrash.c"
#include "stack.c"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
char ** ERegTypes = 1;
char *  gHiveName = 1;
#pragma GCC diagnostic pop

typedef struct _regkeyval {
    char * keypath;
    DWORD  dwkeypathsz;
    HKEY   hreg;
} regkeyval, *pregkeyval;

void init_enums(){
    ERegTypes = antiStringResolve(12, "REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REGDWORD_BE", "REG_LINK", "REG_MULTI_SZ", "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESC", "REG_RESOURCE_REQ_LIST", "REG_QWORD");
}

void free_enums(){
    intFree(ERegTypes);
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

pregkeyval init_regkey(const char * curpath, DWORD dwcurpathsz, const char * childkey, DWORD dwchildkeysz, HKEY hreg)
{
    pregkeyval item = (pregkeyval)intAlloc(sizeof(regkeyval));
    item->dwkeypathsz = dwcurpathsz + ((dwchildkeysz) ? dwchildkeysz + 1 : 0); //str\str does not include null or just str, if we don't have a child key
    item->keypath = intAlloc(item->dwkeypathsz + 1);
    memcpy(item->keypath, curpath, dwcurpathsz);
    if(dwchildkeysz > 0)
    {
        item->keypath[dwcurpathsz] = '\\';
        memcpy(item->keypath + dwcurpathsz + 1, childkey, dwchildkeysz);
    }
    item->hreg = hreg;
    //item->keypath[item->dwkeypathsz] = 0;
    return item;
}

void free_regkey(pregkeyval val)
{
    if(val->keypath)
    {
        intFree(val->keypath);
    }
    if(val->hreg)
    {
        ADVAPI32$RegCloseKey(val->hreg);
    }
}

void Reg_InternalPrintKey(char * data, const char * valuename, DWORD type, DWORD datalen, HKEY key){
    char default_name[] = {'[', 'N', 'U', 'L', 'L', ']', 0};
    int i = 0;

    if(valuename == NULL)
    {
        valuename = default_name;
    }
    internal_printf("\t%-20s   %-15s ", valuename, (type >= 0 && type <= 11) ? ERegTypes[type] : "UNKNOWN");

    if(type == REG_BINARY)
    {
        for(i = 0; i < datalen; i++)
        {
            if(i % 16 == 0)
                internal_printf("\n");
            internal_printf(" %2.2x ", data[i] & 0xff);  
        }
        internal_printf("\n");
    }
    else if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && datalen == 4)
        internal_printf("%lu\n", *(DWORD *)data);
    else if (type == REG_QWORD && datalen == 8)
        internal_printf("%llu\n", *(QWORD *)data);
    else if (type == REG_SZ || type == REG_EXPAND_SZ)
        internal_printf("%s\n", data);
    else if (type == REG_MULTI_SZ)
    {
        while(data[0] != '\0')
        {
            DWORD len = MSVCRT$strlen(data)+1;
            internal_printf("%s%s", data, (data[len]) ? "\\0" : "");
            data += MSVCRT$strlen(data)+1;
        }
        internal_printf("\n");
    }
    else
    {
        internal_printf("None data type, or unhandled\n");
    }
}

// Simple case-insensitive substring match, no CRT
static BOOL str_icontains(const char *haystack, const char *needle) {
    if (!needle || !*needle) return TRUE;
    if (!haystack) return FALSE;
    size_t nlen = MSVCRT$strlen(needle);
    size_t hlen = MSVCRT$strlen(haystack);
    if (nlen > hlen) return FALSE;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j = 0;
        while (j < nlen) {
            char hc = haystack[i+j];
            char nc = needle[j];
            // tolower inline
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
            j++;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

// search_type: 0 = value name, 1 = value data, 2 = both
DWORD Reg_Find(
    const char * hostname,
    HKEY         hivekey,
    const char * keystring,
    const char * pattern,
    int          search_type
){
    HKEY   rootkey    = NULL;
    HKEY   RemoteKey  = NULL;
    HKEY   curKey     = NULL;
    DWORD  dwresult   = 0;
    DWORD  cSubKeys   = 0, cbMaxSubKey  = 0;
    DWORD  cValues    = 0, cchMaxValue  = 0, cchMaxData = 0;
    DWORD  cchValue   = 0, cchData      = 0, regType    = 0;
    DWORD  cbName     = 0;
    DWORD  i          = 0;
    DWORD  retCode    = 0;
    DWORD  matches    = 0;
    Pstack keyStack   = NULL;
    pregkeyval curitem = NULL;
    char * currentkeyname   = NULL;
    char * currentvaluename = NULL;
    char * currentdata      = NULL;

    if (hostname == NULL)
    {
        dwresult = ADVAPI32$RegOpenKeyExA(hivekey, keystring, 0, KEY_READ, &rootkey);
        if (dwresult) { goto END; }
    }
    else
    {
        dwresult = ADVAPI32$RegConnectRegistryA(hostname, hivekey, &RemoteKey);
        if (dwresult) { internal_printf("failed to connect\n"); goto END; }

        dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, keystring, 0, KEY_READ, &rootkey);
        if (dwresult) { internal_printf("failed to open remote key\n"); goto END; }
    }

    keyStack = stackInit();
    keyStack->push(keyStack, init_regkey(keystring, MSVCRT$strlen(keystring), NULL, 0, rootkey));

    while ((curitem = keyStack->pop(keyStack)) != NULL)
    {
        dwresult = ADVAPI32$RegQueryInfoKeyA(
            curitem->hreg, NULL, NULL, NULL,
            &cSubKeys, &cbMaxSubKey, NULL,
            &cValues, &cchMaxValue, &cchMaxData,
            NULL, NULL);

        if (dwresult) { goto nextloop; }

        currentkeyname   = intAlloc(cbMaxSubKey + 1);
        currentvaluename = intAlloc(cchMaxValue + 2);
        currentdata      = intAlloc(cchMaxData  + 2);

        // ── Search values ──────────────────────────────────────────────────
        for (i = 0; i < cValues; i++)
        {
            cchValue = cchMaxValue + 2;
            cchData  = cchMaxData  + 2;

            retCode = ADVAPI32$RegEnumValueA(
                curitem->hreg, i,
                currentvaluename, &cchValue,
                NULL, &regType,
                (LPBYTE)currentdata, &cchData);

            if (retCode != ERROR_SUCCESS) continue;

            BOOL name_match = (search_type == 0 || search_type == 2)
                              && str_icontains(currentvaluename, pattern);

            // Data match only meaningful for string types
            BOOL data_match = FALSE;
            if (search_type == 1 || search_type == 2)
            {
                if (regType == REG_SZ || regType == REG_EXPAND_SZ)
                    data_match = str_icontains(currentdata, pattern);
            }

            if (name_match || data_match)
            {
                if (matches == 0)
                    internal_printf("%-12s  %-20s  %-15s  %s\n",
                        "Match", "Value Name", "Type", "Path");
                
                internal_printf("%-12s  %-20s  %-15s  %s\\%s\n",
                    name_match ? "name" : "data",
                    currentvaluename,
                    (regType <= 11) ? ERegTypes[regType] : "UNKNOWN",
                    gHiveName, curitem->keypath);

                // Print the matched value inline
                Reg_InternalPrintKey(currentdata, currentvaluename, regType, cchData, curitem->hreg);
                matches++;
            }
        }

        // ── Push subkeys onto stack for traversal ─────────────────────────
        for (i = 0; i < cSubKeys; i++)
        {
            cbName  = cbMaxSubKey + 1;
            retCode = ADVAPI32$RegEnumKeyExA(
                curitem->hreg, i,
                currentkeyname, &cbName,
                NULL, NULL, NULL, NULL);

            if (retCode == ERROR_SUCCESS)
            {
                DWORD openResult = ADVAPI32$RegOpenKeyExA(
                    curitem->hreg, currentkeyname, 0, KEY_READ, &curKey);
                if (openResult == ERROR_SUCCESS)
                    keyStack->push(keyStack, init_regkey(
                        curitem->keypath, curitem->dwkeypathsz,
                        currentkeyname, cbName, curKey));
                // non-fatal, continue on access denied
            }
        }

    nextloop:
        if (currentkeyname)   { intFree(currentkeyname);   currentkeyname   = NULL; }
        if (currentvaluename) { intFree(currentvaluename); currentvaluename = NULL; }
        if (currentdata)      { intFree(currentdata);      currentdata      = NULL; }
        cSubKeys = cbMaxSubKey = cValues = cchMaxValue = cchMaxData = 0;

        if (curitem) { free_regkey(curitem); intFree(curitem); curitem = NULL; }
    }

    if (matches == 0)
        internal_printf("No matches found for pattern: %s\n", pattern);
    else
        internal_printf("\nTotal matches: %lu\n", matches);

    dwresult = ERROR_SUCCESS;  // partial access denials are non-fatal

END:
    if (currentkeyname)   intFree(currentkeyname);
    if (currentvaluename) intFree(currentvaluename);
    if (currentdata)      intFree(currentdata);
    if (RemoteKey)        ADVAPI32$RegCloseKey(RemoteKey);
    if (keyStack)         keyStack->free(keyStack);
    return dwresult;
}

#ifdef BOF

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
){
    datap       parser      = {0};
    const char *hostname    = NULL;
    const char *path        = NULL;
    const char *pattern     = NULL;
    HKEY        hive        = (HKEY)0x80000000;
    int         t           = 0;
    int         search_type = 0;
    DWORD       dwresult    = 0;

    init_enums();
    BeaconDataParse(&parser, Buffer, Length);
    hostname    = BeaconDataExtract(&parser, NULL);
    t           = BeaconDataInt(&parser);
    path        = BeaconDataExtract(&parser, NULL);
    pattern     = BeaconDataExtract(&parser, NULL);
    search_type = BeaconDataInt(&parser);

    set_hive_name(t);

    #pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    hive = (HKEY)((DWORD)hive + (DWORD)t);
    #pragma GCC diagnostic pop

    if (*hostname == 0) hostname = NULL;

    if (!*pattern) {
        BeaconPrintf(CALLBACK_ERROR, "Pattern required. Use -s <pattern>");
        return;
    }

    if (!bofstart()) { return; }

    BeaconPrintf(CALLBACK_OUTPUT,
        "Searching: %s\\%s for pattern \"%s\" (mode: %s)",
        gHiveName, path, pattern,
        (search_type == 0) ? "name" : (search_type == 1) ? "data" : "both");

    dwresult = Reg_Find(hostname, hive, path, pattern, search_type);

    if (dwresult)
        BeaconPrintf(CALLBACK_ERROR, "reg_find failed, error: %lu", dwresult);

    printoutput(TRUE);
    free_enums();
}

#endif