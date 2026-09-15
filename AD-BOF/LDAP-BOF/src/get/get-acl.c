#include <windows.h>
#include "beacon.h"
#include "ldap_common.c"
#include "acl_common.c"

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    // Parse arguments: object_identifier, is_dn, search_ou, dc_address, use_ldaps, resolve_names
    char* objectIdentifier = ValidateInput(BeaconDataExtract(&parser, NULL));
    int isObjectDN = BeaconDataInt(&parser);
    char* searchOu = ValidateInput(BeaconDataExtract(&parser, NULL));
    char* dcAddress = ValidateInput(BeaconDataExtract(&parser, NULL));
    int useLdaps = BeaconDataInt(&parser);
    int resolveNames = BeaconDataInt(&parser);
    char* trustee = ValidateInput(BeaconDataExtract(&parser, NULL));

    if (!objectIdentifier || MSVCRT$strlen(objectIdentifier) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object identifier is required");
        return;
    }

    // Initialize LDAP connection
    char* dcHostname = NULL;
    LDAP* ld = InitializeLDAPConnection(dcAddress, useLdaps, &dcHostname);
    if (!ld) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize LDAP connection");
        return;
    }

    // Get default naming context
    char* defaultNC = GetDefaultNamingContext(ld, dcHostname);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get default naming context");
        if (dcHostname) MSVCRT$free(dcHostname);
        CleanupLDAP(ld);
        return;
    }

    // Resolve target DN
    char* targetDN = NULL;
    if (isObjectDN) {
        size_t len = MSVCRT$strlen(objectIdentifier) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) {
            MSVCRT$strcpy(targetDN, objectIdentifier);
        }
    } else {
        char* searchBase = (searchOu && MSVCRT$strlen(searchOu) > 0) ? searchOu : defaultNC;
        targetDN = FindObjectDN(ld, objectIdentifier, searchBase);
        if (!targetDN) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Target '%s' not found", objectIdentifier);
            MSVCRT$free(defaultNC);
            if (dcHostname) MSVCRT$free(dcHostname);
            CleanupLDAP(ld);
            return;
        }
    }

    // Read security descriptor
    BERVAL* sdBerval = ReadSecurityDescriptor(ld, targetDN);
    if (!sdBerval) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read security descriptor");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Read security descriptor (%d bytes)", sdBerval->bv_len);

    // Get object SID for display
    PSID pObjectSid = GetObjectSid(ld, targetDN);
    char* objectSidStr = NULL;
    if (pObjectSid) {
        objectSidStr = SidToString(pObjectSid);
    }

    // Parse security descriptor
    PSD_INFO sdInfo = ParseSecurityDescriptor((BYTE*)sdBerval->bv_val, sdBerval->bv_len);
    if (!sdInfo) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse security descriptor");
        if (objectSidStr) MSVCRT$free(objectSidStr);
        if (pObjectSid) MSVCRT$free(pObjectSid);
        MSVCRT$free(sdBerval->bv_val);
        MSVCRT$free(sdBerval);
        goto cleanup;
    }

    // Resolve SID names if requested
    if (resolveNames) {
        if (sdInfo->OwnerSid) {
            sdInfo->OwnerName = ResolveSidToName(ld, sdInfo->OwnerSid, defaultNC);
        }
        if (sdInfo->GroupSid) {
            sdInfo->GroupName = ResolveSidToName(ld, sdInfo->GroupSid, defaultNC);
        }
        if (sdInfo->DaclAces) {
            for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
                if (sdInfo->DaclAces[i].TrusteeSid) {
                    sdInfo->DaclAces[i].TrusteeName = ResolveSidToName(ld, sdInfo->DaclAces[i].TrusteeSid, defaultNC);
                }
            }
        }
    }

    // Display security descriptor
    if (trustee) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Filtering Output for %s", trustee);
        PrintFilteredSecurityDescriptorInfo(sdInfo, targetDN, objectSidStr, trustee);
    } else PrintSecurityDescriptorInfo(sdInfo, targetDN, objectSidStr);
    // Cleanup
    FreeSecurityDescriptorInfo(sdInfo);
    if (objectSidStr) MSVCRT$free(objectSidStr);
    if (pObjectSid) MSVCRT$free(pObjectSid);
    MSVCRT$free(sdBerval->bv_val);
    MSVCRT$free(sdBerval);

cleanup:
    if (defaultNC) MSVCRT$free(defaultNC);
    if (dcHostname) MSVCRT$free(dcHostname);
    if (targetDN) MSVCRT$free(targetDN);
    CleanupLDAP(ld);
}
