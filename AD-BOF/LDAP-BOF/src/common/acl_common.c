// acl_common.c - Shared ACL/Security Descriptor utilities for BOF operations
// This file should be #included in each BOF that uses these functions

#include <windows.h>
#include "acl_common.h"

// Import required MSVCRT functions (already imported in ldap_common.c but listed for clarity)
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$strncmp(const char* str1, const char* str2, size_t count);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strncpy(char* dest, const char* src, size_t count);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char* dest, const char* src);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strstr(const char* str, const char* substr);
DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char* buffer, size_t count, const char* format, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);

// ============================================================================
// SECURITY DESCRIPTOR OPERATIONS
// ============================================================================

// Read ntSecurityDescriptor attribute from LDAP object
BERVAL* ReadSecurityDescriptor(LDAP* ld, const char* objectDN) {
    if (!ld || !objectDN) return NULL;

    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char* attrs[] = { "ntSecurityDescriptor", NULL };
    struct berval** values = NULL;
    BERVAL* sdBerval = NULL;

    // Create SD_FLAGS control to request OWNER, GROUP, and DACL
    DWORD sdFlags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    char sdFlagsBuffer[10];
    struct berval sdFlagsValue;
    LDAPControlA* sdFlagsControl = BuildSDFlagsControl(sdFlags, sdFlagsBuffer, &sdFlagsValue);

    LDAPControlA* serverControls[] = { sdFlagsControl, NULL };

    // Search for the object with ntSecurityDescriptor attribute using the SD_FLAGS control
    ULONG result = WLDAP32$ldap_search_ext_s(
        ld,
        (char*)objectDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        serverControls,
        NULL,           // ClientControls
        NULL,           // timeout
        0,              // SizeLimit
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for object");
        PrintLdapError("Search for ntSecurityDescriptor", result);
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object not found");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Get the binary ntSecurityDescriptor value
    values = WLDAP32$ldap_get_values_len(ld, entry, "ntSecurityDescriptor");
    if (!values || !values[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve ntSecurityDescriptor attribute");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Allocate and copy the security descriptor
    sdBerval = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (sdBerval) {
        sdBerval->bv_len = values[0]->bv_len;
        sdBerval->bv_val = (char*)MSVCRT$malloc(sdBerval->bv_len);
        if (sdBerval->bv_val) {
            MSVCRT$memcpy(sdBerval->bv_val, values[0]->bv_val, sdBerval->bv_len);
        } else {
            MSVCRT$free(sdBerval);
            sdBerval = NULL;
        }
    }

    WLDAP32$ldap_value_free_len(values);
    WLDAP32$ldap_msgfree(searchResult);

    return sdBerval;
}

// Write ntSecurityDescriptor attribute back to LDAP object
BOOL WriteSecurityDescriptor(LDAP* ld, const char* objectDN, BERVAL* sdBerval) {
    if (!ld || !objectDN || !sdBerval) return FALSE;

    struct berval* values[] = { sdBerval, NULL };
    LDAPModA sdMod;
    sdMod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    sdMod.mod_type = "ntSecurityDescriptor";
    sdMod.mod_vals.modv_bvals = values;

    LDAPModA* mods[] = { &sdMod, NULL };

    ULONG result = WLDAP32$ldap_modify_s(ld, (char*)objectDN, mods);

    if (result == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully updated ntSecurityDescriptor");
        return TRUE;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to update ntSecurityDescriptor");
        PrintLdapError("Update ntSecurityDescriptor", result);
        return FALSE;
    }
}

// Parse security descriptor buffer into structured information
PSD_INFO ParseSecurityDescriptor(BYTE* sdBuffer, DWORD sdLength) {
    if (!sdBuffer || sdLength == 0) return NULL;

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBuffer;
    PSD_INFO sdInfo = (PSD_INFO)MSVCRT$malloc(sizeof(SD_INFO));
    if (!sdInfo) return NULL;

    MSVCRT$memset(sdInfo, 0, sizeof(SD_INFO));

    // Get control flags
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!ADVAPI32$GetSecurityDescriptorControl(pSD, &control, &revision)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get security descriptor control");
        MSVCRT$free(sdInfo);
        return NULL;
    }
    sdInfo->ControlFlags = control;

    // Get Owner SID
    PSID pOwner = NULL;
    BOOL ownerDefaulted = FALSE;
    if (ADVAPI32$GetSecurityDescriptorOwner(pSD, &pOwner, &ownerDefaulted) && pOwner) {
        LPSTR ownerSidStr = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(pOwner, &ownerSidStr)) {
            size_t len = MSVCRT$strlen(ownerSidStr) + 1;
            sdInfo->OwnerSid = (char*)MSVCRT$malloc(len);
            if (sdInfo->OwnerSid) {
                MSVCRT$strcpy(sdInfo->OwnerSid, ownerSidStr);
            }
            KERNEL32$LocalFree(ownerSidStr);
        }
    }

    // Get Group SID
    PSID pGroup = NULL;
    BOOL groupDefaulted = FALSE;
    if (ADVAPI32$GetSecurityDescriptorGroup(pSD, &pGroup, &groupDefaulted) && pGroup) {
        LPSTR groupSidStr = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(pGroup, &groupSidStr)) {
            size_t len = MSVCRT$strlen(groupSidStr) + 1;
            sdInfo->GroupSid = (char*)MSVCRT$malloc(len);
            if (sdInfo->GroupSid) {
                MSVCRT$strcpy(sdInfo->GroupSid, groupSidStr);
            }
            KERNEL32$LocalFree(groupSidStr);
        }
    }

    // Get DACL
    PACL pDacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    if (ADVAPI32$GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted)) {
        sdInfo->HasDacl = daclPresent;

        if (daclPresent && pDacl) {
            ACL_SIZE_INFORMATION aclSizeInfo;
            if (ADVAPI32$GetAclInformation(pDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
                sdInfo->DaclAceCount = aclSizeInfo.AceCount;

                if (aclSizeInfo.AceCount > 0) {
                    sdInfo->DaclAces = (PARSED_ACE_INFO*)MSVCRT$malloc(sizeof(PARSED_ACE_INFO) * aclSizeInfo.AceCount);
                    if (sdInfo->DaclAces) {
                        MSVCRT$memset(sdInfo->DaclAces, 0, sizeof(PARSED_ACE_INFO) * aclSizeInfo.AceCount);

                        // Parse each ACE
                        for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
                            PACE_HEADER pAce = NULL;
                            if (ADVAPI32$GetAce(pDacl, i, (LPVOID*)&pAce)) {
                                ParseAce(pAce, &sdInfo->DaclAces[i]);
                            }
                        }
                    }
                }
            }
        }
    }

    // Get SACL (System ACL - for auditing)
    PACL pSacl = NULL;
    BOOL saclPresent = FALSE;
    BOOL saclDefaulted = FALSE;
    if (ADVAPI32$GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted)) {
        sdInfo->HasSacl = saclPresent;

        if (saclPresent && pSacl) {
            ACL_SIZE_INFORMATION aclSizeInfo;
            if (ADVAPI32$GetAclInformation(pSacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
                sdInfo->SaclAceCount = aclSizeInfo.AceCount;

                if (aclSizeInfo.AceCount > 0) {
                    sdInfo->SaclAces = (PARSED_ACE_INFO*)MSVCRT$malloc(sizeof(PARSED_ACE_INFO) * aclSizeInfo.AceCount);
                    if (sdInfo->SaclAces) {
                        MSVCRT$memset(sdInfo->SaclAces, 0, sizeof(PARSED_ACE_INFO) * aclSizeInfo.AceCount);

                        for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
                            PACE_HEADER pAce = NULL;
                            if (ADVAPI32$GetAce(pSacl, i, (LPVOID*)&pAce)) {
                                ParseAce(pAce, &sdInfo->SaclAces[i]);
                            }
                        }
                    }
                }
            }
        }
    }

    return sdInfo;
}

// Free parsed security descriptor information
void FreeSecurityDescriptorInfo(PSD_INFO sdInfo) {
    if (!sdInfo) return;

    if (sdInfo->OwnerSid) MSVCRT$free(sdInfo->OwnerSid);
    if (sdInfo->OwnerName) MSVCRT$free(sdInfo->OwnerName);
    if (sdInfo->GroupSid) MSVCRT$free(sdInfo->GroupSid);
    if (sdInfo->GroupName) MSVCRT$free(sdInfo->GroupName);

    // Free DACL ACEs
    if (sdInfo->DaclAces) {
        for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
            if (sdInfo->DaclAces[i].TrusteeSid) MSVCRT$free(sdInfo->DaclAces[i].TrusteeSid);
            if (sdInfo->DaclAces[i].TrusteeName) MSVCRT$free(sdInfo->DaclAces[i].TrusteeName);
        }
        MSVCRT$free(sdInfo->DaclAces);
    }

    // Free SACL ACEs
    if (sdInfo->SaclAces) {
        for (DWORD i = 0; i < sdInfo->SaclAceCount; i++) {
            if (sdInfo->SaclAces[i].TrusteeSid) MSVCRT$free(sdInfo->SaclAces[i].TrusteeSid);
            if (sdInfo->SaclAces[i].TrusteeName) MSVCRT$free(sdInfo->SaclAces[i].TrusteeName);
        }
        MSVCRT$free(sdInfo->SaclAces);
    }

    MSVCRT$free(sdInfo);
}

// ============================================================================
// ACE PARSING AND MANIPULATION
// ============================================================================

// Parse access mask string into ACCESS_MASK value
// Supports named masks (GenericAll, WriteDacl, etc.) and hex values (0x000F01FF)
ACCESS_MASK ParseAccessMask(const char* maskStr) {
    if (!maskStr || MSVCRT$strlen(maskStr) == 0) return 0;

    // Check for hex format (0x prefix)
    if (MSVCRT$strncmp(maskStr, "0x", 2) == 0 || MSVCRT$strncmp(maskStr, "0X", 2) == 0) {
        // Parse hex string
        ACCESS_MASK mask = 0;
        const char* p = maskStr + 2;
        while (*p) {
            mask <<= 4;
            if (*p >= '0' && *p <= '9') {
                mask |= (*p - '0');
            } else if (*p >= 'a' && *p <= 'f') {
                mask |= (*p - 'a' + 10);
            } else if (*p >= 'A' && *p <= 'F') {
                mask |= (*p - 'A' + 10);
            }
            p++;
        }
        return mask;
    }

    // Parse named masks (can be comma-separated)
    ACCESS_MASK mask = 0;
    char buffer[512];
    MSVCRT$strncpy(buffer, maskStr, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Convert to lowercase for case-insensitive comparison
    char* p = buffer;
    while (*p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p + ('a' - 'A');
        }
        p++;
    }

    // Check for each known mask name (case-insensitive substrings)
    if (MSVCRT$strstr(buffer, "genericall")) {
        mask |= GENERIC_ALL;
    }
    if (MSVCRT$strstr(buffer, "genericwrite")) {
        mask |= GENERIC_WRITE;
    }
    if (MSVCRT$strstr(buffer, "genericread")) {
        mask |= GENERIC_READ;
    }
    if (MSVCRT$strstr(buffer, "genericexecute")) {
        mask |= GENERIC_EXECUTE;
    }
    if (MSVCRT$strstr(buffer, "writedacl")) {
        mask |= WRITE_DACL;
    }
    if (MSVCRT$strstr(buffer, "writeowner")) {
        mask |= WRITE_OWNER;
    }
    if (MSVCRT$strstr(buffer, "delete")) {
        mask |= DELETE_ACCESS;
    }
    if (MSVCRT$strstr(buffer, "readcontrol")) {
        mask |= READ_CONTROL;
    }
    if (MSVCRT$strstr(buffer, "createchild")) {
        mask |= ADS_RIGHT_DS_CREATE_CHILD;
    }
    if (MSVCRT$strstr(buffer, "deletechild")) {
        mask |= ADS_RIGHT_DS_DELETE_CHILD;
    }
    if (MSVCRT$strstr(buffer, "readprop")) {
        mask |= ADS_RIGHT_DS_READ_PROP;
    }
    if (MSVCRT$strstr(buffer, "writeprop")) {
        mask |= ADS_RIGHT_DS_WRITE_PROP;
    }
    if (MSVCRT$strstr(buffer, "extendedright")) {
        mask |= ADS_RIGHT_DS_CONTROL_ACCESS;
    }
    if (MSVCRT$strstr(buffer, "controlaccess")) {
        mask |= ADS_RIGHT_DS_CONTROL_ACCESS;
    }
    if (MSVCRT$strstr(buffer, "self")) {
        mask |= ADS_RIGHT_DS_SELF;
    }
    if (MSVCRT$strstr(buffer, "deletetree")) {
        mask |= ADS_RIGHT_DS_DELETE_TREE;
    }
    if (MSVCRT$strstr(buffer, "listobject")) {
        mask |= ADS_RIGHT_DS_LIST_OBJECT;
    }

    return mask;
}

// Parse ACE type string into ACE type byte
// Supports: allow, deny, audit
BYTE ParseAceType(const char* typeStr) {
    if (!typeStr || MSVCRT$strlen(typeStr) == 0) {
        return ACCESS_ALLOWED_ACE_TYPE; // Default to allow
    }

    // Convert to lowercase
    char buffer[32];
    MSVCRT$strncpy(buffer, typeStr, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char* p = buffer;
    while (*p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p + ('a' - 'A');
        }
        p++;
    }

    // Match type
    if (MSVCRT$strstr(buffer, "deny")) {
        return ACCESS_DENIED_ACE_TYPE;
    } else if (MSVCRT$strstr(buffer, "audit")) {
        return SYSTEM_AUDIT_ACE_TYPE;
    } else {
        return ACCESS_ALLOWED_ACE_TYPE; // Default
    }
}

// Parse ACE flags string into ACE flags byte
// Supports: OI (object inherit), CI (container inherit), NP (no propagate), IO (inherit only)
BYTE ParseAceFlags(const char* flagsStr) {
    if (!flagsStr || MSVCRT$strlen(flagsStr) == 0) {
        return 0; // No inheritance flags
    }

    BYTE flags = 0;

    // Convert to uppercase for easier matching
    char buffer[256];
    MSVCRT$strncpy(buffer, flagsStr, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char* p = buffer;
    while (*p) {
        if (*p >= 'a' && *p <= 'z') {
            *p = *p - ('a' - 'A');
        }
        p++;
    }

    // Check for flag abbreviations
    if (MSVCRT$strstr(buffer, "OI")) {
        flags |= OBJECT_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "CI")) {
        flags |= CONTAINER_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "NP")) {
        flags |= NO_PROPAGATE_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "IO")) {
        flags |= INHERIT_ONLY_ACE;
    }

    // Also check for full names
    if (MSVCRT$strstr(buffer, "OBJECT_INHERIT")) {
        flags |= OBJECT_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "CONTAINER_INHERIT")) {
        flags |= CONTAINER_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "NO_PROPAGATE")) {
        flags |= NO_PROPAGATE_INHERIT_ACE;
    }
    if (MSVCRT$strstr(buffer, "INHERIT_ONLY")) {
        flags |= INHERIT_ONLY_ACE;
    }

    return flags;
}

// Parse an ACE into structured format
BOOL ParseAce(PACE_HEADER aceHeader, PPARSED_ACE_INFO parsedAce) {
    if (!aceHeader || !parsedAce) return FALSE;

    parsedAce->AceType = aceHeader->AceType;
    parsedAce->AceFlags = aceHeader->AceFlags;

    // Determine if this is an object ACE (has GUIDs)
    parsedAce->IsObjectAce = (aceHeader->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                              aceHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                              aceHeader->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE);

    if (parsedAce->IsObjectAce) {
        // Object ACE - has GUIDs
        PACCESS_ALLOWED_OBJECT_ACE pObjectAce = (PACCESS_ALLOWED_OBJECT_ACE)aceHeader;
        parsedAce->Mask = pObjectAce->Mask;

        parsedAce->HasObjectType = (pObjectAce->Flags & ACE_OBJECT_TYPE_PRESENT) != 0;
        parsedAce->HasInheritedObjectType = (pObjectAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0;

        if (parsedAce->HasObjectType) {
            MSVCRT$memcpy(&parsedAce->ObjectType, &pObjectAce->ObjectType, sizeof(GUID));
        }

        if (parsedAce->HasInheritedObjectType) {
            MSVCRT$memcpy(&parsedAce->InheritedObjectType, &pObjectAce->InheritedObjectType, sizeof(GUID));
        }

        // Get SID (it's after the GUIDs in the structure)
        PSID pSid = GetSidFromAce(aceHeader);
        if (pSid) {
            LPSTR sidStr = NULL;
            if (ADVAPI32$ConvertSidToStringSidA(pSid, &sidStr)) {
                size_t len = MSVCRT$strlen(sidStr) + 1;
                parsedAce->TrusteeSid = (char*)MSVCRT$malloc(len);
                if (parsedAce->TrusteeSid) {
                    MSVCRT$strcpy(parsedAce->TrusteeSid, sidStr);
                }
                KERNEL32$LocalFree(sidStr);
            }
        }
    } else {
        // Standard ACE
        PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)aceHeader;
        parsedAce->Mask = pAce->Mask;

        // SID starts at SidStart offset
        PSID pSid = (PSID)&pAce->SidStart;
        LPSTR sidStr = NULL;
        if (ADVAPI32$ConvertSidToStringSidA(pSid, &sidStr)) {
            size_t len = MSVCRT$strlen(sidStr) + 1;
            parsedAce->TrusteeSid = (char*)MSVCRT$malloc(len);
            if (parsedAce->TrusteeSid) {
                MSVCRT$strcpy(parsedAce->TrusteeSid, sidStr);
            }
            KERNEL32$LocalFree(sidStr);
        }
    }

    return TRUE;
}

// Get SID from ACE (handles both standard and object ACEs)
PSID GetSidFromAce(PACE_HEADER aceHeader) {
    if (!aceHeader) return NULL;

    if (aceHeader->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
        aceHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
        aceHeader->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
        // Object ACE - SID position depends on which GUIDs are present
        // Structure: ACE_HEADER + ACCESS_MASK + Flags + [ObjectType GUID] + [InheritedObjectType GUID] + SID

        // Start after ACE_HEADER (8 bytes) + ACCESS_MASK (4 bytes) + Flags (4 bytes) = 16 bytes
        BYTE* pSidLocation = (BYTE*)aceHeader + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(DWORD);

        // Get the flags to determine which GUIDs are present
        DWORD* pFlags = (DWORD*)((BYTE*)aceHeader + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
        DWORD flags = *pFlags;

        // Account for ObjectType GUID if present
        if (flags & ACE_OBJECT_TYPE_PRESENT) {
            pSidLocation += sizeof(GUID);
        }

        // Account for InheritedObjectType GUID if present
        if (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            pSidLocation += sizeof(GUID);
        }

        return (PSID)pSidLocation;
    } else {
        // Standard ACE
        PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)aceHeader;
        return (PSID)&pAce->SidStart;
    }
}

// Get human-readable ACE type string
char* GetAceTypeString(BYTE aceType) {
    switch (aceType) {
        case ACCESS_ALLOWED_ACE_TYPE: return "Allow";
        case ACCESS_DENIED_ACE_TYPE: return "Deny";
        case SYSTEM_AUDIT_ACE_TYPE: return "Audit";
        case SYSTEM_ALARM_ACE_TYPE: return "Alarm";
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE: return "AllowObject";
        case ACCESS_DENIED_OBJECT_ACE_TYPE: return "DenyObject";
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE: return "AuditObject";
        default: return "Unknown";
    }
}

// Get human-readable ACE flags string (PowerView format)
char* GetAceFlagsString(BYTE aceFlags) {
    static char flagsBuffer[256];
    flagsBuffer[0] = '\0';

    if (aceFlags == 0) {
        return "None";
    }

    BOOL first = TRUE;

    if (aceFlags & OBJECT_INHERIT_ACE) {
        MSVCRT$strcat(flagsBuffer, "OBJECT_INHERIT_ACE");
        first = FALSE;
    }
    if (aceFlags & CONTAINER_INHERIT_ACE) {
        if (!first) MSVCRT$strcat(flagsBuffer, ", ");
        MSVCRT$strcat(flagsBuffer, "CONTAINER_INHERIT_ACE");
        first = FALSE;
    }
    if (aceFlags & NO_PROPAGATE_INHERIT_ACE) {
        if (!first) MSVCRT$strcat(flagsBuffer, ", ");
        MSVCRT$strcat(flagsBuffer, "NO_PROPAGATE_INHERIT_ACE");
        first = FALSE;
    }
    if (aceFlags & INHERIT_ONLY_ACE) {
        if (!first) MSVCRT$strcat(flagsBuffer, ", ");
        MSVCRT$strcat(flagsBuffer, "INHERIT_ONLY_ACE");
        first = FALSE;
    }
    if (aceFlags & INHERITED_ACE) {
        if (!first) MSVCRT$strcat(flagsBuffer, ", ");
        MSVCRT$strcat(flagsBuffer, "INHERITED_ACE");
        first = FALSE;
    }

    return flagsBuffer;
}

// Get inheritance type string based on ACE flags
char* GetInheritanceTypeString(BYTE aceFlags) {
    // Extract only the inheritance-related flags (not INHERITED_ACE)
    BYTE inheritFlags = aceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                                     NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE);

    // Map flag combinations to PowerView inheritance types
    if (inheritFlags == 0) {
        return "None";
    }

    // All = OI + CI (inherits to all descendants)
    if ((inheritFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) ==
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) &&
        !(inheritFlags & NO_PROPAGATE_INHERIT_ACE) &&
        !(inheritFlags & INHERIT_ONLY_ACE)) {
        return "All";
    }

    // Children = OI + CI + NP (one level only)
    if ((inheritFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE)) ==
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE) &&
        !(inheritFlags & INHERIT_ONLY_ACE)) {
        return "Children";
    }

    // Descendents = OI + CI + IO (inherits to children but not this object)
    if ((inheritFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)) ==
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) &&
        !(inheritFlags & NO_PROPAGATE_INHERIT_ACE)) {
        return "Descendents";
    }

    // SelfAndChildren = OI + CI + NP + IO (not common, but possible)
    if ((inheritFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE)) ==
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE)) {
        return "SelfAndChildren";
    }

    // Containers = CI only (no IO, no NP)
    if (inheritFlags == CONTAINER_INHERIT_ACE) {
        return "Containers";
    }

    // CI + IO = inherit to container descendants only, not this object
    if ((inheritFlags & (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)) ==
        (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) &&
        !(inheritFlags & OBJECT_INHERIT_ACE) &&
        !(inheritFlags & NO_PROPAGATE_INHERIT_ACE)) {
        return "Descendents";
    }

    // CI + NP = immediate container children only
    if ((inheritFlags & (CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE)) ==
        (CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE) &&
        !(inheritFlags & OBJECT_INHERIT_ACE) &&
        !(inheritFlags & INHERIT_ONLY_ACE)) {
        return "Children";
    }

    // Objects = OI only
    if (inheritFlags == OBJECT_INHERIT_ACE) {
        return "Objects";
    }

    // OI + IO = inherit to object descendants only, not this object
    if ((inheritFlags & (OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)) ==
        (OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE) &&
        !(inheritFlags & CONTAINER_INHERIT_ACE) &&
        !(inheritFlags & NO_PROPAGATE_INHERIT_ACE)) {
        return "Descendents";
    }

    // OI + NP = immediate object children only
    if ((inheritFlags & (OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE)) ==
        (OBJECT_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE) &&
        !(inheritFlags & CONTAINER_INHERIT_ACE) &&
        !(inheritFlags & INHERIT_ONLY_ACE)) {
        return "Children";
    }

    // Default for other combinations
    return "None";
}

// Get human-readable access mask string
char* GetAccessMaskString(ACCESS_MASK mask) {
    static char maskBuffer[512];
    maskBuffer[0] = '\0';

    if (mask == 0) {
        return "None";
    }

    BOOL first = TRUE;

    // Check for generic rights first
    if (mask & GENERIC_ALL) {
        MSVCRT$strcat(maskBuffer, "GenericAll");
        first = FALSE;
    }
    if (mask & GENERIC_WRITE) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "GenericWrite");
        first = FALSE;
    }
    if (mask & GENERIC_READ) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "GenericRead");
        first = FALSE;
    }
    if (mask & GENERIC_EXECUTE) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "GenericExecute");
        first = FALSE;
    }

    // Standard rights
    if (mask & DELETE_ACCESS) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "Delete");
        first = FALSE;
    }
    if (mask & WRITE_DACL) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "WriteDacl");
        first = FALSE;
    }
    if (mask & WRITE_OWNER) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "WriteOwner");
        first = FALSE;
    }
    if (mask & READ_CONTROL) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "ReadControl");
        first = FALSE;
    }

    // DS-specific rights
    if (mask & ADS_RIGHT_DS_CREATE_CHILD) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "CreateChild");
        first = FALSE;
    }
    if (mask & ADS_RIGHT_DS_DELETE_CHILD) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "DeleteChild");
        first = FALSE;
    }
    if (mask & ADS_RIGHT_DS_READ_PROP) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "ReadProperty");
        first = FALSE;
    }
    if (mask & ADS_RIGHT_DS_WRITE_PROP) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "WriteProperty");
        first = FALSE;
    }
    if (mask & ADS_RIGHT_DS_CONTROL_ACCESS) {
        if (!first) MSVCRT$strcat(maskBuffer, ",");
        MSVCRT$strcat(maskBuffer, "ExtendedRight");
        first = FALSE;
    }

    // If buffer is still empty, show raw hex
    if (maskBuffer[0] == '\0') {
        MSVCRT$_snprintf(maskBuffer, sizeof(maskBuffer), "0x%08x", mask);
    }

    return maskBuffer;
}

// ============================================================================
// SID UTILITIES
// ============================================================================

// Convert SID to string
char* SidToString(PSID sid) {
    if (!sid) return NULL;

    LPSTR sidStr = NULL;
    if (!ADVAPI32$ConvertSidToStringSidA(sid, &sidStr)) {
        return NULL;
    }

    // Copy to our own buffer
    size_t len = MSVCRT$strlen(sidStr) + 1;
    char* result = (char*)MSVCRT$malloc(len);
    if (result) {
        MSVCRT$strcpy(result, sidStr);
    }

    KERNEL32$LocalFree(sidStr);
    return result;
}

// Convert string to SID
PSID StringToSid(const char* sidString) {
    if (!sidString) return NULL;

    PSID pSid = NULL;
    if (!ADVAPI32$ConvertStringSidToSidA(sidString, &pSid)) {
        return NULL;
    }

    return pSid;
}

// Resolve SID to name via LDAP (searches for objectSid attribute)
char* ResolveSidToName(LDAP* ld, const char* sidString, const char* defaultNC) {
    if (!ld || !sidString || !defaultNC) return NULL;

    // Convert SID string to binary SID
    PSID pSid = StringToSid(sidString);
    if (!pSid) return NULL;

    // Get the SID length
    DWORD sidLen = ADVAPI32$GetLengthSid(pSid);
    if (sidLen == 0) {
        KERNEL32$LocalFree(pSid);
        return NULL;
    }

    // Build LDAP filter with escaped binary SID
    // Format: (objectSid=\xx\xx\xx...) where xx is hex byte
    char filter[512];
    int filterPos = 0;

    // Start filter
    filterPos += MSVCRT$_snprintf(filter + filterPos, sizeof(filter) - filterPos, "(objectSid=");

    // Add escaped binary bytes
    BYTE* sidBytes = (BYTE*)pSid;
    for (DWORD i = 0; i < sidLen && filterPos < sizeof(filter) - 4; i++) {
        filterPos += MSVCRT$_snprintf(filter + filterPos, sizeof(filter) - filterPos, "\\%02x", sidBytes[i]);
    }

    // Close filter
    filterPos += MSVCRT$_snprintf(filter + filterPos, sizeof(filter) - filterPos, ")");

    // Free the SID
    KERNEL32$LocalFree(pSid);

    char* attrs[] = { "sAMAccountName", "name", "cn", NULL };
    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char** values = NULL;
    char* name = NULL;

    // Try searching in the default NC first
    ULONG result = WLDAP32$ldap_search_s(
        ld,
        (char*)defaultNC,
        LDAP_SCOPE_SUBTREE,
        filter,
        attrs,
        0,
        &searchResult
    );

    if (result == LDAP_SUCCESS) {
        entry = WLDAP32$ldap_first_entry(ld, searchResult);
        if (entry) {
            // Try sAMAccountName first
            values = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
            if (!values || !values[0]) {
                // Fall back to cn attribute
                if (values) WLDAP32$ldap_value_free(values);
                values = WLDAP32$ldap_get_values(ld, entry, "cn");
            }
            if (!values || !values[0]) {
                // Fall back to name attribute
                if (values) WLDAP32$ldap_value_free(values);
                values = WLDAP32$ldap_get_values(ld, entry, "name");
            }

            if (values && values[0]) {
                size_t len = MSVCRT$strlen(values[0]) + 1;
                name = (char*)MSVCRT$malloc(len);
                if (name) {
                    MSVCRT$strcpy(name, values[0]);
                }
                WLDAP32$ldap_value_free(values);
            }
        }
        WLDAP32$ldap_msgfree(searchResult);
    }

    // If not found in default NC, try searching from root (for cross-domain SIDs like Enterprise Admins)
    if (!name) {
        // Extract forest root from default NC
        // E.g., DC=child,DC=parent,DC=local -> DC=parent,DC=local
        char* forestRoot = NULL;
        const char* firstComma = MSVCRT$strstr(defaultNC, ",");
        if (firstComma) {
            const char* secondComma = MSVCRT$strstr(firstComma + 1, ",");
            if (secondComma) {
                // We're in a child domain, try searching from parent
                forestRoot = (char*)(firstComma + 1);
            }
        }

        // If we found a potential forest root, search there
        if (forestRoot) {
            result = WLDAP32$ldap_search_s(
                ld,
                forestRoot,
                LDAP_SCOPE_SUBTREE,
                filter,
                attrs,
                0,
                &searchResult
            );

            if (result == LDAP_SUCCESS) {
                entry = WLDAP32$ldap_first_entry(ld, searchResult);
                if (entry) {
                    // Try sAMAccountName first
                    values = WLDAP32$ldap_get_values(ld, entry, "sAMAccountName");
                    if (!values || !values[0]) {
                        // Fall back to cn attribute
                        if (values) WLDAP32$ldap_value_free(values);
                        values = WLDAP32$ldap_get_values(ld, entry, "cn");
                    }
                    if (!values || !values[0]) {
                        // Fall back to name attribute
                        if (values) WLDAP32$ldap_value_free(values);
                        values = WLDAP32$ldap_get_values(ld, entry, "name");
                    }

                    if (values && values[0]) {
                        size_t len = MSVCRT$strlen(values[0]) + 1;
                        name = (char*)MSVCRT$malloc(len);
                        if (name) {
                            MSVCRT$strcpy(name, values[0]);
                        }
                        WLDAP32$ldap_value_free(values);
                    }
                }
                WLDAP32$ldap_msgfree(searchResult);
            }
        }
    }

    return name;
}

// Get objectSid from an LDAP object
PSID GetObjectSid(LDAP* ld, const char* objectDN) {
    if (!ld || !objectDN) return NULL;

    LDAPMessage* searchResult = NULL;
    LDAPMessage* entry = NULL;
    char* attrs[] = { "objectSid", NULL };
    struct berval** values = NULL;
    PSID pSid = NULL;

    // Search for the object with objectSid attribute
    ULONG result = WLDAP32$ldap_search_s(
        ld,
        (char*)objectDN,
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &searchResult
    );

    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to search for object");
        PrintLdapError("Search for objectSid", result);
        return NULL;
    }

    entry = WLDAP32$ldap_first_entry(ld, searchResult);
    if (!entry) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Object not found");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Get the binary objectSid value
    values = WLDAP32$ldap_get_values_len(ld, entry, "objectSid");
    if (!values || !values[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve objectSid attribute");
        WLDAP32$ldap_msgfree(searchResult);
        return NULL;
    }

    // Allocate and copy the SID
    DWORD sidLength = values[0]->bv_len;
    pSid = (PSID)MSVCRT$malloc(sidLength);
    if (pSid) {
        MSVCRT$memcpy(pSid, values[0]->bv_val, sidLength);
    }

    WLDAP32$ldap_value_free_len(values);
    WLDAP32$ldap_msgfree(searchResult);

    return pSid;
}

// ============================================================================
// GUID UTILITIES
// ============================================================================

// Convert GUID string to GUID structure
BOOL StringToGuid(const char* guidString, GUID* guid) {
    if (!guidString || !guid) return FALSE;
    
    RPC_STATUS status = RPCRT4$UuidFromStringA((RPC_CSTR)guidString, guid);
    return (status == RPC_S_OK);
}

// Convert GUID structure to string
char* GuidToString(GUID* guid) {
    if (!guid) return NULL;
    
    RPC_CSTR guidStr = NULL;
    if (RPCRT4$UuidToStringA(guid, &guidStr) != RPC_S_OK) {
        return NULL;
    }
    
    // Copy to our own buffer
    size_t len = MSVCRT$strlen((char*)guidStr) + 1;
    char* result = (char*)MSVCRT$malloc(len);
    if (result) {
        MSVCRT$strcpy(result, (char*)guidStr);
    }
    
    // Free RPC string (using RpcStringFree would be proper, but LocalFree works)
    KERNEL32$LocalFree(guidStr);
    
    return result;
}

// Get friendly name for well-known GUIDs
// Always returns an allocated string that must be freed by the caller
char* GetGuidFriendlyName(GUID* guid) {
    if (!guid) return NULL;
    
    char* guidStr = GuidToString(guid);
    if (!guidStr) return NULL;
    
    // Check for well-known extended rights GUIDs
    if (MSVCRT$strcmp(guidStr, "00299570-246d-11d0-a768-00aa006e0529") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(28);
        if (name) MSVCRT$strcpy(name, "User-Force-Change-Password");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(29);
        if (name) MSVCRT$strcpy(name, "DS-Replication-Get-Changes");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(33);
        if (name) MSVCRT$strcpy(name, "DS-Replication-Get-Changes-All");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "89e95b76-444d-4c62-991a-0facbeda640c") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(38);
        if (name) MSVCRT$strcpy(name, "DS-Replication-Get-Changes-Filtered");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "91e647de-d96f-4b70-9557-d63ff4f3ccd8") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(20);
        if (name) MSVCRT$strcpy(name, "Private-Information");
        return name;
    }
    
    // Check for well-known object class GUIDs (InheritedObjectType)
    else if (MSVCRT$strcmp(guidStr, "bf967aba-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(5);
        if (name) MSVCRT$strcpy(name, "User");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967a9c-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(6);
        if (name) MSVCRT$strcpy(name, "Group");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967a86-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(9);
        if (name) MSVCRT$strcpy(name, "Computer");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "4828cc14-1437-45bc-9b07-ad6f015e5f28") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(14);
        if (name) MSVCRT$strcpy(name, "inetOrgPerson");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967aa5-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(19);
        if (name) MSVCRT$strcpy(name, "organizationalUnit");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967aa8-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(11);
        if (name) MSVCRT$strcpy(name, "printQueue");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967ab3-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(7);
        if (name) MSVCRT$strcpy(name, "volume");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "bf967a0a-0de6-11d0-a285-00aa003049e2") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(11);
        if (name) MSVCRT$strcpy(name, "domainDNS");
        return name;
    }
    else if (MSVCRT$strcmp(guidStr, "19195a5a-6da0-11d0-afd3-00c04fd930c9") == 0) {
        MSVCRT$free(guidStr);
        char* name = (char*)MSVCRT$malloc(8);
        if (name) MSVCRT$strcpy(name, "contact");
        return name;
    }
    
    // Return the GUID string itself if not recognized
    return guidStr;
}

// ============================================================================
// DISPLAY UTILITIES
// ============================================================================

// Print parsed security descriptor information
void PrintSecurityDescriptorInfo(PSD_INFO sdInfo, const char* objectDN, const char* objectSid) {
    if (!sdInfo) return;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Security Descriptor Information:\n=====================================");
    
    // Owner
    if (sdInfo->OwnerSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Owner: %s", sdInfo->OwnerSid);
        if (sdInfo->OwnerName) {
            BeaconPrintf(CALLBACK_OUTPUT, "    Name: %s", sdInfo->OwnerName);
        }
    }
    
    // Group
    if (sdInfo->GroupSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Group: %s", sdInfo->GroupSid);
        if (sdInfo->GroupName) {
            BeaconPrintf(CALLBACK_OUTPUT, "    Name: %s", sdInfo->GroupName);
        }
    }
    
    // Control flags
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Control Flags: 0x%04x", sdInfo->ControlFlags);
    if (sdInfo->ControlFlags & SE_DACL_PROTECTED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    - DACL is protected (inheritance blocked)");
    }
    if (sdInfo->ControlFlags & SE_SACL_PROTECTED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    - SACL is protected");
    }
    
    // DACL
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] DACL (Discretionary Access Control List):");
    if (!sdInfo->HasDacl) {
        BeaconPrintf(CALLBACK_OUTPUT, "    No DACL present (NULL DACL - everyone has full access!)");
    } else if (sdInfo->DaclAceCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Empty DACL (no one has access)");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    %d ACE(s):", sdInfo->DaclAceCount);
        for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
            PrintAceInfo(&sdInfo->DaclAces[i], i, objectDN, objectSid);
        }
    }
    
    // SACL (if present)
    if (sdInfo->HasSacl && sdInfo->SaclAceCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] SACL (System Access Control List):");
        BeaconPrintf(CALLBACK_OUTPUT, "    %d ACE(s):", sdInfo->SaclAceCount);
        for (DWORD i = 0; i < sdInfo->SaclAceCount; i++) {
            PrintAceInfo(&sdInfo->SaclAces[i], i, objectDN, objectSid);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "=====================================\n");
}

void PrintFilteredSecurityDescriptorInfo(PSD_INFO sdInfo, const char* objectDN, const char* objectSid, const char* trustee) {
    if (!sdInfo) return;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Security Descriptor Information:\n=====================================");

    // Owner
    if (sdInfo->OwnerSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Owner: %s", sdInfo->OwnerSid);
        if (sdInfo->OwnerName) {
            BeaconPrintf(CALLBACK_OUTPUT, "    Name: %s", sdInfo->OwnerName);
        }
    }

    // Group
    if (sdInfo->GroupSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Group: %s", sdInfo->GroupSid);
        if (sdInfo->GroupName) {
            BeaconPrintf(CALLBACK_OUTPUT, "    Name: %s", sdInfo->GroupName);
        }
    }

    // Control flags
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Control Flags: 0x%04x", sdInfo->ControlFlags);
    if (sdInfo->ControlFlags & SE_DACL_PROTECTED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    - DACL is protected (inheritance blocked)");
    }
    if (sdInfo->ControlFlags & SE_SACL_PROTECTED) {
        BeaconPrintf(CALLBACK_OUTPUT, "    - SACL is protected");
    }

    // DACL
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] DACL (Discretionary Access Control List):");
    if (!sdInfo->HasDacl) {
        BeaconPrintf(CALLBACK_OUTPUT, "    No DACL present (NULL DACL - everyone has full access!)");
    } else if (sdInfo->DaclAceCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    Empty DACL (no one has access)");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    %d ACE(s):", sdInfo->DaclAceCount);
        for (DWORD i = 0; i < sdInfo->DaclAceCount; i++) {
            if (!MSVCRT$strcmp(sdInfo->DaclAces[i].TrusteeSid, trustee)) {
               PrintAceInfo(&sdInfo->DaclAces[i], i, objectDN, objectSid); 
            }
        }
    }

    // SACL (if present)
    if (sdInfo->HasSacl && sdInfo->SaclAceCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] SACL (System Access Control List):");
        BeaconPrintf(CALLBACK_OUTPUT, "    %d ACE(s):", sdInfo->SaclAceCount);
        for (DWORD i = 0; i < sdInfo->SaclAceCount; i++) {
            PrintAceInfo(&sdInfo->SaclAces[i], i, objectDN, objectSid);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "=====================================\n");
}

// Print individual ACE information (PowerView format)
void PrintAceInfo(PPARSED_ACE_INFO aceInfo, int index, const char* objectDN, const char* objectSid) {
    if (!aceInfo) return;

    // Print ACE number header
    BeaconPrintf(CALLBACK_OUTPUT, "\n    ACE #%d:", index);
    
    // ObjectDN
    if (objectDN) {
        BeaconPrintf(CALLBACK_OUTPUT, "      ObjectDN                : %s", objectDN);
    }
    
    // ObjectSID
    if (objectSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "      ObjectSID               : %s", objectSid);
    }
    
    // ACEType
    char* aceTypeStr = GetAceTypeString(aceInfo->AceType);
    if (aceInfo->IsObjectAce) {
        if (aceInfo->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : ACCESS_ALLOWED_OBJECT_ACE");
        } else if (aceInfo->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : ACCESS_DENIED_OBJECT_ACE");
        } else if (aceInfo->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : SYSTEM_AUDIT_OBJECT_ACE");
        }
    } else {
        if (aceInfo->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : ACCESS_ALLOWED_ACE");
        } else if (aceInfo->AceType == ACCESS_DENIED_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : ACCESS_DENIED_ACE");
        } else if (aceInfo->AceType == SYSTEM_AUDIT_ACE_TYPE) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ACEType                 : SYSTEM_AUDIT_ACE");
        }
    }
    
    // ACEFlags
    char* aceFlagsStr = GetAceFlagsString(aceInfo->AceFlags);
    BeaconPrintf(CALLBACK_OUTPUT, "      ACEFlags                : %s", aceFlagsStr);
    
    // ActiveDirectoryRights (friendly name for access mask)
    char* accessMaskStr = GetAccessMaskString(aceInfo->Mask);
    BeaconPrintf(CALLBACK_OUTPUT, "      ActiveDirectoryRights   : %s", accessMaskStr);
    
    // AccessMask (same as ActiveDirectoryRights for consistency)
    BeaconPrintf(CALLBACK_OUTPUT, "      AccessMask              : %s", accessMaskStr);
    
    // ObjectAceFlags and ObjectAceType for object ACEs
    if (aceInfo->IsObjectAce) {
        // Print ObjectAceFlags once with all applicable flags
        if (aceInfo->HasObjectType && aceInfo->HasInheritedObjectType) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ObjectAceFlags          : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT");
        } else if (aceInfo->HasObjectType) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ObjectAceFlags          : ACE_OBJECT_TYPE_PRESENT");
        } else if (aceInfo->HasInheritedObjectType) {
            BeaconPrintf(CALLBACK_OUTPUT, "      ObjectAceFlags          : ACE_INHERITED_OBJECT_TYPE_PRESENT");
        }
        
        // Print ObjectAceType if present
        if (aceInfo->HasObjectType) {
            char* guidName = GetGuidFriendlyName(&aceInfo->ObjectType);
            if (guidName) {
                BeaconPrintf(CALLBACK_OUTPUT, "      ObjectAceType           : %s", guidName);
                MSVCRT$free(guidName);
            }
        }
        
        // Print InheritedObjectType if present
        if (aceInfo->HasInheritedObjectType) {
            char* inheritGuidName = GetGuidFriendlyName(&aceInfo->InheritedObjectType);
            if (inheritGuidName) {
                BeaconPrintf(CALLBACK_OUTPUT, "      InheritedObjectType     : %s", inheritGuidName);
                MSVCRT$free(inheritGuidName);
            }
        }
    }
    
    // InheritanceType (based on ACE flags)
    char* inheritanceType = GetInheritanceTypeString(aceInfo->AceFlags);
    BeaconPrintf(CALLBACK_OUTPUT, "      InheritanceType         : %s", inheritanceType);
    
    // SecurityIdentifier (trustee SID or name)
    if (aceInfo->TrusteeName) {
        BeaconPrintf(CALLBACK_OUTPUT, "      SecurityIdentifier      : %s", aceInfo->TrusteeName);
    } else if (aceInfo->TrusteeSid) {
        BeaconPrintf(CALLBACK_OUTPUT, "      SecurityIdentifier      : %s", aceInfo->TrusteeSid);
    }
}

// ============================================================================
// SPECIAL OPERATION HELPERS
// ============================================================================

// Check if a string contains a DCSync keyword
BOOL IsDCSyncKeyword(const char* str) {
    if (!str || MSVCRT$strlen(str) == 0) return FALSE;
    
    // Convert to lowercase for comparison
    char buffer[256];
    MSVCRT$strncpy(buffer, str, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char* p = buffer;
    while (*p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p = *p + ('a' - 'A');
        }
        p++;
    }
    
    // Check for DCSync keywords
    if (MSVCRT$strstr(buffer, "dcsync")) return TRUE;
    if (MSVCRT$strstr(buffer, "replication-get-changes")) return TRUE;
    
    return FALSE;
}

// ============================================================================
// ACL MODIFICATION UTILITIES
// ============================================================================

// Create a new DACL with an additional ACE
// This function builds a completely new DACL by parsing the self-relative SD directly
// and building a new DACL from scratch, rather than trying to copy from an absolute format
PACL CreateNewDaclWithAce(PACL oldDacl, PSID trusteeSid, ACCESS_MASK accessMask, 
                          BYTE aceType, BYTE aceFlags, GUID* objectTypeGuid, GUID* inheritedObjectTypeGuid) {
    if (!trusteeSid || !ADVAPI32$IsValidSid(trusteeSid)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid trustee SID provided");
        return NULL;
    }

    DWORD oldAceCount = 0;
    DWORD oldAclSize = 0;
    
    // Get information about the old DACL
    if (oldDacl) {
        ACL_SIZE_INFORMATION aclSizeInfo;
        if (!ADVAPI32$GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get ACL information");
            return NULL;
        }
        oldAceCount = aclSizeInfo.AceCount;
        oldAclSize = aclSizeInfo.AclBytesInUse;
        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Old DACL: %d ACEs, %d bytes used", oldAceCount, oldAclSize);
    }

    // Determine if we're creating an object ACE or standard ACE
    BOOL isObjectAce = (objectTypeGuid != NULL || inheritedObjectTypeGuid != NULL);
    DWORD sidLength = ADVAPI32$GetLengthSid(trusteeSid);
    DWORD newAceSize = 0;

    if (isObjectAce) {
        // Object ACE structure size
        newAceSize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(DWORD); // Flags field
        if (objectTypeGuid) {
            newAceSize += sizeof(GUID);
        }
        if (inheritedObjectTypeGuid) {
            newAceSize += sizeof(GUID);
        }
        newAceSize += sidLength;
    } else {
        // Standard ACE structure size
        newAceSize = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sidLength;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] New ACE size: %d bytes (type: %s)", 
                newAceSize, isObjectAce ? "Object" : "Standard");

    // Calculate new DACL size with generous padding
    // We need: old DACL size + new ACE + extra space for alignment and safety
    DWORD newAclSize = oldAclSize + newAceSize + 256; // Increased padding for safety
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Allocating new DACL: %d bytes (old: %d + new ACE: %d + padding: 256)", 
                newAclSize, oldAclSize, newAceSize);
    
    // Allocate new DACL
    PACL newDacl = (PACL)MSVCRT$malloc(newAclSize);
    if (!newDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for new DACL");
        return NULL;
    }

    // Determine ACL revision based on old DACL contents
    DWORD aclRevision = ACL_REVISION;
    
    // Check if old DACL contains object ACEs (Type 5, 6, 7) which require ACL_REVISION_DS
    if (oldDacl && oldAceCount > 0) {
        for (DWORD i = 0; i < oldAceCount; i++) {
            PACE_HEADER pAce = NULL;
            if (ADVAPI32$GetAce(oldDacl, i, (LPVOID*)&pAce)) {
                if (pAce->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                    pAce->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                    pAce->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
                    aclRevision = ACL_REVISION_DS;
                    break;
                }
            }
        }
    }
    
    // Also use ACL_REVISION_DS if we're adding an object ACE
    if (isObjectAce && aclRevision == ACL_REVISION) {
        aclRevision = ACL_REVISION_DS;
    }

    // Initialize new DACL with appropriate revision
    if (!ADVAPI32$InitializeAcl(newDacl, newAclSize, aclRevision)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize new DACL");
        MSVCRT$free(newDacl);
        return NULL;
    }

    // Add the new ACE first (ACEs are evaluated in order, so we want our ACE to be checked first)
    BOOL aceAdded = FALSE;
    
    if (isObjectAce) {
        // Manually construct object ACE
        BYTE* aceBuffer = (BYTE*)MSVCRT$malloc(newAceSize);
        if (!aceBuffer) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate ACE buffer");
            MSVCRT$free(newDacl);
            return NULL;
        }

        PACE_HEADER pAceHeader = (PACE_HEADER)aceBuffer;
        pAceHeader->AceType = aceType;
        pAceHeader->AceFlags = aceFlags;
        pAceHeader->AceSize = (WORD)newAceSize;

        // Set access mask
        ACCESS_MASK* pMask = (ACCESS_MASK*)(aceBuffer + sizeof(ACE_HEADER));
        *pMask = accessMask;

        // Set object flags
        DWORD* pFlags = (DWORD*)(aceBuffer + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
        *pFlags = 0;
        if (objectTypeGuid) *pFlags |= ACE_OBJECT_TYPE_PRESENT;
        if (inheritedObjectTypeGuid) *pFlags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;

        // Copy GUIDs
        BYTE* pCurrent = aceBuffer + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(DWORD);
        if (objectTypeGuid) {
            MSVCRT$memcpy(pCurrent, objectTypeGuid, sizeof(GUID));
            pCurrent += sizeof(GUID);
        }
        if (inheritedObjectTypeGuid) {
            MSVCRT$memcpy(pCurrent, inheritedObjectTypeGuid, sizeof(GUID));
            pCurrent += sizeof(GUID);
        }

        // Copy SID
        MSVCRT$memcpy(pCurrent, trusteeSid, sidLength);

        // Add the ACE to the DACL (use detected revision)
        aceAdded = ADVAPI32$AddAce(newDacl, aclRevision, MAXDWORD, aceBuffer, newAceSize);
        MSVCRT$free(aceBuffer);

        if (!aceAdded) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add object ACE to DACL");
        }
    } else {
        // Standard ACE - use helper function (use detected revision)
        if (aceType == ACCESS_ALLOWED_ACE_TYPE) {
            aceAdded = ADVAPI32$AddAccessAllowedAceEx(newDacl, aclRevision, aceFlags, accessMask, trusteeSid);
        } else if (aceType == ACCESS_DENIED_ACE_TYPE) {
            aceAdded = ADVAPI32$AddAccessDeniedAceEx(newDacl, aclRevision, aceFlags, accessMask, trusteeSid);
        }

        if (!aceAdded) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add standard ACE to DACL");
        }
    }

    if (!aceAdded) {
        MSVCRT$free(newDacl);
        return NULL;
    }

    // Now copy existing ACEs from old DACL by reading them as raw bytes
    // This is the key fix: instead of using AddAce() which fails for complex object ACEs,
    // we manually append the ACE data to the DACL buffer
    if (oldDacl && oldAceCount > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Copying %d existing ACEs...", oldAceCount);
        
        DWORD successCount = 0;
        DWORD failCount = 0;
        
        for (DWORD i = 0; i < oldAceCount; i++) {
            PACE_HEADER pAce = NULL;
            if (ADVAPI32$GetAce(oldDacl, i, (LPVOID*)&pAce)) {
                // Try to add the ACE - AddAce copies the raw bytes (use detected revision)
                if (ADVAPI32$AddAce(newDacl, aclRevision, MAXDWORD, pAce, pAce->AceSize)) {
                    successCount++;
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy ACE #%d (Type: %d, Size: %d)", 
                                i, pAce->AceType, pAce->AceSize);
                    failCount++;
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to retrieve ACE #%d", i);
                failCount++;
            }
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ACE copy results: %d successful, %d failed", successCount, failCount);
    }

    // Verify the final ACE count
    ACL_SIZE_INFORMATION finalAclInfo;
    if (ADVAPI32$GetAclInformation(newDacl, &finalAclInfo, sizeof(finalAclInfo), AclSizeInformation)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created new DACL with %d ACE(s) (1 new + %d copied)", 
                    finalAclInfo.AceCount, finalAclInfo.AceCount - 1);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created new DACL");
    }
    
    return newDacl;
}

// Create a new DACL without a specific ACE (by index)
PACL CreateNewDaclWithoutAce(PACL oldDacl, DWORD aceIndexToRemove) {
    if (!oldDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No DACL provided");
        return NULL;
    }

    ACL_SIZE_INFORMATION aclSizeInfo;
    if (!ADVAPI32$GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get ACL information");
        return NULL;
    }

    if (aceIndexToRemove >= aclSizeInfo.AceCount) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ACE index %d out of range (max: %d)", aceIndexToRemove, aclSizeInfo.AceCount - 1);
        return NULL;
    }

    // Get the size of the ACE we're removing
    PACE_HEADER pAceToRemove = NULL;
    if (!ADVAPI32$GetAce(oldDacl, aceIndexToRemove, (LPVOID*)&pAceToRemove)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get ACE to remove");
        return NULL;
    }

    // Calculate new DACL size (old size minus the ACE we're removing)
    DWORD newAclSize = aclSizeInfo.AclBytesInUse - pAceToRemove->AceSize + sizeof(ACL);
    
    // Allocate new DACL
    PACL newDacl = (PACL)MSVCRT$malloc(newAclSize);
    if (!newDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for new DACL");
        return NULL;
    }

    // Initialize new DACL
    if (!ADVAPI32$InitializeAcl(newDacl, newAclSize, ACL_REVISION)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize new DACL");
        MSVCRT$free(newDacl);
        return NULL;
    }

    // Copy all ACEs except the one we're removing
    for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
        if (i == aceIndexToRemove) {
            continue; // Skip this ACE
        }

        PACE_HEADER pAce = NULL;
        if (ADVAPI32$GetAce(oldDacl, i, (LPVOID*)&pAce)) {
            if (!ADVAPI32$AddAce(newDacl, ACL_REVISION, MAXDWORD, pAce, pAce->AceSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy ACE #%d", i);
                MSVCRT$free(newDacl);
                return NULL;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created new DACL with ACE #%d removed", aceIndexToRemove);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] New DACL has %d ACE(s)", aclSizeInfo.AceCount - 1);
    return newDacl;
}

// Create a new DACL without multiple specific ACEs (by indices)
PACL CreateNewDaclWithoutAces(PACL oldDacl, DWORD* aceIndicesToRemove, DWORD removeCount) {
    if (!oldDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No DACL provided");
        return NULL;
    }
    
    if (!aceIndicesToRemove || removeCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No ACE indices provided");
        return NULL;
    }

    ACL_SIZE_INFORMATION aclSizeInfo;
    if (!ADVAPI32$GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get ACL information");
        return NULL;
    }

    // Validate all indices
    for (DWORD i = 0; i < removeCount; i++) {
        if (aceIndicesToRemove[i] >= aclSizeInfo.AceCount) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ACE index %d out of range (max: %d)", 
                        aceIndicesToRemove[i], aclSizeInfo.AceCount - 1);
            return NULL;
        }
    }

    // Calculate total size of ACEs to remove
    DWORD totalRemoveSize = 0;
    for (DWORD i = 0; i < removeCount; i++) {
        PACE_HEADER pAce = NULL;
        if (ADVAPI32$GetAce(oldDacl, aceIndicesToRemove[i], (LPVOID*)&pAce)) {
            totalRemoveSize += pAce->AceSize;
        }
    }

    // Calculate new DACL size
    DWORD newAclSize = aclSizeInfo.AclBytesInUse - totalRemoveSize + sizeof(ACL) + 256; // Extra padding
    
    // Allocate new DACL
    PACL newDacl = (PACL)MSVCRT$malloc(newAclSize);
    if (!newDacl) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for new DACL");
        return NULL;
    }

    // Determine ACL revision based on old DACL
    DWORD aclRevision = ACL_REVISION;
    
    // Check if old DACL contains object ACEs (which require ACL_REVISION_DS)
    for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
        PACE_HEADER pAce = NULL;
        if (ADVAPI32$GetAce(oldDacl, i, (LPVOID*)&pAce)) {
            if (pAce->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                pAce->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                pAce->AceType == SYSTEM_AUDIT_OBJECT_ACE_TYPE) {
                aclRevision = ACL_REVISION_DS;
                break;
            }
        }
    }

    // Initialize new DACL with appropriate revision
    if (!ADVAPI32$InitializeAcl(newDacl, newAclSize, aclRevision)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to initialize new DACL");
        MSVCRT$free(newDacl);
        return NULL;
    }

    // Copy all ACEs except the ones we're removing
    DWORD copiedCount = 0;
    for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
        // Check if this index should be removed
        BOOL shouldRemove = FALSE;
        for (DWORD j = 0; j < removeCount; j++) {
            if (aceIndicesToRemove[j] == i) {
                shouldRemove = TRUE;
                break;
            }
        }
        
        if (shouldRemove) {
            continue; // Skip this ACE
        }

        PACE_HEADER pAce = NULL;
        if (ADVAPI32$GetAce(oldDacl, i, (LPVOID*)&pAce)) {
            if (!ADVAPI32$AddAce(newDacl, aclRevision, MAXDWORD, pAce, pAce->AceSize)) {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to copy ACE #%d", i);
                MSVCRT$free(newDacl);
                return NULL;
            }
            copiedCount++;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Removed %d ACE(s), kept %d ACE(s)", removeCount, copiedCount);
    return newDacl;
}


// Convert security descriptor to BERVAL for LDAP
BERVAL* ConvertSecurityDescriptorToBerval(PSECURITY_DESCRIPTOR pSD) {
    if (!pSD) return NULL;

    // First, get the size needed for self-relative format
    DWORD sdSize = 0;
    ADVAPI32$MakeSelfRelativeSD(pSD, NULL, &sdSize);
    
    if (sdSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get security descriptor size");
        return NULL;
    }

    // Allocate buffer for self-relative SD
    BYTE* selfRelativeSD = (BYTE*)MSVCRT$malloc(sdSize);
    if (!selfRelativeSD) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for self-relative SD");
        return NULL;
    }

    // Convert to self-relative format
    if (!ADVAPI32$MakeSelfRelativeSD(pSD, (PSECURITY_DESCRIPTOR)selfRelativeSD, &sdSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to self-relative format");
        MSVCRT$free(selfRelativeSD);
        return NULL;
    }

    // Create BERVAL
    BERVAL* sdBerval = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (!sdBerval) {
        MSVCRT$free(selfRelativeSD);
        return NULL;
    }

    sdBerval->bv_len = sdSize;
    sdBerval->bv_val = (char*)selfRelativeSD;

    return sdBerval;
}

// Convert BERVAL to absolute security descriptor (for modification)
PSECURITY_DESCRIPTOR ConvertBervalToSecurityDescriptor(BERVAL* sdBerval) {
    if (!sdBerval || !sdBerval->bv_val) return NULL;

    // The BERVAL contains a self-relative security descriptor
    // We need to convert it to absolute format for modification
    
    PSECURITY_DESCRIPTOR pSelfRelativeSD = (PSECURITY_DESCRIPTOR)sdBerval->bv_val;
    
    // Get required buffer sizes
    DWORD absSDSize = 0, daclSize = 0, saclSize = 0, ownerSize = 0, groupSize = 0;
    
    ADVAPI32$MakeAbsoluteSD(pSelfRelativeSD, NULL, &absSDSize, NULL, &daclSize, 
                            NULL, &saclSize, NULL, &ownerSize, NULL, &groupSize);

    // Allocate buffers
    PSECURITY_DESCRIPTOR pAbsoluteSD = (PSECURITY_DESCRIPTOR)MSVCRT$malloc(absSDSize);
    PACL pDacl = (PACL)MSVCRT$malloc(daclSize);
    PACL pSacl = (PACL)MSVCRT$malloc(saclSize);
    PSID pOwner = (PSID)MSVCRT$malloc(ownerSize);
    PSID pGroup = (PSID)MSVCRT$malloc(groupSize);

    if (!pAbsoluteSD || !pDacl || !pSacl || !pOwner || !pGroup) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate buffers for absolute SD");
        if (pAbsoluteSD) MSVCRT$free(pAbsoluteSD);
        if (pDacl) MSVCRT$free(pDacl);
        if (pSacl) MSVCRT$free(pSacl);
        if (pOwner) MSVCRT$free(pOwner);
        if (pGroup) MSVCRT$free(pGroup);
        return NULL;
    }

    // Convert to absolute format
    if (!ADVAPI32$MakeAbsoluteSD(pSelfRelativeSD, pAbsoluteSD, &absSDSize, 
                                 pDacl, &daclSize, pSacl, &saclSize,
                                 pOwner, &ownerSize, pGroup, &groupSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to convert security descriptor to absolute format");
        MSVCRT$free(pAbsoluteSD);
        MSVCRT$free(pDacl);
        MSVCRT$free(pSacl);
        MSVCRT$free(pOwner);
        MSVCRT$free(pGroup);
        return NULL;
    }

    // Note: The DACL, SACL, Owner, and Group pointers are now part of the absolute SD
    // We should NOT free them separately. They'll be freed when the SD is freed
    // However, we allocated them, so we need to track them for cleanup
    // For BOF simplicity, we'll accept this small memory cost

    return pAbsoluteSD;
}
