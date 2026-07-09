#ifndef LDAP_COMMON_H
#define LDAP_COMMON_H

#include <windows.h>

// LDAP timeval structure
struct l_timeval {
    LONG tv_sec;
    LONG tv_usec;
};

// LDAP structures and constants
typedef struct ldap {
    struct {
        UINT_PTR sb_sd;
        UCHAR Reserved1[(10*sizeof(ULONG))+1];
        ULONG_PTR sb_naddr;
        UCHAR Reserved2[(6*sizeof(ULONG))];
    } ld_sb;
    PCHAR ld_host;
    ULONG ld_version;
    UCHAR ld_lberoptions;
    ULONG ld_deref;
    ULONG ld_timelimit;
    ULONG ld_sizelimit;
    ULONG ld_errno;
    PCHAR ld_matched;
    PCHAR ld_error;
    ULONG ld_msgid;
    UCHAR Reserved3[(6*sizeof(ULONG))+1];
    ULONG ld_cldaptries;
    ULONG ld_cldaptimeout;
    ULONG ld_refhoplimit;
    ULONG ld_options;
} LDAP, *PLDAP;

typedef struct berval {
    ULONG bv_len;
    PCHAR bv_val;
} LDAP_BERVAL, *PLDAP_BERVAL, BERVAL, *PBERVAL, BerValue;

typedef struct berelement {
  PCHAR opaque;
} BerElement;

typedef struct ldapmodA {
    ULONG mod_op;
    PCHAR mod_type;
    union {
        PCHAR *modv_strvals;
        struct berval **modv_bvals;
    } mod_vals;
} LDAPModA, *PLDAPModA;

typedef struct ldapcontrolA {
    PCHAR ldctl_oid;
    struct berval ldctl_value;
    BOOLEAN ldctl_iscritical;
} LDAPControlA, *PLDAPControlA;

typedef struct ldapmsg {
    ULONG lm_msgid;
    ULONG lm_msgtype;
    PVOID lm_ber;
    struct ldapmsg* lm_chain;
    struct ldapmsg* lm_next;
    ULONG lm_time;
    LDAP* Connection;
    PVOID Request;
    ULONG lm_returncode;
    USHORT lm_referral;
    BOOLEAN lm_chased;
    BOOLEAN lm_eom;
    BOOLEAN ConnectionReferenced;
} LDAPMessage, *PLDAPMessage;

typedef struct l_timeval {
    LONG tv_sec;
    LONG tv_usec;
} LDAP_TIMEVAL;

// LDAP Constants
#define LDAP_PORT 389
#define LDAP_SSL_PORT 636
#define LDAP_VERSION3 3

// LDAP SSL Options
#define LDAP_OPT_SSL 0x0a
#define LDAP_OPT_SSL_OFF 0
#define LDAP_OPT_SSL_ON 1

// LDAP Operation Constants
#define LDAP_MOD_ADD 0x00
#define LDAP_MOD_DELETE 0x01
#define LDAP_MOD_REPLACE 0x02
#define LDAP_MOD_BVALUES 0x80

// LDAP Return Codes
#define LDAP_SUCCESS 0x00
#define LDAP_OPERATIONS_ERROR 0x01
#define LDAP_PROTOCOL_ERROR 0x02
#define LDAP_TIMELIMIT_EXCEEDED 0x03
#define LDAP_ALREADY_EXISTS 0x44
#define LDAP_INSUFFICIENT_RIGHTS 0x32
#define LDAP_INVALID_DN_SYNTAX 0x22
#define LDAP_NO_SUCH_OBJECT 0x20
#define LDAP_SERVER_DOWN 0x51
#define LDAP_INVALID_CREDENTIALS 0x31
#define LDAP_NO_SUCH_ATTRIBUTE 0x10
#define LDAP_CONSTRAINT_VIOLATION 0x13
#define LDAP_TYPE_OR_VALUE_EXISTS 0x14
#define LDAP_ATTRIBUTE_OR_VALUE_EXISTS	LDAP_TYPE_OR_VALUE_EXISTS
#define LDAP_UNWILLING_TO_PERFORM 0x35
#define LDAP_OBJECT_CLASS_VIOLATION 0x41

// LDAP Options
#define LDAP_OPT_PROTOCOL_VERSION 0x11
#define LDAP_OPT_VERSION 0x11
#define LDAP_OPT_SERVER_CERTIFICATE 0x81
#define LDAP_OPT_SIGN 0x95
#define LDAP_OPT_ENCRYPT 0x96

// LDAP SSL Certificate Verification
#define LDAP_OPT_ON ((void*)1)
#define LDAP_OPT_OFF ((void*)0)

// Certificate callback type
typedef BOOLEAN (*VERIFYSERVERCERT)(PLDAP Connection, PCCERT_CONTEXT pServerCert);

// Authentication methods
#define LDAP_AUTH_NEGOTIATE 0x0486

// LDAP search scope values
#define LDAP_SCOPE_BASE 0x00
#define LDAP_SCOPE_ONELEVEL 0x01
#define LDAP_SCOPE_SUBTREE 0x02

// LDAP Server Controls
#define LDAP_SERVER_SD_FLAGS_OID "1.2.840.113556.1.4.801"

// User Account Control (UAC) flags
// Reference: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
#define UF_SCRIPT                           0x00000001  // Logon script executed
#define UF_ACCOUNTDISABLE                   0x00000002  // Account disabled
#define UF_HOMEDIR_REQUIRED                 0x00000008  // Home directory required
#define UF_LOCKOUT                          0x00000010  // Account locked out
#define UF_PASSWD_NOTREQD                   0x00000020  // No password required
#define UF_PASSWD_CANT_CHANGE               0x00000040  // User cannot change password
#define UF_ENCRYPTED_TEXT_PWD_ALLOWED       0x00000080  // Store password using reversible encryption
#define UF_TEMP_DUPLICATE_ACCOUNT           0x00000100  // Local user account
#define UF_NORMAL_ACCOUNT                   0x00000200  // Default account type (user)
#define UF_INTERDOMAIN_TRUST_ACCOUNT        0x00000800  // Interdomain trust account
#define UF_WORKSTATION_TRUST_ACCOUNT        0x00001000  // Workstation trust account (computer)
#define UF_SERVER_TRUST_ACCOUNT             0x00002000  // Domain controller account
#define UF_DONT_EXPIRE_PASSWD               0x00010000  // Password never expires
#define UF_MNS_LOGON_ACCOUNT                0x00020000  // MNS logon account
#define UF_SMARTCARD_REQUIRED               0x00040000  // Smart card required for interactive logon
#define UF_TRUSTED_FOR_DELEGATION           0x00080000  // Account trusted for Kerberos delegation
#define UF_NOT_DELEGATED                    0x00100000  // Account cannot be delegated
#define UF_USE_DES_KEY_ONLY                 0x00200000  // Restrict to DES encryption types
#define UF_DONT_REQ_PREAUTH                 0x00400000  // Kerberos pre-authentication not required (AS-REP roasting!)
#define UF_PASSWORD_EXPIRED                 0x00800000  // Password expired
#define UF_TRUSTED_TO_AUTH_FOR_DELEGATION   0x01000000  // Account enabled for delegation (constrained delegation)
#define UF_NO_AUTH_DATA_REQUIRED            0x02000000  // Account does not require Kerberos PAC
#define UF_PARTIAL_SECRETS_ACCOUNT          0x04000000  // RODC partial secrets account

// Account type flags (should never be cleared)
#define UF_ACCOUNT_TYPE_MASK (UF_NORMAL_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT | UF_SERVER_TRUST_ACCOUNT | UF_INTERDOMAIN_TRUST_ACCOUNT)

// NETAPI32 imports for DC discovery
typedef struct _DOMAIN_CONTROLLER_INFOA {
    LPSTR DomainControllerName;
    LPSTR DomainControllerAddress;
    ULONG DomainControllerAddressType;
    GUID DomainGuid;
    LPSTR DomainName;
    LPSTR DnsForestName;
    ULONG Flags;
    LPSTR DcSiteName;
    LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(
    LPCSTR ComputerName,
    LPCSTR DomainName,
    GUID *DomainGuid,
    LPCSTR SiteName,
    ULONG Flags,
    PDOMAIN_CONTROLLER_INFOA *DomainControllerInfo
);

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

// KERNEL32 imports
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);

// ADVAPI32 imports for security descriptor operations
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    DWORD RequestedStringSDRevision,
    DWORD SecurityInformation,
    LPSTR* StringSecurityDescriptor,
    PULONG StringSecurityDescriptorLen
);

// LDAP API function imports - ANSI versions
DECLSPEC_IMPORT LDAP* WLDAP32$ldap_init(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_set_option(LDAP* ld, int option, const void* invalue);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_get_option(LDAP* ld, int option, void* outvalue);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_bind_s(LDAP* ld, const PCHAR dn, const PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_unbind_s(LDAP* ld);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_add_s(LDAP* ld, const PCHAR dn, LDAPModA** attrs);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_modify_s(LDAP* ld, const PCHAR dn, LDAPModA** mods);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_count_values(PCHAR *vals);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_delete_s(LDAP* ld, const PCHAR dn);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_search_s(LDAP* ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR* attrs, ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_search_ext_s(LDAP* ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR* attrs, ULONG attrsonly, PLDAPControlA* ServerControls, PLDAPControlA* ClientControls, struct l_timeval* timeout, ULONG SizeLimit, LDAPMessage** res);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_create_page_control(LDAP* ld, ULONG PageSize, struct berval* Cookie, UCHAR IsCritical, PLDAPControlA* Control);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_control_freeA(LDAPControlA* Control);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_next_entry(LDAP* ld, LDAPMessage* entry);
DECLSPEC_IMPORT PCHAR* WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, const PCHAR attr);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_value_free(PCHAR* vals);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_first_attribute(LDAP* ld, LDAPMessage* entry, BerElement** ber);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_next_attribute(LDAP* ld, LDAPMessage* entry, BerElement* ber);
DECLSPEC_IMPORT void WLDAP32$ldap_memfree(PCHAR block);
DECLSPEC_IMPORT void WLDAP32$ber_free(BerElement* ber, int freebuf);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_count_entries(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT PCHAR WLDAP32$ldap_err2stringA(ULONG err);
DECLSPEC_IMPORT struct berval** WLDAP32$ldap_get_values_len(LDAP* ld, LDAPMessage* entry, const PCHAR attr);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_value_free_len(struct berval** vals);
DECLSPEC_IMPORT ULONG WLDAP32$ldap_extended_operation_sA(LDAP* ld, PCHAR Oid, struct berval* Data, PLDAPControlA* ServerControls, PLDAPControlA* ClientControls, PCHAR* ReturnedOid, struct berval** ReturnedData);

// Shared function declarations
char* GetDCHostName();
char* BuildDefaultNamingContextFromDC(const char* dcHostname);
LDAP* InitializeLDAPConnection(const char* dcAddress, BOOL useLdaps, char** outDcHostname);
char* GetDefaultNamingContext(LDAP* ld, const char* dcHostname);
char* FindObjectDN(LDAP* ld, const char* samAccountName, const char* searchBase);
void PrintLdapError(const char* context, ULONG ldapError);
BERVAL* EncodePassword(const char* password);
void CleanupLDAP(LDAP* ld);
LDAPControlA* BuildSDFlagsControl(DWORD sdFlags, char* buffer, struct berval* bervalStorage);

// Helper string conversion functions
char* WCharToChar(const wchar_t* wstr);
wchar_t* CharToWChar(const char* str);

#endif // LDAP_COMMON_H
