/*
 * beacon.h - Beacon Object File API definitions
 * For use with Adaptix Framework / Cobalt Strike BOFs
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Data Parser */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

/* Format */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

/* Data Parser API */
DECLSPEC_IMPORT void    BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char*   BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int     BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap* parser);

/* Output API */
#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void    BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char* data, int len);

/* Format API */
DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp* obj, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp* obj, char* data, int len);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp* obj);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp* obj, int val);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp* obj, char* fmt, ...);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp* obj);
DECLSPEC_IMPORT char*   BeaconFormatToString(formatp* obj, int* size);

/* Internal APIs */
DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken();
DECLSPEC_IMPORT BOOL    BeaconIsAdmIn();
DECLSPEC_IMPORT BOOL    toWideChar(char* src, wchar_t* dst, int max);

/* AX BOF APIs */
DECLSPEC_IMPORT void    AxAddScreenshot(char* note, char* data, int len);
DECLSPEC_IMPORT void    AxDownloadMemory(char* filename, char* data, int len);

/* Key-Value Store */
DECLSPEC_IMPORT BOOL    BeaconAddValue(const char* key, void* ptr);
DECLSPEC_IMPORT void*   BeaconGetValue(const char* key);
DECLSPEC_IMPORT BOOL    BeaconRemoveValue(const char* key);

/*
 * Dynamic Function Resolution (DFR)
 * Declare Win32 API functions that will be resolved at runtime.
 * Use: DECLSPEC_IMPORT return_type WINAPI MODULE$FunctionName(args);
 */
#define DECLSPEC_IMPORT __declspec(dllimport)

#endif /* BEACON_H */
