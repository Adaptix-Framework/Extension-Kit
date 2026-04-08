#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fserror.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
	datap         parser;
	const wchar_t *filePath    = NULL;
	HANDLE         hFile       = INVALID_HANDLE_VALUE;
	char          *chunk       = NULL;
	DWORD          dwBytesRead = 0;
	DWORD          space       = 0;
	DWORD          toCopy      = 0;

	BeaconDataParse(&parser, Buffer, Length);
	filePath = (const wchar_t *) BeaconDataExtract(&parser, NULL);

	if (filePath == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "No file path specified\n");
		return;
	}

	FsNormalizeSlashesW((wchar_t *) filePath);

	if (!bofstart()) { return; }

	chunk = (char *) intAlloc(4096);
	if (chunk == NULL)
	{
		internal_printf("Memory allocation failed\n");
		printoutput(TRUE);
		return;
	}

	hFile = KERNEL32$CreateFileW(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dwError = KERNEL32$GetLastError();
		char errMsg[256];
		FsErrorMessage(dwError, errMsg, sizeof(errMsg));
		internal_printf("%s\n", errMsg);
		intFree(chunk);
		printoutput(TRUE);
		return;
	}

	// Copy file bytes directly into the output buffer via memcpy — bypasses
	// vsnprintf, which fails on raw file bytes. Uses same BeaconOutput path
	// as del/copy/move via printoutput(TRUE/FALSE).
	//
	// On the first read, strip any BOM so output matches Windows type behavior:
	//   UTF-16 LE BOM: 0xFF 0xFE (2 bytes)
	//   UTF-8 BOM:     0xEF 0xBB 0xBF (3 bytes)
	{
		BOOL firstRead = TRUE;
		while (KERNEL32$ReadFile(hFile, chunk, 4096, &dwBytesRead, NULL)
		       && dwBytesRead > 0)
		{
			char *src   = chunk;
			DWORD bytes = dwBytesRead;

			if (firstRead)
			{
				firstRead = FALSE;
				if (bytes >= 3
				    && (unsigned char)src[0] == 0xEF
				    && (unsigned char)src[1] == 0xBB
				    && (unsigned char)src[2] == 0xBF)
				{
					src += 3; bytes -= 3;  // UTF-8 BOM
				}
				else if (bytes >= 2
				         && (unsigned char)src[0] == 0xFF
				         && (unsigned char)src[1] == 0xFE)
				{
					src += 2; bytes -= 2;  // UTF-16 LE BOM
				}
				if (bytes == 0) { continue; }
			}

			space  = bufsize - currentoutsize;
			toCopy = (bytes < space) ? bytes : space;
			memcpy(output + currentoutsize, src, toCopy);
			currentoutsize += (WORD)toCopy;
			if (currentoutsize >= bufsize)
			{
				printoutput(FALSE);
			}
		}
	}

	KERNEL32$CloseHandle(hFile);
	intFree(chunk);

	if (currentoutsize > 0)
		printoutput(TRUE);
	else
		{ MSVCRT$free(output); output = NULL; }
}
