#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fserror.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
	datap         parser;
	const wchar_t *dirPath    = NULL;
	wchar_t       *scratch    = NULL;
	int            len        = 0;
	int            i          = 0;
	int            start      = 0;
	BOOL           anyCreated = FALSE;
	BOOL           allExisted = TRUE;
	DWORD          dwError    = 0;

	BeaconDataParse(&parser, Buffer, Length);
	dirPath = (const wchar_t *) BeaconDataExtract(&parser, NULL);

	if (dirPath == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "No directory path specified\n");
		return;
	}

	len = KERNEL32$lstrlenW(dirPath);
	if (len == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "No directory path specified\n");
		return;
	}

	if (!bofstart()) { return; }

	scratch = (wchar_t *) intAlloc((len + 1) * sizeof(wchar_t));
	if (scratch == NULL)
	{
		internal_printf("Memory allocation failed\n");
		printoutput(TRUE);
		return;
	}

	// Copy path to mutable scratch buffer and normalize forward slashes
	for (i = 0; i <= len; i++) { scratch[i] = dirPath[i]; }
	FsNormalizeSlashesW(scratch);

	// Determine start index: skip root prefix so we don't try to create the root
	// UNC path: \\server\share\ — skip past 2nd backslash after pos 2 (4th overall)
	if (len >= 2 && scratch[0] == L'\\' && scratch[1] == L'\\')
	{
		int slashes = 0;
		for (i = 2; i < len; i++)
		{
			if (scratch[i] == L'\\') { slashes++; }
			if (slashes == 2) { start = i + 1; break; }
		}
	}
	else
	{
		// Drive path C:\... — skip past first backslash (drive root is not creatable)
		for (i = 0; i < len; i++)
		{
			if (scratch[i] == L'\\') { start = i + 1; break; }
		}
	}

	// Walk path segments from start, create each one
	for (i = start; i <= len; i++)
	{
		if (scratch[i] == L'\\' || scratch[i] == L'\0')
		{
			if (i == start) { continue; } // skip empty segment

			wchar_t saved = scratch[i];
			scratch[i] = L'\0';

			if (!KERNEL32$CreateDirectoryW(scratch, NULL))
			{
				dwError = KERNEL32$GetLastError();
				if (dwError != 183) // ERROR_ALREADY_EXISTS
				{
					char errMsg[256];
				FsErrorMessage(dwError, errMsg, sizeof(errMsg));
				internal_printf("%s\n", errMsg);
					intFree(scratch);
					printoutput(TRUE);
					return;
				}
				// Segment already exists — continue walking
			}
			else
			{
				anyCreated = TRUE;
				allExisted = FALSE;
			}

			scratch[i] = saved;
		}
	}

	// Print error if all segments already existed
	if (allExisted && !anyCreated)
	{
		char *utf8Path = Utf16ToUtf8(dirPath);
		internal_printf("A subdirectory or file %s already exists.\n", utf8Path ? utf8Path : "(path)");
		if (utf8Path) { intFree(utf8Path); }
	}

	intFree(scratch);
	printoutput(TRUE);
}
