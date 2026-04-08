#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fserror.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
	datap         parser;
	const wchar_t *srcPath = NULL;
	const wchar_t *dstPath = NULL;
	WIN32_FIND_DATAW fd    = {0};
	HANDLE        hFind    = INVALID_HANDLE_VALUE;
	wchar_t       srcDir[MAX_PATH] = {0};
	int           srcLen   = 0;
	int           dstLen   = 0;
	int           nameLen  = 0;
	int           lastSlash = -1;
	int           movedFiles = 0;
	int           movedDirs  = 0;
	int           failed   = 0;
	int           isWildcard = 0;
	DWORD         dwError  = 0;
	DWORD         dwDstAttrs = 0;
	BOOL          dstIsDir = FALSE;
	int           i        = 0;
	int           pos      = 0;

	BeaconDataParse(&parser, Buffer, Length);
	srcPath = (const wchar_t *) BeaconDataExtract(&parser, NULL);
	dstPath = (const wchar_t *) BeaconDataExtract(&parser, NULL);

	if (srcPath == NULL || dstPath == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Usage: move <source> <destination>\n");
		return;
	}

	FsNormalizeSlashesW((wchar_t *) srcPath);
	FsNormalizeSlashesW((wchar_t *) dstPath);

	if (!bofstart()) { return; }

	// Detect wildcard mode for output format
	srcLen = KERNEL32$lstrlenW(srcPath);
	for (i = 0; i < srcLen; i++)
	{
		if (srcPath[i] == L'*' || srcPath[i] == L'?') { isWildcard = 1; break; }
	}

	// Extract source directory prefix: everything up to and including the last backslash
	// e.g. "C:\logs\*.log" -> srcDir = "C:\logs\"
	for (i = srcLen - 1; i >= 0; i--)
	{
		if (srcPath[i] == L'\\') { lastSlash = i; break; }
	}
	if (lastSlash >= 0)
	{
		for (i = 0; i <= lastSlash; i++) { srcDir[i] = srcPath[i]; }
		srcDir[lastSlash + 1] = L'\0';
	}
	// If no backslash found, srcDir remains empty — cFileName is already the full relative path

	// Enumerate matching files via FindFirstFileW unified wildcard loop (D-01, D-03)
	hFind = KERNEL32$FindFirstFileW(srcPath, &fd);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		dwError = KERNEL32$GetLastError();
		if (isWildcard && (dwError == ERROR_FILE_NOT_FOUND || dwError == ERROR_DIRECTORY))
		{
			char *utf8src = Utf16ToUtf8(srcPath);
			internal_printf("No files found: %s\n", utf8src ? utf8src : "");
			if (utf8src) { intFree(utf8src); }
		}
		else
		{
			char errMsg[256];
			FsErrorMessage(dwError, errMsg, sizeof(errMsg));
			internal_printf("%s\n", errMsg);
		}
		printoutput(TRUE);
		return;  // do NOT call FindClose — handle is invalid
	}

	dstLen = KERNEL32$lstrlenW(dstPath);

	// Detect whether destination is an existing directory
	dwDstAttrs = KERNEL32$GetFileAttributesW(dstPath);
	dstIsDir = (dwDstAttrs != INVALID_FILE_ATTRIBUTES) && (dwDstAttrs & FILE_ATTRIBUTE_DIRECTORY);
	// Also treat as directory if path ends with backslash (even if dir doesn't exist yet)
	if (!dstIsDir && dstLen > 0 && dstPath[dstLen - 1] == L'\\') { dstIsDir = TRUE; }

	do {
		// Skip . and .. directory entries; allow real directories through
		if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == L'\0' || (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0'))) { continue; }

		nameLen = KERNEL32$lstrlenW(fd.cFileName);

		// Build full source path: srcDir + fd.cFileName
		{
			int srcDirLen = KERNEL32$lstrlenW(srcDir);
			int srcTotal  = srcDirLen + nameLen + 1;
			wchar_t *srcFile = (wchar_t *) intAlloc(srcTotal * sizeof(wchar_t));

			pos = 0;
			for (i = 0; i < srcDirLen; i++) { srcFile[pos++] = srcDir[i]; }
			for (i = 0; i < nameLen;   i++) { srcFile[pos++] = fd.cFileName[i]; }
			srcFile[pos] = L'\0';

			// Build destination path — conditional on whether destination is a directory
			wchar_t *destFile = NULL;
			if (dstIsDir)
			{
				// Directory destination: append backslash + cFileName
				BOOL needSlash = (dstLen > 0 && dstPath[dstLen - 1] != L'\\');
				int  dstTotal  = dstLen + (needSlash ? 1 : 0) + nameLen + 1;
				destFile = (wchar_t *) intAlloc(dstTotal * sizeof(wchar_t));

				pos = 0;
				for (i = 0; i < dstLen;  i++) { destFile[pos++] = dstPath[i]; }
				if (needSlash)               { destFile[pos++] = L'\\'; }
				for (i = 0; i < nameLen; i++) { destFile[pos++] = fd.cFileName[i]; }
				destFile[pos] = L'\0';
			}
			else
			{
				// File destination: use dstPath directly as target (rename)
				destFile = (wchar_t *) intAlloc((dstLen + 1) * sizeof(wchar_t));
				for (i = 0; i < dstLen; i++) { destFile[i] = dstPath[i]; }
				destFile[dstLen] = L'\0';
			}

			// Move file/dir — dwFlags = 0x3 (MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) (D-07)
			if (!KERNEL32$MoveFileExW(srcFile, destFile, 0x3))
			{
				dwError = KERNEL32$GetLastError();
				char errMsg[256];
				FsErrorMessage(dwError, errMsg, sizeof(errMsg));
				internal_printf("%s\n", errMsg);
				failed++;
			}
			else
			{
				// Per-item success: wildcard prints full source path; single is silent (mirrors copy)
				if (isWildcard)
				{
					char *utf8src = Utf16ToUtf8(srcFile);
					internal_printf("%s\n", utf8src ? utf8src : "(name)");
					if (utf8src) { intFree(utf8src); }
				}
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					movedDirs++;
				else
					movedFiles++;
			}

			intFree(srcFile);
			intFree(destFile);
		}
	} while (KERNEL32$FindNextFileW(hFind, &fd));

	KERNEL32$FindClose(hFind);  // safe — only reached when FindFirstFileW succeeded

	// Summary output — indented to match copy, distinguish files vs dirs
	if (movedFiles > 0)
		internal_printf("        %d file(s) moved.\n", movedFiles);
	if (movedDirs > 0)
		internal_printf("        %d dir(s) moved.\n", movedDirs);
	if (movedFiles == 0 && movedDirs == 0 && failed == 0)
		internal_printf("        0 file(s) moved.\n");
	if (failed > 0)
		internal_printf("        %d file(s) failed.\n", failed);
	printoutput(TRUE);
}
