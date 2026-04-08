#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fserror.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
	datap         parser;
	const wchar_t *targetPath = NULL;
	DWORD         dwError     = 0;

	BeaconDataParse(&parser, Buffer, Length);
	targetPath = (const wchar_t *) BeaconDataExtract(&parser, NULL);

	if (targetPath == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "Usage: rmdir <directory>\n");
		return;
	}

	FsNormalizeSlashesW((wchar_t *) targetPath);

	if (!bofstart()) { return; }

	if (!KERNEL32$RemoveDirectoryW(targetPath))
	{
		dwError = KERNEL32$GetLastError();
		char errMsg[256];
		FsErrorMessage(dwError, errMsg, sizeof(errMsg));
		internal_printf("%s\n", errMsg);
	}

	printoutput(TRUE);
}
