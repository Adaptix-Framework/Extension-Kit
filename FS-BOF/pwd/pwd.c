#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "fserror.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
	wchar_t buf[MAX_PATH] = {0};
	DWORD   len           = 0;

	if (!bofstart()) { return; }

	len = KERNEL32$GetCurrentDirectoryW(MAX_PATH, buf);

	if (len == 0)
	{
		DWORD dwError = KERNEL32$GetLastError();
		char errMsg[256];
		FsErrorMessage(dwError, errMsg, sizeof(errMsg));
		internal_printf("%s\n", errMsg);
	}
	else
	{
		char *utf8path = Utf16ToUtf8(buf);
		internal_printf("%s\n", utf8path ? utf8path : "(unknown)");
		if (utf8path) { intFree(utf8path); }
	}

	printoutput(TRUE);
}
