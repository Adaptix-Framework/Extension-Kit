#ifndef _FSERROR_H_
#define _FSERROR_H_

#include <windows.h>
#include "bofdefs.h"

// Normalize forward slashes to backslashes in-place.
static inline void FsNormalizeSlashesW(wchar_t *p)
{
    for (; *p != L'\0'; p++)
        if (*p == L'/') *p = L'\\';
}

static inline void FsNormalizeSlashesA(char *p)
{
    for (; *p != '\0'; p++)
        if (*p == '/') *p = '\\';
}

// FsErrorMessage: convert a Windows error code to a human-readable string.
// Uses FormatMessageA to get the system error message for dwError.
// Strips trailing \r\n that FormatMessage appends.
// Falls back to "error %lu" format if FormatMessage fails.
static inline void FsErrorMessage(DWORD dwError, char *buf, int bufSize)
{
	char  *sysBuf = NULL;
	DWORD  ret    = 0;
	int    i      = 0;

	ret = KERNEL32$FormatMessageA(
		0x1300,       // FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS
		NULL,
		dwError,
		0,
		(LPSTR) &sysBuf,
		0,
		NULL
	);

	if (ret > 0 && sysBuf != NULL)
	{
		// Copy into caller buffer, stripping trailing \r\n
		for (i = 0; i < bufSize - 1 && sysBuf[i] != '\0'; i++)
		{
			buf[i] = sysBuf[i];
		}
		buf[i] = '\0';

		// Strip trailing whitespace / \r\n
		while (i > 0 && (buf[i-1] == '\r' || buf[i-1] == '\n' || buf[i-1] == ' '))
		{
			i--;
			buf[i] = '\0';
		}

		KERNEL32$LocalFree((HLOCAL) sysBuf);
	}
	else
	{
		MSVCRT$_snprintf(buf, bufSize, "error %lu", dwError);
	}
}

#endif // _FSERROR_H_
