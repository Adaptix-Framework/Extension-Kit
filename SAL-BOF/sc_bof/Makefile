CC64    = x86_64-w64-mingw32-gcc
CC86    = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded

CFLAGS  = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel -I src

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	@($(CC64) $(CFLAGS) -c src/svcmgr_bof.c -o _bin/svcmgr.x64.o && $(STRIP64) _bin/svcmgr.x64.o) && echo '[+] svcmgr x64' || echo '[!] svcmgr x64 FAILED'
	@($(CC86) $(CFLAGS) -c src/svcmgr_bof.c -o _bin/svcmgr.x86.o && $(STRIP86) _bin/svcmgr.x86.o) && echo '[+] svcmgr x86' || echo '[!] svcmgr x86 FAILED'

clean:
	@(rm -rf _bin)
