CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) findobjects/FindModule.c -o _bin/findmodule.x64.o && $(STRIP64) _bin/findmodule.x64.o) && echo '[+] findmodule' || echo '[!] findmodule'
	@($(CC64) $(CFLAGS) findobjects/FindProcHandle.c -o _bin/findprochandle.x64.o && $(STRIP64) _bin/findprochandle.x64.o) && echo '[+] findprochandle' || echo '[!] findprochandle'
	@($(CC64) $(CFLAGS) process/psc.c -o _bin/psc.x64.o && $(STRIP64) _bin/psc.x64.o) && echo '[+] psc' || echo '[!] psc'
	@($(CC64) $(CFLAGS) procfreeze/procfreeze.c -o _bin/procfreeze.x64.o && $(STRIP64) _bin/procfreeze.x64.o) && echo '[+] procfreeze' || echo '[!] procfreeze'

clean:
	@(rm -rf _bin)
