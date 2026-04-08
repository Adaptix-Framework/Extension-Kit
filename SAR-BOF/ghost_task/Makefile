CC64    = x86_64-w64-mingw32-gcc
CC86    = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded

CFLAGS  = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel -I src

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	@($(CC64) $(CFLAGS) -c src/entry.c -o _bin/GhostTask.x64.o && $(STRIP64) _bin/GhostTask.x64.o) && echo '[+] GhostTask x64' || echo '[!] GhostTask x64 FAILED'
	@($(CC86) $(CFLAGS) -c src/entry.c -o _bin/GhostTask.x86.o && $(STRIP86) _bin/GhostTask.x86.o) && echo '[+] GhostTask x86' || echo '[!] GhostTask x86 FAILED'

clean:
	@(rm -rf _bin)
