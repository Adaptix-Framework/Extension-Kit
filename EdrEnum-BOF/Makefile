CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded

CFLAGS = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel -I src

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit builds
	@($(CC64) $(CFLAGS) -c src/edr_enum_bof.c   -o _bin/edrenum.x64.o        && $(STRIP64) _bin/edrenum.x64.o)        && echo '[+] edr_enum'         || echo '[!] edr_enum'
	@($(CC64) $(CFLAGS) -c src/edr_remote_bof.c -o _bin/edrenumremote.x64.o && $(STRIP64) _bin/edrenumremote.x64.o) && echo '[+] edr_enum_remote'  || echo '[!] edr_enum_remote'

	# 32-bit builds
	@($(CC86) $(CFLAGS) -c src/edr_enum_bof.c   -o _bin/edrenum.x32.o        && $(STRIP86) _bin/edrenum.x32.o)        && echo '[+] edr_enum (x32)'        || echo '[!] edr_enum'
	@($(CC86) $(CFLAGS) -c src/edr_remote_bof.c -o _bin/edrenumremote.x32.o && $(STRIP86) _bin/edrenumremote.x32.o) && echo '[+] edr_enum_remote (x32)' || echo '[!] edr_enum_remote)'

clean:
	@(rm -rf _bin)
