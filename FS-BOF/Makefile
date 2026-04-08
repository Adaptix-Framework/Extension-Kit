CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -I _include -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) dir/dir.c -o _bin/dir.x64.o && $(STRIP64) _bin/dir.x64.o) && echo '[+] dir x64' || echo '[!] dir x64'
	@($(CC86) $(CFLAGS) dir/dir.c -o _bin/dir.x32.o && $(STRIP86) _bin/dir.x32.o) && echo '[+] dir x32' || echo '[!] dir x32'
	@($(CC64) $(CFLAGS) type/type.c -o _bin/type.x64.o && $(STRIP64) _bin/type.x64.o) && echo '[+] type x64' || echo '[!] type x64'
	@($(CC86) $(CFLAGS) type/type.c -o _bin/type.x32.o && $(STRIP86) _bin/type.x32.o) && echo '[+] type x32' || echo '[!] type x32'
	@($(CC64) $(CFLAGS) mkdir/mkdir.c -o _bin/mkdir.x64.o && $(STRIP64) _bin/mkdir.x64.o) && echo '[+] mkdir x64' || echo '[!] mkdir x64'
	@($(CC86) $(CFLAGS) mkdir/mkdir.c -o _bin/mkdir.x32.o && $(STRIP86) _bin/mkdir.x32.o) && echo '[+] mkdir x32' || echo '[!] mkdir x32'
	@($(CC64) $(CFLAGS) move/move.c -o _bin/move.x64.o && $(STRIP64) _bin/move.x64.o) && echo '[+] move x64' || echo '[!] move x64'
	@($(CC86) $(CFLAGS) move/move.c -o _bin/move.x32.o && $(STRIP86) _bin/move.x32.o) && echo '[+] move x32' || echo '[!] move x32'
	@($(CC64) $(CFLAGS) del/del.c -o _bin/del.x64.o && $(STRIP64) _bin/del.x64.o) && echo '[+] del x64' || echo '[!] del x64'
	@($(CC86) $(CFLAGS) del/del.c -o _bin/del.x32.o && $(STRIP86) _bin/del.x32.o) && echo '[+] del x32' || echo '[!] del x32'
	@($(CC64) $(CFLAGS) copy/copy.c -o _bin/copy.x64.o && $(STRIP64) _bin/copy.x64.o) && echo '[+] copy x64' || echo '[!] copy x64'
	@($(CC86) $(CFLAGS) copy/copy.c -o _bin/copy.x32.o && $(STRIP86) _bin/copy.x32.o) && echo '[+] copy x32' || echo '[!] copy x32'
	@($(CC64) $(CFLAGS) rmdir/rmdir.c -o _bin/rmdir.x64.o && $(STRIP64) _bin/rmdir.x64.o) && echo '[+] rmdir x64' || echo '[!] rmdir x64'
	@($(CC86) $(CFLAGS) rmdir/rmdir.c -o _bin/rmdir.x32.o && $(STRIP86) _bin/rmdir.x32.o) && echo '[+] rmdir x32' || echo '[!] rmdir x32'
	@($(CC64) $(CFLAGS) pwd/pwd.c -o _bin/pwd.x64.o && $(STRIP64) _bin/pwd.x64.o) && echo '[+] pwd x64' || echo '[!] pwd x64'
	@($(CC86) $(CFLAGS) pwd/pwd.c -o _bin/pwd.x32.o && $(STRIP86) _bin/pwd.x32.o) && echo '[+] pwd x32' || echo '[!] pwd x32'
	@($(CC64) $(CFLAGS) cd/cd.c -o _bin/cd.x64.o && $(STRIP64) _bin/cd.x64.o) && echo '[+] cd x64' || echo '[!] cd x64'
	@($(CC86) $(CFLAGS) cd/cd.c -o _bin/cd.x32.o && $(STRIP86) _bin/cd.x32.o) && echo '[+] cd x32' || echo '[!] cd x32'

clean:
	@(rm -rf _bin)
