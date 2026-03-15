CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	# 64-bit builds
	@($(CC64) $(CFLAGS) ScreenshotBOF/entry.c -o _bin/Screenshot.x64.o && $(STRIP64) _bin/Screenshot.x64.o) && echo '[+] Screenshot (x64)' || echo '[!] Screenshot (x64)'
	@($(CC64) $(CFLAGS) firewallrule/addfirewallrule.c -o _bin/addfirewallrule.x64.o && $(STRIP64) _bin/addfirewallrule.x64.o) && echo '[+] addfirewallrule (x64)' || echo '[!] addfirewallrule (x64)'
	@($(CC64) $(CFLAGS) SauronEyeBOF/entry.c -o _bin/sauroneye.x64.o && $(STRIP64) _bin/sauroneye.x64.o) && echo '[+] sauroneye (x64)' || echo '[!] sauroneye (x64)'
	@($(CC64) $(CFLAGS) KeyloggerBOF/keylog_start_bof.c -o _bin/keylog_start_bof.x64.o && $(STRIP64) _bin/keylog_start_bof.x64.o) && echo '[+] keylog_start (x64)' || echo '[!] keylog_start (x64)'
	@($(CC64) $(CFLAGS) KeyloggerBOF/keylog_dump_bof.c -o _bin/keylog_dump_bof.x64.o && $(STRIP64) _bin/keylog_dump_bof.x64.o) && echo '[+] keylog_dump (x64)' || echo '[!] keylog_dump (x64)'
	@($(CC64) $(CFLAGS) KeyloggerBOF/keylog_stop_bof.c -o _bin/keylog_stop_bof.x64.o && $(STRIP64) _bin/keylog_stop_bof.x64.o) && echo '[+] keylog_stop (x64)' || echo '[!] keylog_stop (x64)'
	# 32-bit builds
	@($(CC86) $(CFLAGS) ScreenshotBOF/entry.c -o _bin/Screenshot.x32.o && $(STRIP86) _bin/Screenshot.x32.o) && echo '[+] Screenshot (x32)' || echo '[!] Screenshot (x32)'
	@($(CC86) $(CFLAGS) firewallrule/addfirewallrule.c -o _bin/addfirewallrule.x32.o && $(STRIP86) _bin/addfirewallrule.x32.o) && echo '[+] addfirewallrule (x32)' || echo '[!] addfirewallrule (x32)'
	@($(CC86) $(CFLAGS) SauronEyeBOF/entry.c -o _bin/sauroneye.x32.o && $(STRIP86) _bin/sauroneye.x32.o) && echo '[+] sauroneye (x32)' || echo '[!] sauroneye (x32)'
	@($(CC86) $(CFLAGS) KeyloggerBOF/keylog_start_bof.c -o _bin/keylog_start_bof.x32.o && $(STRIP86) _bin/keylog_start_bof.x32.o) && echo '[+] keylog_start (x32)' || echo '[!] keylog_start (x32)'
	@($(CC86) $(CFLAGS) KeyloggerBOF/keylog_dump_bof.c -o _bin/keylog_dump_bof.x32.o && $(STRIP86) _bin/keylog_dump_bof.x32.o) && echo '[+] keylog_dump (x32)' || echo '[!] keylog_dump (x32)'
	@($(CC86) $(CFLAGS) KeyloggerBOF/keylog_stop_bof.c -o _bin/keylog_stop_bof.x32.o && $(STRIP86) _bin/keylog_stop_bof.x32.o) && echo '[+] keylog_stop (x32)' || echo '[!] keylog_stop (x32)'

clean:
	@(rm -rf _bin)
