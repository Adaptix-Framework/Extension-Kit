CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit builds
	@($(CC64) $(CFLAGS) -s smartscan/portscan_simple.c -o _bin/smartscan.x64.o && $(STRIP64) _bin/smartscan.x64.o) && echo '[+] smartscan' || echo '[!] smartscan'
	@($(CC64) $(CFLAGS) -s nbtscan/nbtscan.c -o _bin/nbtscan.x64.o && $(STRIP64) _bin/nbtscan.x64.o) && echo '[+] nbtscan' || echo '[!] nbtscan'
	@($(CC64) $(CFLAGS) taskhound/taskhound.c -o _bin/taskhound.x64.o && $(STRIP64) _bin/taskhound.x64.o) && echo '[+] taskhound' || echo '[!] taskhound'
	@($(CC64) $(CFLAGS) quser/quser.c -o _bin/quser.x64.o && $(STRIP64) _bin/quser.x64.o) && echo '[+] quser' || echo '[!] quser'

	# 32-bit builds
	@($(CC86) $(CFLAGS) -s smartscan/portscan_simple.c -o _bin/smartscan.x32.o   && $(STRIP86) _bin/smartscan.x32.o)   && echo '[+] smartscan (x32)'   || echo '[!] smartscan (x32)'
	@($(CC86) $(CFLAGS) -s nbtscan/nbtscan.c           -o _bin/nbtscan.x32.o     && $(STRIP86) _bin/nbtscan.x32.o)     && echo '[+] nbtscan (x32)'     || echo '[!] nbtscan (x32)'
	@#($(CC86) $(CFLAGS) taskhound/taskhound.c          -o _bin/taskhound.x32.o   && $(STRIP86) _bin/taskhound.x32.o)   && echo '[+] taskhound (x32)'   || echo '[!] taskhound (x32)'
	@($(CC86) $(CFLAGS) quser/quser.c                  -o _bin/quser.x32.o       && $(STRIP86) _bin/quser.x32.o)       && echo '[+] quser (x32)'       || echo '[!] quser (x32)'


	@$(MAKE) --no-print-directory -C EdrEnum-BOF
	@cp EdrEnum-BOF/_bin/*.o _bin/

clean:
	@(rm -rf _bin)