CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc

CFLAGS = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel -I src

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit builds
	@($(CC64) $(CFLAGS) -c src/keylog_start_bof.c -o _bin/keylog_start_bof.x64.o) && echo '[+] keylog_start' || echo '[!] keylog_start'
	@($(CC64) $(CFLAGS) -c src/keylog_dump_bof.c  -o _bin/keylog_dump_bof.x64.o)  && echo '[+] keylog_dump'  || echo '[!] keylog_dump'
	@($(CC64) $(CFLAGS) -c src/keylog_stop_bof.c  -o _bin/keylog_stop_bof.x64.o)  && echo '[+] keylog_stop'  || echo '[!] keylog_stop'

	# 32-bit builds
	@($(CC86) $(CFLAGS) -c src/keylog_start_bof.c -o _bin/keylog_start_bof.x86.o) && echo '[+] keylog_start (x86)' || echo '[!] keylog_start (x86)'
	@($(CC86) $(CFLAGS) -c src/keylog_dump_bof.c  -o _bin/keylog_dump_bof.x86.o)  && echo '[+] keylog_dump (x86)'  || echo '[!] keylog_dump (x86)'
	@($(CC86) $(CFLAGS) -c src/keylog_stop_bof.c  -o _bin/keylog_stop_bof.x86.o)  && echo '[+] keylog_stop (x86)'  || echo '[!] keylog_stop (x86)'

clean:
	@(rm -rf _bin)
