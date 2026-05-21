CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP = x86_64-w64-mingw32-strip
CFLAGS = -Wall -masm=intel -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -I src
SRC = src/wifidump.c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit builds
	@$(CC64) $(CFLAGS) -DBOF_ENTRY_ENUM -c $(SRC) -o _bin/wifidump_enum.x64.o && $(STRIP) --strip-unneeded _bin/wifidump_enum.x64.o && echo '[+] wifidump_enum (x64)' || echo '[!] wifidump_enum (x64)'
	@$(CC64) $(CFLAGS) -DBOF_ENTRY_DUMP -c $(SRC) -o _bin/wifidump_dump.x64.o && $(STRIP) --strip-unneeded _bin/wifidump_dump.x64.o && echo '[+] wifidump_dump (x64)' || echo '[!] wifidump_dump (x64)'
	@$(CC64) $(CFLAGS) -DBOF_ENTRY_AUTH -c $(SRC) -o _bin/wifidump_auth.x64.o && $(STRIP) --strip-unneeded _bin/wifidump_auth.x64.o && echo '[+] wifidump_auth (x64)' || echo '[!] wifidump_auth (x64)'

	# 32-bit builds
	@$(CC86) $(CFLAGS) -DBOF_ENTRY_ENUM -c $(SRC) -o _bin/wifidump_enum.x86.o && echo '[+] wifidump_enum (x86)' || echo '[!] wifidump_enum (x86)'
	@$(CC86) $(CFLAGS) -DBOF_ENTRY_DUMP -c $(SRC) -o _bin/wifidump_dump.x86.o && echo '[+] wifidump_dump (x86)' || echo '[!] wifidump_dump (x86)'
	@$(CC86) $(CFLAGS) -DBOF_ENTRY_AUTH -c $(SRC) -o _bin/wifidump_auth.x86.o && echo '[+] wifidump_auth (x86)' || echo '[!] wifidump_auth (x86)'


clean:
	@(rm -rf _bin)
