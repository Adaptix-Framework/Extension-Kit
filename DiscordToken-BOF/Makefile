CC64    = x86_64-w64-mingw32-gcc
CC86    = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS  = -w -Os -s -mno-stack-arg-probe -fno-stack-protector -c

all: clean bof

bof:
	@mkdir -p _bin
	@($(CC64) $(CFLAGS) discord_tokens.c -o _bin/discord_tokens.x64.o && $(STRIP64) _bin/discord_tokens.x64.o) && echo '[+] discord_tokens.x64.o' || echo '[-] x64 build failed'
	@($(CC86) $(CFLAGS) discord_tokens.c -o _bin/discord_tokens.x86.o && $(STRIP86) _bin/discord_tokens.x86.o) && echo '[+] discord_tokens.x86.o' || echo '[-] x86 build failed'

clean:
	@rm -rf _bin
