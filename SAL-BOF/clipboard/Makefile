CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip
STRIP86 = i686-w64-mingw32-strip

CFLAGS = -Wall -masm=intel -I src

SRC = src/clipboard.c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit build
	@$(CC64) $(CFLAGS) -c $(SRC) -o _bin/clipboard.x64.o && \
	$(STRIP64) --strip-unneeded _bin/clipboard.x64.o && \
	echo '[+] clipboard (x64)' || echo '[!] clipboard (x64)'

	# 32-bit build
	@$(CC86) $(CFLAGS) -c $(SRC) -o _bin/clipboard.x86.o && \
	$(STRIP86) --strip-unneeded _bin/clipboard.x86.o && \
	echo '[+] clipboard (x86)' || echo '[!] clipboard (x86)'


clean:
	@(rm -rf _bin)
