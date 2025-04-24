all: bof
	
bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -I _include -masm=intel -Wall -Os -c screenshot/screenshot.cpp -DBOF -nostdlib -Wno-nonnull -o _bin/screenshot.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/screenshot.x64.o) && echo '[*] screenshot x64' || echo '[X] screenshot x64'
	@(i686-w64-mingw32-gcc -I _include -masm=intel -Wall -Os -c screenshot/screenshot.cpp -DBOF -nostdlib -Wno-nonnull -o _bin/screenshot.x32.o && i686-w64-mingw32-strip --strip-unneeded _bin/screenshot.x32.o) && echo '[*] screenshot x32' || echo '[X] screenshot x32'