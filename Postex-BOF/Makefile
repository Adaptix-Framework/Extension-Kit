
all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/Screenshot.x64.o ScreenshotBOF/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Screenshot.x64.o) && echo '[*] Screenshot' || echo '[!] Screenshot build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/Persistence.x64.o PersistenceBof/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Persistence.x64.o) && echo '[*] Persistence' || echo '[!] Persistence build failed'
