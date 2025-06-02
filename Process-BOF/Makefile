all: bof

clean:
	@(rm -f _bin/* && echo '[*] cleaned')

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -o _bin/findmodule.x64.o -I ./_include/ -Os -s -c findobjects/FindModule.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/findmodule.x64.o) && echo '[*] findmodule' || echo '[X] findmodule build failed'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -o _bin/findprochandle.x64.o -I ./_include/ -Os -s -c findobjects/FindProcHandle.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/findprochandle.x64.o) && echo '[*] findprochandle' || echo '[X] findprochandle build failed'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -o _bin/psc.x64.o -DBOF -Os -I process/_include -c process/psc.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/psc.x64.o) && echo '[*] psc' || echo '[X] psc build failed'