all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[+] _bin exists'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -s -I _include -c -o _bin/findmodule.x64.o findobjects/FindModule.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/findmodule.x64.o) && echo '[+] findmodule' || echo '[!] findmodule build failed'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -s -I _include -c -o _bin/findprochandle.x64.o findobjects/FindProcHandle.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/findprochandle.x64.o) && echo '[+] findprochandle' || echo '[!] findprochandle build failed'
	@(x86_64-w64-mingw32-gcc -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -I process/_include -c -o _bin/psc.x64.o process/psc.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/psc.x64.o) && echo '[+] psc' || echo '[!] psc build failed'

clean:
	@(rm -rf _bin)