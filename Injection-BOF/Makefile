all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -masm=intel -Wall -Os -c inject_cfg/inject_cfg.c -o _bin/inject_cfg.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/inject_cfg.x64.o) && echo '[+] inject_cfg' || echo '[!] inject_cfg'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -I _include -Os -c inject_sec/inject_sec.c -o _bin/inject_sec.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/inject_sec.x64.o) && echo '[+] inject_sec' || echo '[!] inject_sec'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -I _include -Os -c inject_poolparty/inject_poolparty.c -o _bin/inject_poolparty.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/inject_poolparty.x64.o) && echo '[+] inject_poolparty' || echo '[!] inject_poolparty'

	@(i686-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -I _include -Os -c inject_32to64/inject_32to64.c -o _bin/inject_32to64.x86.o -DBOF && i686-w64-mingw32-strip --strip-unneeded _bin/inject_32to64.x86.o) && echo '[+] inject_32to64' || echo '[!] inject_32to64'

clean:
	@(rm -rf _bin)