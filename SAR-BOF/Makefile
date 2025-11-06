all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -s -c smartscan/portscan_simple.c -o _bin/smartscan.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/smartscan.x64.o) && echo '[+] smartscan' || echo '[!] smartscan'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c taskhound/taskhound.c -o _bin/taskhound.x64.o -DBOF -mno-stack-arg-probe && x86_64-w64-mingw32-strip --strip-unneeded _bin/taskhound.x64.o) && echo '[+] taskhound' || echo '[!] taskhound'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c quser/quser.c -o _bin/quser.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/quser.x64.o) && echo '[+] quser' || echo '[!] quser'


clean:
	@(rm -rf _bin)