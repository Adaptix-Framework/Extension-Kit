
all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/Screenshot.x64.o ScreenshotBOF/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Screenshot.x64.o) && echo '[+] Screenshot' || echo '[!] Screenshot build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/addfirewallrule.x64.o firewallrule/addfirewallrule.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/addfirewallrule.x64.o) && echo '[+] addfirewallrule' || echo '[!] addfirewallrule'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -c -o _bin/sauroneye.x64.o SauronEyeBOF/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sauroneye.x64.o) && echo '[+] sauroneye' || echo '[!] sauroneye build failed'


clean:
	@(rm -rf _bin)