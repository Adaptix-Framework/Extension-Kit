all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -I _include -DBOF -c askcreds/askcreds.c -o _bin/askcreds.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/askcreds.x64.o)             && echo '[+] askcreds'  || echo '[!] askcreds'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -I _include -DBOF -c autologon/autologon.c -o _bin/autologon.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/autologon.x64.o)         && echo '[+] autologon' || echo '[!] autologon build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -I _include -DBOF -c credman/credentialmanager.c -o _bin/credman.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/credman.x64.o)       && echo '[+] credman'   || echo '[!] credman build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -I _include -DBOF -c hashdump/hashdump.c -o _bin/hashdump.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/hashdump.x64.o)             && echo '[+] hashdump'  || echo '[!] hashdump build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -c cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/cookie-monster-bof.x64.o) && echo '[+] cookie-monster'  || echo '[!] cookie-monster build failed'
	@(x86_64-w64-mingw32-gcc -w -DBOF -I _include -c get-netntlm/get-netntlm.c -o _bin/get-netntlm.x64.o && x86_64-w64-mingw32-strip --strip-unneeded _bin/get-netntlm.x64.o) && echo '[+] get-netntlm'  || echo '[!] get-netntlm build failed'
	@(x86_64-w64-mingw32-gcc -I UnderlayCopy-BOF/_include -Os -masm=intel -c UnderlayCopy-BOF/UnderlayCopyBOF/entry.c -o _bin/underlaycopy.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/underlaycopy.x64.o) && echo '[+] underlaycopy x64' || echo '[!] underlaycopy x64'
	@$(MAKE) --no-print-directory -C nanodump
	@cp nanodump/dist/*.o _bin/

clean:
	@(rm -rf _bin)