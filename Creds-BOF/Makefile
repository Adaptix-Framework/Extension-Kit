all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -c askcreds/askcreds.c -o _bin/askcreds.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/askcreds.x64.o) && echo '[*] askcreds' || echo '[X] askcreds'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -c autologon/autologon.c -o _bin/autologon.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/autologon.x64.o) && echo '[*] autologon' || echo '[!] autologon build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -c credman/credentialmanager.c -o _bin/credman.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/credman.x64.o) && echo '[*] credman' || echo '[!] credman build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -c hashdump/hashdump.c -o _bin/hashdump.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/hashdump.x64.o) && echo '[*] hashdump' || echo '[!] hashdump build failed'

