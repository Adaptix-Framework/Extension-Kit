
all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/psexec.x64.o -I ./ -Os -s -c psexec/psexec.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/psexec.x64.o) && echo '[+] psexec' || echo '[!] psexec'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/scshell.x64.o -I ./ -Os -s -c scshell/scshell.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/scshell.x64.o) && echo '[+] scshell' || echo '[!] scshell'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/token_make.x64.o -I ./ -Os -s -c token_make/token_make.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/token_make.x64.o) && echo '[+] token_make' || echo '[!] token_make'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -o _bin/token_steal.x64.o -I ./ -Os -s -c token_steal/token_steal.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/token_steal.x64.o) && echo '[+] token_steal' || echo '[!] token_steal'
	@(x86_64-w64-mingw32-gcc -w -Os -s -c -o _bin/winrm.x64.o winrm-client/winrm.cpp -masm=intel -nostdlib -Wno-nonnull -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti && x86_64-w64-mingw32-strip --strip-unneeded _bin/winrm.x64.o) && echo '[*] winrm' || echo '[!] winrm build failed'

clean:
	@(rm -rf _bin)