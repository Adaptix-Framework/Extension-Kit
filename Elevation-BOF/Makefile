all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin' || echo '_bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -I _include -c -o _bin/getsystem_token.x64.o getsystem_token/getsystem_token.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/getsystem_token.x64.o) && echo '[+] getsystem_token' || echo '[!] getsystem_token'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -I _include -c -o _bin/uac_regshellcmd.x64.o uac_regshellcmd/RegistryShellCommandBOF.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/uac_regshellcmd.x64.o) && echo '[+] uac_regshellcmd' || echo '[!] uac_regshellcmd build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -I _include -c -o _bin/printspoofer.x64.o printspoofer/printspoofer.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/printspoofer.x64.o) && echo '[+] printspoofer' || echo '[!] printspoofer build failed'
	@(x86_64-w64-mingw32-gcc -w -Os -s -I _include -c -o _bin/uac_sspi.x64.o uac_sspi/SspiUacBypassBOF.cpp && x86_64-w64-mingw32-strip --strip-unneeded _bin/uac_sspi.x64.o) && echo '[+] uac_sspi' || echo '[!] uac_sspi build failed'
	@(x86_64-w64-mingw32-gcc -w -Os -s -I _include -c -o _bin/DCOMPotato.x64.o potato-dcom/DCOMPotato.cpp -masm=intel -nostdlib -Wno-nonnull -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti && x86_64-w64-mingw32-strip --strip-unneeded _bin/DCOMPotato.x64.o) && echo '[+] DCOMPotato' || echo '[!] DCOMPotato build failed'

clean:
	@(rm -rf _bin)