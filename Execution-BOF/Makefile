all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[!] _bin exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -I _include -c -o _bin/execute-assembly.x64.o execute-assembly/inlineExecute-Assembly.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/execute-assembly.x64.o) && echo '[+] execute-assembly' || echo '[!] execute-assembly build failed'

	@$(MAKE) --no-print-directory -C No-Consolation
	@cp No-Consolation/_bin/*.o _bin/


clean:
	@(rm -rf _bin)