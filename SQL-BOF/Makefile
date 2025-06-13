all: bof

clean:
	@(rm -f _bin/* && echo '[*] cleaned')

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[*] _bin exists'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-1434udp.x64.o -Os -s -c 1434udp/sql-1434udp.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-1434udp.x64.o) && echo '[*] sql-1434udp' || echo '[!] sql-1434udp build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-adsi.x64.o -Os -s -c adsi/sql-adsi.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-adsi.x64.o) && echo '[*] sql-adsi' || echo '[!] sql-adsi build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-agentcmd.x64.o -Os -s -c agentcmd/sql-agentcmd.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-agentcmd.x64.o) && echo '[*] sql-agentcmd' || echo '[!] sql-agentcmd build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-agentstatus.x64.o -Os -s -c agentstatus/sql-agentstatus.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-agentstatus.x64.o) && echo '[*] sql-agentstatus' || echo '[!] sql-agentstatus build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-checkrpc.x64.o -Os -s -c checkrpc/sql-checkrpc.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-checkrpc.x64.o) && echo '[*] sql-checkrpc' || echo '[!] sql-checkrpc build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-clr.x64.o -Os -s -c clr/sql-clr.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-clr.x64.o) && echo '[*] sql-clr' || echo '[!] sql-clr build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-columns.x64.o -Os -s -c columns/sql-columns.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-columns.x64.o) && echo '[*] sql-columns' || echo '[!] sql-columns build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-databases.x64.o -Os -s -c databases/sql-databases.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-databases.x64.o) && echo '[*] sql-databases' || echo '[!] sql-databases build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-impersonate.x64.o -Os -s -c impersonate/sql-impersonate.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-impersonate.x64.o) && echo '[*] sql-impersonate' || echo '[!] sql-impersonate build failed'
	@(x86_64-w64-mingw32-gcc -DBOF -w -Wno-incompatible-pointer-types -o _bin/sql-info.x64.o -Os -s -c info/sql-info.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/sql-info.x64.o) && echo '[*] sql-info' || echo '[!] sql-info build failed'

