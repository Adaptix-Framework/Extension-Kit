
all: bof

bof:
	@(mkdir -p _bin/SQL 2>/dev/null) && echo 'creating _bin/SQL' || echo '_bin/SQL exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/1434udp.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/1434udp/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/1434udp.x64.o) && echo '[+] 1434udp' || echo '[!] 1434udp'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/adsi.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/adsi/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/adsi.x64.o) && echo '[+] adsi' || echo '[!] adsi'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/agentcmd.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/agentcmd/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/agentcmd.x64.o) && echo '[+] agentcmd' || echo '[!] agentcmd'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/agentstatus.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/agentstatus/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/agentstatus.x64.o) && echo '[+] agentstatus' || echo '[!] agentstatus'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/checkrpc.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/checkrpc/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/checkrpc.x64.o) && echo '[+] checkrpc' || echo '[!] checkrpc'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/clr.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/clr/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/clr.x64.o) && echo '[+] clr' || echo '[!] clr'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/columns.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/columns/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/columns.x64.o) && echo '[+] columns' || echo '[!] columns'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/databases.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/databases/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/databases.x64.o) && echo '[+] databases' || echo '[!] databases'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/togglemodule.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/togglemodule/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/togglemodule.x64.o) && echo '[+] togglemodule' || echo '[!] togglemodule'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/impersonate.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/impersonate/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/impersonate.x64.o) && echo '[+] impersonate' || echo '[!] impersonate'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/info.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/info/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/info.x64.o) && echo '[+] info' || echo '[!] info'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/links.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/links/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/links.x64.o) && echo '[+] links' || echo '[!] links'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/olecmd.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/olecmd/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/olecmd.x64.o) && echo '[+] olecmd' || echo '[!] olecmd'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/query.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/query/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/query.x64.o) && echo '[+] query' || echo '[!] query'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/rows.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/rows/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/rows.x64.o) && echo '[+] rows' || echo '[!] rows'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/search.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/search/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/search.x64.o) && echo '[+] search' || echo '[!] search'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/smb.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/smb/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/smb.x64.o) && echo '[+] smb' || echo '[!] smb'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/tables.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/tables/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/tables.x64.o) && echo '[+] tables' || echo '[!] tables'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/users.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/users/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/users.x64.o) && echo '[+] users' || echo '[!] users'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/whoami.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/whoami/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/whoami.x64.o) && echo '[+] whoami' || echo '[!] whoami'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/SQL/xpcmd.x64.o -I ./src/common -Os -s -DBOF -c src/SQL/xpcmd/entry.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/SQL/xpcmd.x64.o) && echo '[+] xpcmd' || echo '[!] xpcmd'

clean:
	@(rm -rf _bin)