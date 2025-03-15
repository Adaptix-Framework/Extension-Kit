all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@(x86_64-w64-mingw32-gcc -o _bin/arp.x64.o -I _include -Os -c arp/arp.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/arp.x64.o) && echo '[*] arp' || echo '[X] arp'
	@(x86_64-w64-mingw32-gcc -o _bin/cacls.x64.o -I _include -Os -c cacls/cacls.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/cacls.x64.o) && echo '[*] cacls' || echo '[X] cacls'
	@(x86_64-w64-mingw32-gcc -o _bin/dir.x64.o -I _include  -Os -c dir/dir.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/dir.x64.o) && echo '[*] dir' || echo '[X] dir'
	@(x86_64-w64-mingw32-gcc -o _bin/env.x64.o -I _include  -Os -c env/env.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/env.x64.o) && echo '[*] env' || echo '[X] env'
	@(x86_64-w64-mingw32-gcc -o _bin/ipconfig.x64.o -I _include -Os -c ipconfig/ipconfig.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/ipconfig.x64.o) && echo '[*] ipconfig' || echo '[X] ipconfig'
	@(x86_64-w64-mingw32-gcc -o _bin/listdns.x64.o -I _include -Os -c listdns/listdns.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/listdns.x64.o) && echo '[*] listdns' || echo '[X] listdns'
	@(x86_64-w64-mingw32-gcc -o _bin/netstat.x64.o -I _include -Os -c netstat/netstat.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/netstat.x64.o) && echo '[*] netstat' || echo '[X] netstat'
	@(x86_64-w64-mingw32-gcc -o _bin/nslookup.x64.o -I _include -Os -fno-jump-tables -c nslookup/nslookup.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/nslookup.x64.o) && echo '[*] nslookup' || echo '[X] nslookup'
	@(x86_64-w64-mingw32-gcc -o _bin/routerprint.x64.o -I _include -Os -c routerprint/routerprint.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/routerprint.x64.o) && echo '[*] routerprint' || echo '[X] routerprint'
	@(x86_64-w64-mingw32-gcc -o _bin/uptime.x64.o -I _include -Os -c uptime/uptime.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/uptime.x64.o) && echo '[*] uptime' || echo '[X] uptime'
	@(x86_64-w64-mingw32-gcc -o _bin/whoami.x64.o -I _include -Os -c whoami/whoami.c -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/whoami.x64.o) && echo '[*] whoami' || echo '[X] whoami'