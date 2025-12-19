all: bof

bof:
	@(mkdir _bin 2>/dev/null) && echo '[+] creating _bin' || echo '[+] _bin exists'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c arp/arp.c -o _bin/arp.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/arp.x64.o) && echo '[+] arp' || echo '[!] arp'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c cacls/cacls.c -o _bin/cacls.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/cacls.x64.o) && echo '[+] cacls' || echo '[!] cacls'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c dir/dir.c -o _bin/dir.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/dir.x64.o) && echo '[+] dir' || echo '[!] dir'
	@(x86_64-w64-mingw32-gcc -I _include -Os -s -c env/env.c -o _bin/env.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/env.x64.o) && echo '[+] env' || echo '[!] env'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c ipconfig/ipconfig.c -o _bin/ipconfig.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/ipconfig.x64.o) && echo '[+] ipconfig' || echo '[!] ipconfig'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c listdns/listdns.c -o _bin/listdns.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/listdns.x64.o) && echo '[+] listdns' || echo '[!] listdns'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c netstat/netstat.c -o _bin/netstat.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/netstat.x64.o) && echo '[+] netstat' || echo '[!] netstat'
	@(x86_64-w64-mingw32-gcc -I _include -Os -fno-jump-tables -c nslookup/nslookup.c -o _bin/nslookup.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/nslookup.x64.o) && echo '[+] nslookup' || echo '[!] nslookup'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c routeprint/routeprint.c -o _bin/routeprint.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/routeprint.x64.o) && echo '[+] routeprint' || echo '[!] routeprint'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c uptime/uptime.c -o _bin/uptime.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/uptime.x64.o) && echo '[+] uptime' || echo '[!] uptime'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c useridletime/useridletime.c -o _bin/useridletime.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/useridletime.x64.o) && echo '[+] useridletime' || echo '[!] useridletime'
	@(x86_64-w64-mingw32-gcc -I _include -Os -c whoami/whoami.c -o _bin/whoami.x64.o -DBOF && x86_64-w64-mingw32-strip --strip-unneeded _bin/whoami.x64.o) && echo '[+] whoami' || echo '[!] whoami'
	@(python3 ./privcheck/download_vulnerable_driver_list.py)
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/vulndrivers.x64.o privcheck/vulnerabledrivers.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/vulndrivers.x64.o) && echo '[+] vulndrivers' || echo '[!] vulndrivers build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/alwayselevated.x64.o privcheck/alwaysinstallelevated.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/alwayselevated.x64.o) && echo '[+] alwayselevated' || echo '[!] alwayselevated build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/hijackablepath.x64.o privcheck/hijackablepath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/hijackablepath.x64.o) && echo '[+] hijackablepath' || echo '[!] hijackablepath build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/tokenpriv.x64.o privcheck/tokenprivileges.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/tokenpriv.x64.o) && echo '[+] tokenpriv' || echo '[!] tokenpriv build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/unattendfiles.x64.o privcheck/unattendfiles.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unattendfiles.x64.o) && echo '[+] unattendfiles' || echo '[!] unattendfiles build failed'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -Os -s -c -I _include -o _bin/unquotedsvc.x64.o privcheck/unquotedsvcpath.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/unquotedsvc.x64.o) && echo '[+] unquotedsvc' || echo '[!] unquotedsvc build failed'

clean:
	@(rm -rf _bin)