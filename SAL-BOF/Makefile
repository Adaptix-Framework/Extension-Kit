CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	# 64-bit builds
	@($(CC64) $(CFLAGS) arp/arp.c -o _bin/arp.x64.o && $(STRIP64) _bin/arp.x64.o) && echo '[+] arp x64' || echo '[!] arp x64'
	@($(CC64) $(CFLAGS) cacls/cacls.c -o _bin/cacls.x64.o && $(STRIP64) _bin/cacls.x64.o) && echo '[+] cacls x64' || echo '[!] cacls x64'
	@($(CC64) $(CFLAGS) dir/dir.c -o _bin/dir.x64.o && $(STRIP64) _bin/dir.x64.o) && echo '[+] dir x64' || echo '[!] dir x64'
	@($(CC64) $(CFLAGS) env/env.c -o _bin/env.x64.o && $(STRIP64) _bin/env.x64.o) && echo '[+] env x64' || echo '[!] env x64'
	@($(CC64) $(CFLAGS) ipconfig/ipconfig.c -o _bin/ipconfig.x64.o && $(STRIP64) _bin/ipconfig.x64.o) && echo '[+] ipconfig x64' || echo '[!] ipconfig x64'
	@($(CC64) $(CFLAGS) listdns/listdns.c -o _bin/listdns.x64.o && $(STRIP64) _bin/listdns.x64.o) && echo '[+] listdns x64' || echo '[!] listdns x64'
	@($(CC64) $(CFLAGS) netstat/netstat.c -o _bin/netstat.x64.o && $(STRIP64) _bin/netstat.x64.o) && echo '[+] netstat x64' || echo '[!] netstat x64'
	@($(CC64) $(CFLAGS) -fno-jump-tables nslookup/nslookup.c -o _bin/nslookup.x64.o && $(STRIP64) _bin/nslookup.x64.o) && echo '[+] nslookup x64' || echo '[!] nslookup x64'
	@($(CC64) $(CFLAGS) routeprint/routeprint.c -o _bin/routeprint.x64.o && $(STRIP64) _bin/routeprint.x64.o) && echo '[+] routeprint x64' || echo '[!] routeprint x64'
	@($(CC64) $(CFLAGS) uptime/uptime.c -o _bin/uptime.x64.o && $(STRIP64) _bin/uptime.x64.o) && echo '[+] uptime x64' || echo '[!] uptime x64'
	@($(CC64) $(CFLAGS) useridletime/useridletime.c -o _bin/useridletime.x64.o && $(STRIP64) _bin/useridletime.x64.o) && echo '[+] useridletime x64' || echo '[!] useridletime x64'
	@($(CC64) $(CFLAGS) whoami/whoami.c -o _bin/whoami.x64.o && $(STRIP64) _bin/whoami.x64.o) && echo '[+] whoami x64' || echo '[!] whoami x64'
	@(python3 ./privcheck/download_vulnerable_driver_list.py)
	@($(CC64) $(CFLAGS) privcheck/vulnerabledrivers.c -o _bin/vulndrivers.x64.o && $(STRIP64) _bin/vulndrivers.x64.o) && echo '[+] vulndrivers x64' || echo '[!] vulndrivers x64'
	@($(CC64) $(CFLAGS) privcheck/alwaysinstallelevated.c -o _bin/alwayselevated.x64.o && $(STRIP64) _bin/alwayselevated.x64.o) && echo '[+] alwayselevated x64' || echo '[!] alwayselevated x64'
	@($(CC64) $(CFLAGS) privcheck/hijackablepath.c -o _bin/hijackablepath.x64.o && $(STRIP64) _bin/hijackablepath.x64.o) && echo '[+] hijackablepath x64' || echo '[!] hijackablepath x64'
	@($(CC64) $(CFLAGS) privcheck/tokenprivileges.c -o _bin/tokenpriv.x64.o && $(STRIP64) _bin/tokenpriv.x64.o) && echo '[+] tokenpriv x64' || echo '[!] tokenpriv x64'
	@($(CC64) $(CFLAGS) privcheck/unattendfiles.c -o _bin/unattendfiles.x64.o && $(STRIP64) _bin/unattendfiles.x64.o) && echo '[+] unattendfiles x64' || echo '[!] unattendfiles x64'
	@($(CC64) $(CFLAGS) privcheck/unquotedsvcpath.c -o _bin/unquotedsvc.x64.o && $(STRIP64) _bin/unquotedsvc.x64.o) && echo '[+] unquotedsvc x64' || echo '[!] unquotedsvc x64'

	# 32-bit builds
	@($(CC86) $(CFLAGS) arp/arp.c -o _bin/arp.x32.o && $(STRIP86) _bin/arp.x32.o) && echo '[+] arp x32' || echo '[!] arp x32'
	@($(CC86) $(CFLAGS) cacls/cacls.c -o _bin/cacls.x32.o && $(STRIP86) _bin/cacls.x32.o) && echo '[+] cacls x32' || echo '[!] cacls x32'
	@($(CC86) $(CFLAGS) dir/dir.c -o _bin/dir.x32.o && $(STRIP86) _bin/dir.x32.o) && echo '[+] dir x32' || echo '[!] dir x32'
	@($(CC86) $(CFLAGS) env/env.c -o _bin/env.x32.o && $(STRIP86) _bin/env.x32.o) && echo '[+] env x32' || echo '[!] env x32'
	@($(CC86) $(CFLAGS) ipconfig/ipconfig.c -o _bin/ipconfig.x32.o && $(STRIP86) _bin/ipconfig.x32.o) && echo '[+] ipconfig x32' || echo '[!] ipconfig x32'
	@($(CC86) $(CFLAGS) listdns/listdns.c -o _bin/listdns.x32.o && $(STRIP86) _bin/listdns.x32.o) && echo '[+] listdns x32' || echo '[!] listdns x32'
	@($(CC86) $(CFLAGS) netstat/netstat.c -o _bin/netstat.x32.o && $(STRIP86) _bin/netstat.x32.o) && echo '[+] netstat x32' || echo '[!] netstat x32'
	@#($(CC86) $(CFLAGS) -fno-jump-tables nslookup/nslookup.c -o _bin/nslookup.x32.o && $(STRIP86) _bin/nslookup.x32.o) && echo '[+] nslookup x32' || echo '[!] nslookup x32'
	@($(CC86) $(CFLAGS) routeprint/routeprint.c -o _bin/routeprint.x32.o && $(STRIP86) _bin/routeprint.x32.o) && echo '[+] routeprint x32' || echo '[!] routeprint x32'
	@($(CC86) $(CFLAGS) uptime/uptime.c -o _bin/uptime.x32.o && $(STRIP86) _bin/uptime.x32.o) && echo '[+] uptime x32' || echo '[!] uptime x32'
	@($(CC86) $(CFLAGS) useridletime/useridletime.c -o _bin/useridletime.x32.o && $(STRIP86) _bin/useridletime.x32.o) && echo '[+] useridletime x32' || echo '[!] useridletime x32'
	@($(CC86) $(CFLAGS) whoami/whoami.c -o _bin/whoami.x32.o && $(STRIP86) _bin/whoami.x32.o) && echo '[+] whoami x32' || echo '[!] whoami x32'
	@($(CC86) $(CFLAGS) privcheck/vulnerabledrivers.c -o _bin/vulndrivers.x32.o && $(STRIP86) _bin/vulndrivers.x32.o) && echo '[+] vulndrivers x32' || echo '[!] vulndrivers x32'
	@($(CC86) $(CFLAGS) privcheck/alwaysinstallelevated.c -o _bin/alwayselevated.x32.o && $(STRIP86) _bin/alwayselevated.x32.o) && echo '[+] alwayselevated x32' || echo '[!] alwayselevated x32'
	@($(CC86) $(CFLAGS) privcheck/hijackablepath.c -o _bin/hijackablepath.x32.o && $(STRIP86) _bin/hijackablepath.x32.o) && echo '[+] hijackablepath x32' || echo '[!] hijackablepath x32'
	@($(CC86) $(CFLAGS) privcheck/tokenprivileges.c -o _bin/tokenpriv.x32.o && $(STRIP86) _bin/tokenpriv.x32.o) && echo '[+] tokenpriv x32' || echo '[!] tokenpriv x32'
	@($(CC86) $(CFLAGS) privcheck/unattendfiles.c -o _bin/unattendfiles.x32.o && $(STRIP86) _bin/unattendfiles.x32.o) && echo '[+] unattendfiles x32' || echo '[!] unattendfiles x32'
	@($(CC86) $(CFLAGS) privcheck/unquotedsvcpath.c -o _bin/unquotedsvc.x32.o && $(STRIP86) _bin/unquotedsvc.x32.o) && echo '[+] unquotedsvc x32' || echo '[!] unquotedsvc x32'
clean:
	@(rm -rf _bin)
