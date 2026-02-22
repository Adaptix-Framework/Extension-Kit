
CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -Os -masm=intel -DBOF -c

all: bof

bof: clean
	# 64-bit builds
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) ldapsearch/ldapsearch.c -o _bin/ldapsearch.x64.o && $(STRIP64) _bin/ldapsearch.x64.o) && echo '[+] ldapsearch' || echo '[!] ldapsearch'
	@($(CC64) $(CFLAGS) adwssearch/adws_search.c -o _bin/adws_search.x64.o && $(STRIP64) _bin/adws_search.x64.o) && echo '[+] adws_search' || echo '[!] adws_search'
	@($(CC64) $(CFLAGS) readlaps/readlaps.c -o _bin/readlaps.x64.o && $(STRIP64) _bin/readlaps.x64.o) && echo '[+] readlaps' || echo '[!] readlaps'
	@($(CC64) $(CFLAGS) WebDAVClient/EnableWebDAVClient.c -o _bin/webdav_enable.x64.o && $(STRIP64) _bin/webdav_enable.x64.o) && echo '[+] webdav_enable' || echo '[!] webdav_enable'
	@($(CC64) $(CFLAGS) WebDAVClient/StatusWebDAVClient.c -o _bin/webdav_status.x64.o && $(STRIP64) _bin/webdav_status.x64.o) && echo '[+] webdav_status' || echo '[!] webdav_status'
	@ # x86: -DWOW64 -fno-leading-underscore
	@($(CC64) $(CFLAGS) -fno-asynchronous-unwind-tables -nostdlib -fno-ident -fpack-struct=8 -falign-functions=1 -s -ffunction-sections -falign-jumps=1 -w -Wall -shared -Wl,--no-seh -Wl,--enable-stdcall-fixup badtakeover/BadTakeover.c -o _bin/badtakeover.x64.o -DBOF && $(STRIP64) _bin/badtakeover.x64.o) && echo '[+] badtakeover' || echo '[!] badtakeover'


	@$(MAKE) --no-print-directory -C DCSync-BOF
	@mv DCSync-BOF/_bin/* _bin/

	@$(MAKE) --no-print-directory -C RelayInformer
	@$(MAKE) --no-print-directory -C ADCS-BOF
	@$(MAKE) --no-print-directory -C Kerbeus-BOF
	@$(MAKE) --no-print-directory -C SQL-BOF
	@$(MAKE) --no-print-directory -C LDAP-BOF

clean:
	@(rm -rf _bin)
