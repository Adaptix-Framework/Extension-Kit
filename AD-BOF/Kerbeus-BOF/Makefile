CC64 = x86_64-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ./ -w -Wno-incompatible-pointer-types -Os -s -DBOF -c

all: bof

bof:
	@(mkdir -p _bin/Kerbeus-BOF 2>/dev/null) && echo 'creating _bin/Kerbeus-BOF' || echo '_bin/Kerbeus-BOF exists'
	@($(CC64) $(CFLAGS) monitor/monitor.c -o _bin/Kerbeus-BOF/monitor.x64.o && $(STRIP64) _bin/Kerbeus-BOF/monitor.x64.o) && echo '[+] monitor' || echo '[!] monitor'
	@($(CC64) $(CFLAGS) hash/hash.c -o _bin/Kerbeus-BOF/hash.x64.o    && $(STRIP64) _bin/Kerbeus-BOF/hash.x64.o) && echo '[+] hash' || echo '[!] hash'
	@($(CC64) $(CFLAGS) klist/klist.c -o _bin/Kerbeus-BOF/klist.x64.o && $(STRIP64) _bin/Kerbeus-BOF/klist.x64.o) && echo '[+] klist' || echo '[!] klist'
	@($(CC64) $(CFLAGS) -DTRIAGE klist/klist.c -o _bin/Kerbeus-BOF/triage.x64.o && $(STRIP64) _bin/Kerbeus-BOF/triage.x64.o) && echo '[+] triage' || echo '[!] triage'
	@($(CC64) $(CFLAGS) -DDUMP klist/klist.c -o _bin/Kerbeus-BOF/dump.x64.o     && $(STRIP64) _bin/Kerbeus-BOF/dump.x64.o) && echo '[+] dump' || echo '[!] dump'
	@($(CC64) $(CFLAGS) describe/describe.c -o _bin/Kerbeus-BOF/describe.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/describe.x64.o) && echo '[+] describe' || echo '[!] describe'
	@($(CC64) $(CFLAGS) tgtdeleg/tgtdeleg.c -o _bin/Kerbeus-BOF/tgtdeleg.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/tgtdeleg.x64.o) && echo '[+] tgtdeleg' || echo '[!] tgtdeleg'
	@($(CC64) $(CFLAGS) ptt/ptt.c -o _bin/Kerbeus-BOF/ptt.x64.o                 && $(STRIP64) _bin/Kerbeus-BOF/ptt.x64.o) && echo '[+] ptt' || echo '[!] ptt'
	@($(CC64) $(CFLAGS) purge/purge.c -o _bin/Kerbeus-BOF/purge.x64.o           && $(STRIP64) _bin/Kerbeus-BOF/purge.x64.o) && echo '[+] purge' || echo '[!] purge'
	@($(CC64) $(CFLAGS) asktgt/asktgt.c -o _bin/Kerbeus-BOF/asktgt.x64.o        && $(STRIP64) _bin/Kerbeus-BOF/asktgt.x64.o) && echo '[+] asktgt' || echo '[!] asktgt'
	@($(CC64) $(CFLAGS) asktgs/asktgs.c -o _bin/Kerbeus-BOF/asktgs.x64.o        && $(STRIP64) _bin/Kerbeus-BOF/asktgs.x64.o) && echo '[+] asktgs' || echo '[!] asktgs'
	@($(CC64) $(CFLAGS) renew/renew.c -o _bin/Kerbeus-BOF/renew.x64.o           && $(STRIP64) _bin/Kerbeus-BOF/renew.x64.o) && echo '[+] renew' || echo '[!] renew'
	@($(CC64) $(CFLAGS) changepw/changepw.c -o _bin/Kerbeus-BOF/changepw.x64.o  && $(STRIP64) _bin/Kerbeus-BOF/changepw.x64.o) && echo '[+] changepw' || echo '[!] changepw'
	@($(CC64) $(CFLAGS) asreproasting/asreproasting.c -o _bin/Kerbeus-BOF/asreproasting.x64.o && $(STRIP64) _bin/Kerbeus-BOF/asreproasting.x64.o) && echo '[+] asreproasting' || echo '[!] asreproasting'
	@($(CC64) $(CFLAGS) kerberoasting/kerberoasting.c -o _bin/Kerbeus-BOF/kerberoasting.x64.o && $(STRIP64) _bin/Kerbeus-BOF/kerberoasting.x64.o) && echo '[+] kerberoasting' || echo '[!] kerberoasting'
	@($(CC64) $(CFLAGS) s4u/s4u.c -o _bin/Kerbeus-BOF/s4u.x64.o             && $(STRIP64) _bin/Kerbeus-BOF/s4u.x64.o) && echo '[+] s4u' || echo '[!] s4u'
	@($(CC64) $(CFLAGS) s4u/cross_s4u.c -o _bin/Kerbeus-BOF/cross_s4u.x64.o && $(STRIP64) _bin/Kerbeus-BOF/cross_s4u.x64.o) && echo '[+] cross_s4u' || echo '[!] cross_s4u'
clean:
	@(rm -rf _bin)
