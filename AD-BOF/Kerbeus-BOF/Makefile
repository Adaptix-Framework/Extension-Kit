
all: bof

bof:
	@(mkdir -p _bin/Kerbeus-BOF 2>/dev/null) && echo 'creating _bin/Kerbeus-BOF' || echo '_bin/Kerbeus-BOF exists'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/hash.x64.o -I ./ -Os -s -c hash/hash.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/hash.x64.o) && echo '[+] hash' || echo '[!] hash'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/klist.x64.o -I ./ -Os -s -c klist/klist.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/klist.x64.o) && echo '[+] klist' || echo '[!] klist'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/triage.x64.o -I ./ -DTRIAGE -Os -s -c klist/klist.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/triage.x64.o) && echo '[+] triage' || echo '[!] triage'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/dump.x64.o -I ./ -DDUMP -Os -s -c klist/klist.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/dump.x64.o) && echo '[+] dump' || echo '[!] dump'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/describe.x64.o -I ./ -Os -s -c describe/describe.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/describe.x64.o) && echo '[+] describe' || echo '[!] describe'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/tgtdeleg.x64.o -I ./ -Os -s -c tgtdeleg/tgtdeleg.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/tgtdeleg.x64.o) && echo '[+] tgtdeleg' || echo '[!] tgtdeleg'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/ptt.x64.o -I ./ -Os -s -c ptt/ptt.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/ptt.x64.o) && echo '[+] ptt' || echo '[!] ptt'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/purge.x64.o -I ./ -Os -s -c purge/purge.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/purge.x64.o) && echo '[+] purge' || echo '[!] purge'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/asktgt.x64.o -I ./ -Os -s -c asktgt/asktgt.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/asktgt.x64.o) && echo '[+] asktgt' || echo '[!] asktgt'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/asktgs.x64.o -I ./ -Os -s -c asktgs/asktgs.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/asktgs.x64.o) && echo '[+] asktgs' || echo '[!] asktgs'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/renew.x64.o -I ./ -Os -s -c renew/renew.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/renew.x64.o) && echo '[+] renew' || echo '[!] renew'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/changepw.x64.o -I ./ -Os -s -c changepw/changepw.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/changepw.x64.o) && echo '[+] changepw' || echo '[!] changepw'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/asreproasting.x64.o -I ./ -Os -s -c asreproasting/asreproasting.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/asreproasting.x64.o) && echo '[+] asreproasting' || echo '[!] asreproasting'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/kerberoasting.x64.o -I ./ -Os -s -c kerberoasting/kerberoasting.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/kerberoasting.x64.o) && echo '[+] kerberoasting' || echo '[!] kerberoasting'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/s4u.x64.o -I ./ -Os -s -c s4u/s4u.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/s4u.x64.o) && echo '[+] s4u' || echo '[!] s4u'
	@(x86_64-w64-mingw32-gcc -w -Wno-incompatible-pointer-types -o _bin/Kerbeus-BOF/cross_s4u.x64.o -I ./ -Os -s -c s4u/cross_s4u.c && x86_64-w64-mingw32-strip --strip-unneeded _bin/Kerbeus-BOF/cross_s4u.x64.o) && echo '[+] cross_s4u' || echo '[!] cross_s4u'

clean:
	@(rm -rf _bin)