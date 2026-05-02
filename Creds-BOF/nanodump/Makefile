BOFNAME := nanodump
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
GCC := gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Wimplicit-function-declaration -Wall -I include -Wl,--dynamicbase
PPL_MEDIC_OPTIONS := -Wno-trigraphs -DPASS_PARAMS_VIA_NAMED_PIPES=1
SSP_OPTIONS := -DPASS_PARAMS_VIA_NAMED_PIPES=1

nanodump:
	@(mkdir dist 2>/dev/null) && echo 'creating dist' || echo 'dist exists'

	@$(CC_x64) -c source/entry.c -o dist/$(BOFNAME).x64.o $(OPTIONS) -DNANO -DBOF
	@$(STRIP_x64) --strip-unneeded dist/$(BOFNAME).x64.o && echo '[+] nanodump x64' || echo '[!] nanodump x64'

	@$(CC_x86) -c source/entry.c -o dist/$(BOFNAME).x86.o $(OPTIONS) -DNANO -DBOF
	@$(STRIP_x86) --strip-unneeded dist/$(BOFNAME).x86.o && echo '[+] nanodump x86' || echo '[!] nanodump x86'

	@$(CC_x64) source/spoof_callstack.c source/hw_breakpoint.c source/shtinkering.c source/dinvoke.c source/utils.c source/handle.c source/impersonate.c source/modules.c source/syscalls.c source/token_priv.c source/malseclogon.c source/nanodump.c source/werfault.c source/entry.c -o dist/$(BOFNAME).x64.exe $(OPTIONS) -DNANO -DEXE
	@$(STRIP_x64) --strip-all dist/$(BOFNAME).x64.exe && echo '[+] nanodump exe x64' || echo '[!] nanodump exe x64'

	@$(CC_x86) source/spoof_callstack.c source/hw_breakpoint.c source/shtinkering.c source/dinvoke.c source/utils.c source/handle.c source/impersonate.c source/modules.c source/syscalls.c source/token_priv.c source/malseclogon.c source/nanodump.c source/werfault.c source/entry.c -o dist/$(BOFNAME).x86.exe $(OPTIONS) -DNANO -DEXE
	@$(STRIP_x86) --strip-all dist/$(BOFNAME).x86.exe && echo '[+] nanodump exe x86' || echo '[!] nanodump exe x86'

	@$(GCC) source/bin2c.c -o dist/bin2c -Os

	@$(CC_x64) source/utils.c source/handle.c source/modules.c source/syscalls.c source/token_priv.c source/nanodump.c source/dinvoke.c source/pipe.c source/entry.c -o dist/$(BOFNAME)_ssp.x64.dll $(OPTIONS) $(SSP_OPTIONS) -DNANO -DSSP -DDDL -shared
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ssp.x64.dll && echo '[+] nanodump_ssp Dll x64' || echo '[!] nanodump_ssp Dll x64'
	@./dist/bin2c dist/$(BOFNAME)_ssp.x64.dll $(BOFNAME)_ssp_dll > include/$(BOFNAME)_ssp_dll.x64.h

	@$(CC_x86) source/utils.c source/handle.c source/modules.c source/syscalls.c source/token_priv.c source/nanodump.c source/dinvoke.c source/pipe.c source/entry.c -o dist/$(BOFNAME)_ssp.x86.dll $(OPTIONS) $(SSP_OPTIONS) -DNANO -DSSP -DDDL -shared
	@$(STRIP_x86) --strip-all dist/$(BOFNAME)_ssp.x86.dll && echo '[+] nanodump_ssp Dll x86' || echo '[!] nanodump_ssp Dll x86'
	@./dist/bin2c dist/$(BOFNAME)_ssp.x86.dll $(BOFNAME)_ssp_dll > include/$(BOFNAME)_ssp_dll.x86.h

	@$(CC_x64) -c source/ssp/ssp.c -o dist/$(BOFNAME)_ssp.x64.o $(OPTIONS) $(SSP_OPTIONS) -DBOF -DSSP
	@$(STRIP_x64) --strip-unneeded dist/$(BOFNAME)_ssp.x64.o && echo '[+] nanodump_ssp x64' || echo '[!] nanodump_ssp x64'

	@$(CC_x86) -c source/ssp/ssp.c -o dist/$(BOFNAME)_ssp.x86.o $(OPTIONS) $(SSP_OPTIONS) -DBOF -DSSP
	@$(STRIP_x86) --strip-unneeded dist/$(BOFNAME)_ssp.x86.o && echo '[+] nanodump_ssp x86' || echo '[!] nanodump_ssp x86'

	@$(CC_x64) source/utils.c source/syscalls.c source/dinvoke.c source/pipe.c source/ssp/ssp_utils.c source/ssp/ssp.c -o dist/$(BOFNAME)_ssp.x64.exe $(OPTIONS) $(SSP_OPTIONS) -DEXE -DSSP
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ssp.x64.exe

	@$(CC_x86) source/utils.c source/syscalls.c source/dinvoke.c source/pipe.c source/ssp/ssp_utils.c source/ssp/ssp.c -o dist/$(BOFNAME)_ssp.x86.exe $(OPTIONS) $(SSP_OPTIONS) -DEXE -DSSP
	@$(STRIP_x86) --strip-all dist/$(BOFNAME)_ssp.x86.exe

	@$(CC_x64) source/spoof_callstack.c source/hw_breakpoint.c source/shtinkering.c source/output.c source/ppl/cleanup.c source/utils.c source/dinvoke.c source/handle.c source/impersonate.c source/modules.c source/syscalls.c source/token_priv.c source/nanodump.c source/entry.c -o dist/$(BOFNAME)_ppl_dump.x64.dll $(OPTIONS) -DNANO -DPPL_DUMP -DDDL -shared
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ppl_dump.x64.dll && echo '[+] nanodump_ppl_dump Dll x64' || echo '[!] nanodump_ppl_dump Dll x64'
	@./dist/bin2c dist/$(BOFNAME)_ppl_dump.x64.dll $(BOFNAME)_ppl_dump_dll > include/$(BOFNAME)_ppl_dump_dll.x64.h

	@$(CC_x86) source/spoof_callstack.c source/hw_breakpoint.c source/shtinkering.c source/output.c source/ppl/cleanup.c source/utils.c source/dinvoke.c source/handle.c source/impersonate.c source/modules.c source/syscalls.c source/token_priv.c source/nanodump.c source/entry.c -o dist/$(BOFNAME)_ppl_dump.x86.dll $(OPTIONS) -DNANO -DPPL_DUMP -DDDL -shared
	@$(STRIP_x86) --strip-all dist/$(BOFNAME)_ppl_dump.x86.dll && echo '[+] nanodump_ppl_dump Dll x86' || echo '[!] nanodump_ppl_dump Dll x86'
	@./dist/bin2c dist/$(BOFNAME)_ppl_dump.x86.dll $(BOFNAME)_ppl_dump_dll > include/$(BOFNAME)_ppl_dump_dll.x86.h

	@$(CC_x64) source/utils.c source/syscalls.c source/dinvoke.c source/token_priv.c source/ppl/ppl_utils.c source/impersonate.c source/ppl/ppl.c source/ppl/ppl_dump.c -o dist/$(BOFNAME)_ppl_dump.x64.exe $(OPTIONS) -DEXE -DPPL_DUMP
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ppl_dump.x64.exe

	@$(CC_x86) source/utils.c source/syscalls.c source/dinvoke.c source/token_priv.c source/ppl/ppl_utils.c source/impersonate.c source/ppl/ppl.c source/ppl/ppl_dump.c -o dist/$(BOFNAME)_ppl_dump.x86.exe $(OPTIONS) -DEXE -DPPL_DUMP
	@$(STRIP_x86) --strip-all dist/$(BOFNAME)_ppl_dump.x86.exe

	@$(CC_x64) -c source/ppl/ppl.c -o dist/$(BOFNAME)_ppl_dump.x64.o $(OPTIONS) -DBOF -DPPL_DUMP
	@$(STRIP_x64) --strip-unneeded dist/$(BOFNAME)_ppl_dump.x64.o && echo '[+] nanodump_ppl_dump x64' || echo '[!] nanodump_ppl_dump x64'

	@$(CC_x86) -c source/ppl/ppl.c -o dist/$(BOFNAME)_ppl_dump.x86.o $(OPTIONS) -DBOF -DPPL_DUMP
	@$(STRIP_x86) --strip-unneeded dist/$(BOFNAME)_ppl_dump.x86.o && echo '[+] nanodump_ppl_dump x86' || echo '[!] nanodump_ppl_dump x86'

	@$(CC_x64) source/spoof_callstack.c source/hw_breakpoint.c source/shtinkering.c source/output.c source/ppl/cleanup.c source/utils.c source/dinvoke.c source/handle.c source/impersonate.c source/modules.c source/syscalls.c source/token_priv.c source/nanodump.c source/ppl/ppl_medic_dll.c source/pipe.c source/entry.c -o dist/$(BOFNAME)_ppl_medic.x64.dll $(OPTIONS) $(PPL_MEDIC_OPTIONS) -DNANO -DPPL_MEDIC -DDDL -shared
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ppl_medic.x64.dll && echo '[+] nanodump_ppl_medic Dll x64' || echo '[!] nanodump_ppl_medic Dll x64'
	@./dist/bin2c dist/$(BOFNAME)_ppl_medic.x64.dll $(BOFNAME)_ppl_medic_dll > include/$(BOFNAME)_ppl_medic_dll.x64.h

	@$(CC_x64) source/utils.c source/syscalls.c source/dinvoke.c source/handle.c source/token_priv.c source/ppl/ppl_utils.c source/impersonate.c source/ppl/ppl.c source/ppl/ppl_medic.c source/pipe.c source/ppl/ppl_medic_client.c -o dist/$(BOFNAME)_ppl_medic.x64.exe $(OPTIONS) $(PPL_MEDIC_OPTIONS) -DEXE -DPPL_MEDIC -DNANO
	@$(STRIP_x64) --strip-all dist/$(BOFNAME)_ppl_medic.x64.exe

	@$(CC_x64) -c source/ppl/ppl.c -o dist/$(BOFNAME)_ppl_medic.x64.o $(OPTIONS) $(PPL_MEDIC_OPTIONS) -DBOF -DPPL_MEDIC
	@$(STRIP_x64) --strip-unneeded dist/$(BOFNAME)_ppl_medic.x64.o && echo '[+] nanodump_ppl_medic x64' || echo '[!] nanodump_ppl_medic x64'

	@$(GCC) source/restore_signature.c -o scripts/restore_signature -Os

clean:
	@rm -f dist/*
