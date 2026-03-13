CC      = x86_64-w64-mingw32-gcc
SRC_DIR = src
OUTDIR  = _bin

CFLAGS  = -O2 -masm=intel -Wall -nostdlib \
          -fno-asynchronous-unwind-tables -fno-ident \
          -Wl,--enable-stdcall-fixup

BOFS = $(OUTDIR)/etw_enum_bof.x64.o \
       $(OUTDIR)/etw_disable_bof.x64.o

all: banner $(OUTDIR) $(BOFS)

banner:
	@echo "# 64-bit builds"

$(OUTDIR):
	@echo "creating _bin directory"
	@mkdir -p $(OUTDIR)

$(OUTDIR)/etw_enum_bof.x64.o: $(SRC_DIR)/etw_enum_bof.c $(SRC_DIR)/etw_ti_bof.c | $(OUTDIR)
	@$(CC) $(CFLAGS) -c $(SRC_DIR)/etw_enum_bof.c -o $@
	@echo "[+] etw_enum"

$(OUTDIR)/etw_disable_bof.x64.o: $(SRC_DIR)/etw_disable_bof.c $(SRC_DIR)/etw_ti_bof.c | $(OUTDIR)
	@$(CC) $(CFLAGS) -c $(SRC_DIR)/etw_disable_bof.c -o $@
	@echo "[+] etw_disable"

clean:
	@rm -f $(OUTDIR)/*.o

.PHONY: all clean banner
