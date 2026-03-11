CC      = x86_64-w64-mingw32-gcc
SRC_DIR = src
OUTDIR  = _bin

CFLAGS  = -O2 -masm=intel -Wall -nostdlib \
          -fno-asynchronous-unwind-tables -fno-ident \
          -Wl,--enable-stdcall-fixup

BOFS = $(OUTDIR)/ppenum_bof.x64.o \
       $(OUTDIR)/pppatch_bof.x64.o

all: banner $(OUTDIR) $(BOFS)

banner:
	@echo "# 64-bit builds"

$(OUTDIR):
	@echo "creating _bin directory"
	@mkdir -p $(OUTDIR)

$(OUTDIR)/ppenum_bof.x64.o: $(SRC_DIR)/ppenum_bof.c | $(OUTDIR)
	@$(CC) $(CFLAGS) -c $(SRC_DIR)/ppenum_bof.c -o $@
	@echo "[+] ppenum"

$(OUTDIR)/pppatch_bof.x64.o: $(SRC_DIR)/pppatch_bof.c | $(OUTDIR)
	@$(CC) $(CFLAGS) -c $(SRC_DIR)/pppatch_bof.c -o $@
	@echo "[+] pppatch"

clean:
	@rm -f $(OUTDIR)/*.o

.PHONY: all clean banner
