CC      = x86_64-w64-mingw32-gcc
SRC_DIR = src
BIN_DIR = _bin

CFLAGS  = -O2 -masm=intel -Wall \
           -nostdlib -fno-asynchronous-unwind-tables \
           -fno-ident \
           -Wl,--enable-stdcall-fixup

BOFS = $(BIN_DIR)/list_callbacks_bof.x64.o \
       $(BIN_DIR)/remove_callback_bof.x64.o

all: banner $(BOFS)

banner:
	@echo "# 64-bit builds"

$(BIN_DIR)/list_callbacks_bof.x64.o: $(SRC_DIR)/list_callbacks_bof.c | $(BIN_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "[+] list_callbacks"

$(BIN_DIR)/remove_callback_bof.x64.o: $(SRC_DIR)/remove_callback_bof.c | $(BIN_DIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "[+] remove_callback"

$(BIN_DIR):
	@echo "creating _bin directory"
	@mkdir -p $(BIN_DIR)

clean:
	@rm -f $(BIN_DIR)/*.o
