CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc
CFLAGS = -c -Wall -masm=intel
LDFLAGS = -lpsapi -limagehlp -ldbghelp  # Correção: Adicionando -ldbghelp

SRC = BOF_Mockingjay.c
OUT_DIR = bin
OBJ_x64 = $(OUT_DIR)/BOF_Mockingjay.x64.o
OBJ_x86 = $(OUT_DIR)/BOF_Mockingjay.x86.o

all: $(OBJ_x64) $(OBJ_x86)

$(OBJ_x64): $(SRC)
	@mkdir -p $(OUT_DIR)
	$(CC_x64) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(OBJ_x86): $(SRC)
	@mkdir -p $(OUT_DIR)
	$(CC_x86) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(OUT_DIR)
