CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude
LDFLAGS = -lssl -lcrypto
TARGET  = implant
SRCS    = src/main.c src/crypto.c src/shell.c src/evasion.c
EXTRA_OBJS = grid.o

$(TARGET): $(SRCS) $(EXTRA_OBJS)
	$(CC) $(CFLAGS) $(SRCS) $(EXTRA_OBJS) -o $(TARGET) $(LDFLAGS)

grid.o: grid.bin
	objcopy --input-target binary \
	        --output-target elf64-x86-64 \
	        --binary-architecture i386:x86-64 \
	        grid.bin grid.o

clean:
	rm -f $(TARGET) $(EXTRA_OBJS)