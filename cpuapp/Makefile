# Makefile for compiling and running a C program

# Compiler to use
CC=gcc

# Flags to pass to the compiler
CFLAGS=-Wall

# Libraries to link
LDFLAGS=-lssl -lcrypto

# Name of the executable to create
TARGET=myprogram

all: $(TARGET)

$(TARGET): verify_hash.c
	$(CC) $(CFLAGS) -o $(TARGET) verify_hash.c $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

