
CC=gcc
CFLAGS=-Ofast -Wall -std=gnu11

.PHONY: all clean sbench

all: libspooky.a sbench

spooky.o: spooky.c | spooky.h
	$(CC) $(CFLAGS) $^ -c -I. -o $@

libspooky.a: spooky.o
	ar rcs $@ $^

sbench.o: sbench.c | spooky.h
	$(CC) $(CFLAGS) $^ -c -I. -o $@

sbench: sbench.o | libspooky.a
	$(CC) $(CFLAGS) $^ -L. -lspooky -o $@

clean:
	rm -f libspooky.a spooky.o sbench

