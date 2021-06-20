
CC=gcc
CFLAGS=-Ofast -Wall -std=gnu11

.PHONY: all clean sbench

all: libspooky.a sbench scorrect

spooky.o: spooky.c | spooky.h
	$(CC) $(CFLAGS) $^ -c -I. -o $@

SAN=-fsanitize=undefined -fsanitize=address

spooky_ubsan.o: spooky.c | spooky.h
	$(CC) -std=gnu11 -Wall -Wpedantic -I. -c $(SAN)  $^ -o $@

libspooky.a: spooky.o
	ar rcs $@ $^

sbench.o: sbench.c | spooky.h
	$(CC) $(CFLAGS) $^ -c -I. -o $@

sbench: sbench.o spooky.o
	$(CC) $(CFLAGS) $^ -o $@

scorrect: scorrect.o spooky_ubsan.o
	$(CC) $(CFLAGS) $^ $(SAN) -static-libasan -o $@

clean:
	rm -f *.a *.o sbench scorrect

