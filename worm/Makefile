CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lssh

worm: worm.c
	$(CC) $(CFLAGS) worm.c -o worm $(LDFLAGS)

clean:
	rm -f worm

.PHONY: clean
