CC=gcc
#CFLAGS=-Wall -Wextra -Werror -pedantic -O3 -g -pthread
CFLAGS=-Wall
LIBS=-lm -lssl -lcrypto

test: token.o tools.o test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)
tools.o : tools.h tools.c token.h
	$(CC) $(CFLAGS) -o tools.o -c tools.c
token.o : token.c tools.h token.h
	$(CC) $(CFLAGS) -o token.o -c token.c
test.o : tools.h token.h test.c
	$(CC) $(CFLAGS) -o test.o -c test.c

clean :
	rm -rf test *.o
