# Source code for ISA project.
# file: Makefile
# 
# (C) Patrik Ondriga (xondri08) 

CC=gcc
CFLAGS=-lm -lpcap -g
DEPS = sslParser.h my_ssl.h
OBJ = sslsniff.o sslParser.o my_ssl.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

sslsniff: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o sslsniff
