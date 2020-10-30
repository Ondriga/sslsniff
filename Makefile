CC=gcc
CFLAGS= -lm
DEPS = sslParser.h
OBJ = sslsniff.o sslParser.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

sslsniff: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o sslsniff
