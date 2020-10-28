CC=gcc
CFLAGS= -lm
DEPS =
OBJ = sslsniff.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

sslsniff: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o sslsniff
