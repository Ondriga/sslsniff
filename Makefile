CC=gcc
CFLAGS=-lm -lpcap
DEPS = sslParser.h my_ssl.h
OBJ = sslsniff.o sslParser.o my_ssl.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

sslsniff: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o sslsniff
