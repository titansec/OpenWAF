CC = gcc
SO_LIBS=decode.so
CFLAGS=-fpic -Wall -O3
LFLAGS=-shared

all: $(SO_LIBS)

$(SO_LIBS): decode.c
	$(CC) -o $(SO_LIBS) $(CFLAGS) $(LFLAGS) decode.c

install: $(SO_LIBS)
	cp $(SO_LIBS) $(DESTDIR)

clean:
	rm -f $(SO_LIBS) *.o