CC = gcc
SO_LIBS=transforms.so
CFLAGS=-fpic -Wall -O3
LFLAGS=-shared

all: $(SO_LIBS)

$(SO_LIBS): transforms.c
	$(CC) -o $(SO_LIBS) $(CFLAGS) $(LFLAGS) transforms.c

install: $(SO_LIBS)
	cp $(SO_LIBS) $(DESTDIR)

clean:
	rm -f $(SO_LIBS) *.o