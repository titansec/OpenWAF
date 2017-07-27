OPENWAF_PREFIX = $(PWD)
SRCDIR  = $(OPENWAF_PREFIX)/lib/openresty
DESTDIR = $(OPENWAF_PREFIX)/lib/resty

CC = gcc
CFLAGS=-fpic -Wall -O3
LFLAGS=-shared

SO_LIBS = decode.so
MAKE_LIBS = decode
INSTALL_LIBS = install-decode
CLEAN_LIBS = clean-decode

all: $(MAKE_LIBS)

decode: 
	cd $(SRCDIR)/decode && make


clean: $(CLEAN_LIBS)

clean-libs:
	cd $(DESTDIR) && rm $(SO_LIBS)

clean-decode:
	cd $(SRCDIR)/decode && make clean


install: $(INSTALL_LIBS) install-check

install-decode:
	cd $(SRCDIR)/decode && make install DESTDIR=$(DESTDIR)

install-check:
	stat $(DESTDIR)/*.so > /dev/null