OPENWAF_PREFIX = $(PWD)
SRCDIR  = $(OPENWAF_PREFIX)/lib/openresty
DESTDIR = $(OPENWAF_PREFIX)/lib/resty

CC = gcc
CFLAGS=-fpic -Wall -O3
LFLAGS=-shared

SO_LIBS = transforms.so
MAKE_LIBS = transforms
INSTALL_LIBS = install-transforms
CLEAN_LIBS = clean-transforms

all: $(MAKE_LIBS)

transforms: 
	cd $(SRCDIR)/transforms && make


clean: $(CLEAN_LIBS)

clean-libs:
	cd $(DESTDIR) && rm $(SO_LIBS)

clean-transforms:
	cd $(SRCDIR)/transforms && make clean


install: $(INSTALL_LIBS) install-check

install-transforms:
	cd $(SRCDIR)/transforms && make install DESTDIR=$(DESTDIR)

install-check:
	stat $(DESTDIR)/*.so > /dev/null