LUA_VERSION=5.1
PREFIX?=/usr/local
INSTALL?= install
LUA_LIB_DIR?=$(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_FLAGS=-I$(LUA_INCLUDE_DIR)
CFLAGS=-Wall -fPIC -O3

all: prepare geoip/geoip.so geoip/country.so geoip/city.so

prepare:
	mkdir -p geoip

geoip/geoip.so: src/database.o src/lua-geoip.o
geoip/country.so: src/database.o src/country.o
geoip/city.so: src/database.o src/city.o

.c.o:
	$(CC) $(CFLAGS) $(LUA_FLAGS) -Isrc/ -c $^ -o $@

%.so:
	$(CC) -shared -lGeoIP $^ -o $@

install: all
	$(INSTALL) -d $(DESTDIR)/$(LUA_LIB_DIR)/geoip
	$(INSTALL) geoip/* $(DESTDIR)/$(LUA_LIB_DIR)/geoip
    
clean:
	rm -rf geoip
	rm -f src/*.o

.SUFFIXES: .c .o .so
