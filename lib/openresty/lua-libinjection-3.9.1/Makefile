
SUBDIRS=src

LUA_VERSION =      5.1
TARGET =           libinjection.so
PREFIX ?=          /usr/local
LUA_LIB_DIR ?=     $(PREFIX)/lib/lua/$(LUA_VERSION)
EXECPERM =         755

install:
	(cd lua; $(MAKE))
	 mkdir -p $(DESTDIR)/$(LUA_LIB_DIR)
	 rm -f $(DESTDIR)/$(LUA_LIB_DIR)/$(TARGET)
	 cp lua/$(TARGET) $(DESTDIR)/$(LUA_LIB_DIR)
	 chmod $(EXECPERM) $(DESTDIR)/$(LUA_LIB_DIR)/$(TARGET)
	
all:
	(cd src; ${MAKE} all)
check:
	(cd src; ${MAKE} check)
clean:
	(cd src; ${MAKE} clean)

#.PHONY: all check clean
.PHONY: install
