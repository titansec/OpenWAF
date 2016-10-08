Name
====

lua-resty-libinjection - LuaJIT FFI bindings for libinjection

Status
======

This library is in active development and is production ready

Description
===========

This library provides FFI bindings for [libinjection](https://github.com/client9/libinjection/), a SQL/SQLi and XSS tokenizer and analyzer.

Installation
============

Install this library as you would any other OpenResty lua module. The libinjection shared object file is required to live in your [lua_package_cpath](https://github.com/openresty/lua-nginx-module#lua_package_cpath), so you should symlink or copy the .so file to the appropriate location. For convenience a copy has been placed in the `lib` directory of this repo.

Synopsis
========

```lua
  access_by_lua_block {
    local libinjection = require "resty.libinjection"

    -- simple SQLi API
    local issqli, fingerprint = libinjection.sqli(string)

    -- context-specific bindings are also provided
    issqli, fingerprint = libinjection.sqli_noquote(string)
    issqli, fingerprint = libinjection.sqli_singlequote(string)
    issqli, fingerprint = libinjection.sqli_doublequote(string)

	--simple XSS API
	local isxss = libinjection.xss(string)

	-- context-specific bindings
	isxss = libinjection.xss_data_state(string)
	isxss = libinjection.xss_noquote(string)
	isxss = libinjection.xss_singlequote(string)
	isxss = libinjection.xss_doublequote(string)
	isxss = libinjection.xss_backquote(string)
  }
```

Usage
=====

libinjection.sqli
-----------------

**syntax**: *issqli, fingerprint = libinjection.sqli(string)*

Given a string, returns a boolean *issqli* representing if SQLi was detected, and a string *fingerprint* representing the libinjection fingerprint detected. In most cases, this is the preferable option; second-level API bindings noted below may be slightly more efficient in specific contexts.

libinjection.sqli_noquote
-------------------------

**syntax**: *issqli, fingerprint = libinjection.sqli_noquote(string)*

Like [libinjection.sqli](#libinjectionsqli), in the specific context of an "as-is" string.

libinjection.sqli_singlequote
-----------------------------

**syntax**: *issqli, fingerprint = libinjection.sqli_singlequote(string)*

Like [libinjection.sqli](#libinjectionsqli), in the specific context of a single-quoted (`'`) string.

libinjection.sqli_doublequote
-----------------------------

**syntax**: *issqli, fingerprint = libinjection.sqli_doublelequote(string)*

Like [libinjection.sqli](#libinjectionsqli), in the specific context of a double-quoted (`"`) string.

libinjection.xss
----------------

**syntax**: *isxss = libinjection.xss(string)*

ALPHA version of XSS detector. Given a string, returns a boolean *isxss* denoting if XSS was detected. In most cases, this is the preferable option; second-level API bindings noted below may be slight more efficient in specific contexts.

libinjection.xss_data_state
---------------------------

**syntax**: *isxss = libinjection.xss_data_state(string)*

Like [libinjection.xss](#libinjectionxss), but run with only the DATA_STATE flag.

libinjection.xss_noquote
------------------------

**syntax**: *isxss = libinjection.xss_noquote(string)*

Like [libinjection.xss](#libinjectionxss), but run with only the VALUE_NO_QUOTE flag.

libinjection.xss_singlequote
----------------------------

**syntax**: *isxss = libinjection.xss_singlequote(string)*

Like [libinjection.xss](#libinjectionxss), but run with only the VALUE_SINGLE_QUOTE flag.

libinjection.xss_doublequote
----------------------------

**syntax**: *isxss = libinjection.xss_doublequote(string)*

Like [libinjection.xss](#libinjectionxss), but run with only the VALUE_DOUBLE_QUOTE flag.

libinjection.xss_backquote
--------------------------

**syntax**: *isxss = libinjection.xss_backquote(string)*

Like [libinjection.xss](#libinjectionxss), but run with only the VALUE_BACK_QUOTE flag.

License
=======

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/

Bugs
====

Please report bugs by creating a ticket with the GitHub issue tracker.
