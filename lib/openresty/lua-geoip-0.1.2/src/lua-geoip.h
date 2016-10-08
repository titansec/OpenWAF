/*
* lua-geoip.h: Bindings for MaxMind's GeoIP library
*              See copyright information in file COPYRIGHT.
*/

#ifndef LUAGEOIP_LUA_GEOIP_H_
#define LUAGEOIP_LUA_GEOIP_H_

#if defined (__cplusplus)
extern "C" {
#endif

#include <lua.h>
#include <lauxlib.h>

#ifndef luaL_checkint
#define luaL_checkint(L,n) luaL_checkinteger(L,n)
#endif

#ifndef luaL_optint
#define luaL_optint(L,n,s) luaL_optinteger(L,n,s)
#endif

#if defined (__cplusplus)
}
#endif

#include <GeoIP.h>
#include <GeoIPCity.h>

typedef struct luageoip_DB
{
  GeoIP * pGeoIP;
} luageoip_DB;

#endif /* LUAGEOIP_LUA_GEOIP_H */
