/*
* lua-geoip.c: Bindings for MaxMind's GeoIP library
*              See copyright information in file COPYRIGHT.
*/

#define LUAGEOIP_VERSION     "lua-geoip 0.1.1"
#define LUAGEOIP_COPYRIGHT   "Copyright (C) 2011, lua-geoip authors"
#define LUAGEOIP_DESCRIPTION "Bindings for MaxMind's GeoIP library"

#include "lua-geoip.h"

typedef struct luageoip_Enum
{
  const char * name;
  const int value;
} luageoip_Enum;

static const struct luageoip_Enum Options[] =
{
  { "STANDARD", GEOIP_STANDARD },
  { "MEMORY_CACHE", GEOIP_MEMORY_CACHE },
  { "CHECK_CACHE", GEOIP_CHECK_CACHE },
  { "INDEX_CACHE", GEOIP_INDEX_CACHE },
  { "MMAP_CACHE", GEOIP_MMAP_CACHE },
  { NULL, 0 }
};

static const struct luageoip_Enum DBTypes[] =
{
  { "COUNTRY", GEOIP_COUNTRY_EDITION }, /* Note that this is not an alias */
  { "COUNTRY_V6",GEOIP_COUNTRY_EDITION_V6 },

  { "REGION_REV0", GEOIP_REGION_EDITION_REV0 },
  { "REGION_REV1", GEOIP_REGION_EDITION_REV1 },
  { "REGION", GEOIP_REGION_EDITION_REV1 }, /* Alias */

  { "CITY_REV0", GEOIP_CITY_EDITION_REV0 },
  { "CITY_REV1", GEOIP_CITY_EDITION_REV1 },
  { "CITY", GEOIP_CITY_EDITION_REV1 }, /* Alias */

  { "ORG", GEOIP_ORG_EDITION },
  { "ISP", GEOIP_ISP_EDITION },
  { "PROXY", GEOIP_PROXY_EDITION },
  { "ASNUM", GEOIP_ASNUM_EDITION },
  { "NETSPEED", GEOIP_NETSPEED_EDITION },
  { "DOMAIN", GEOIP_DOMAIN_EDITION },

  { NULL, 0 }
};

static const struct luageoip_Enum Charsets[] =
{
  { "ISO_8859_1", GEOIP_CHARSET_ISO_8859_1 },
  { "UTF8", GEOIP_CHARSET_UTF8 },
  { NULL, 0 }
};

static void reg_enum(lua_State * L, const luageoip_Enum * e)
{
  for ( ; e->name; ++e)
  {
    lua_pushinteger(L, e->value);
    lua_setfield(L, -2, e->name);
  }
}

static int lcode_by_id(lua_State * L)
{
  int id = luaL_checkint(L, 1);
  lua_pushstring(L, GeoIP_code_by_id(id));
  return 1;
}

static int lcode3_by_id(lua_State * L)
{
  int id = luaL_checkint(L, 1);
  lua_pushstring(L, GeoIP_code3_by_id(id));
  return 1;
}

static int lname_by_id(lua_State * L)
{
  int id = luaL_checkint(L, 1);
  lua_pushstring(L, GeoIP_name_by_id(id));
  return 1;
}

static int lcontinent_by_id(lua_State * L)
{
  int id = luaL_checkint(L, 1);
  lua_pushstring(L, GeoIP_continent_by_id(id));
  return 1;
}

static int lid_by_code(lua_State * L)
{
  const char * country = luaL_checkstring(L, 1);
  lua_pushinteger(L, GeoIP_id_by_code(country));
  return 1;
}

static int lregion_name_by_code(lua_State * L)
{
  const char * country_code = luaL_checkstring(L, 1);
  const char * region_code = luaL_checkstring(L, 2);
  lua_pushstring(L, GeoIP_region_name_by_code(country_code, region_code));
  return 1;
}

static int ltime_zone_by_country_and_region(lua_State * L)
{
  const char * country_code = luaL_checkstring(L, 1);
  const char * region_code = luaL_checkstring(L, 2);
  lua_pushstring(
      L,
      GeoIP_time_zone_by_country_and_region(country_code, region_code)
    );
  return 1;
}

/* Lua module API */
static const struct luaL_Reg R[] =
{
  { "code_by_id", lcode_by_id },
  { "code3_by_id", lcode3_by_id },
  { "name_by_id", lname_by_id },
  { "continent_by_id", lcontinent_by_id },
  { "id_by_code", lid_by_code },
  { "region_name_by_code", lregion_name_by_code },
  { "time_zone_by_country_and_region", ltime_zone_by_country_and_region },

  { NULL, NULL }
};

#ifdef __cplusplus
extern "C" {
#endif

LUALIB_API int luaopen_geoip_geoip(lua_State * L)
{
  /*
  * Register module
  */

#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
  luaL_register(L, "geoip", R);
#else
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
#endif

  /*
  * Register module information
  */
  lua_pushliteral(L, LUAGEOIP_VERSION);
  lua_setfield(L, -2, "_VERSION");

  lua_pushliteral(L, LUAGEOIP_COPYRIGHT);
  lua_setfield(L, -2, "_COPYRIGHT");

  lua_pushliteral(L, LUAGEOIP_DESCRIPTION);
  lua_setfield(L, -2, "_DESCRIPTION");

  /*
  * Register enums
  */
  reg_enum(L, Options);
  reg_enum(L, DBTypes);
  reg_enum(L, Charsets);

  return 1;
}

#ifdef __cplusplus
}
#endif
