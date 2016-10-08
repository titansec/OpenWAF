/*
* city.c: Bindings for MaxMind's GeoIP library
*              See copyright information in file COPYRIGHT.
*/

#include <fcntl.h>

#include "lua-geoip.h"
#include "database.h"

#define LUAGEOIP_CITY_VERSION     "lua-geoip.city 0.1.1"
#define LUAGEOIP_CITY_COPYRIGHT   "Copyright (C) 2011, lua-geoip authors"
#define LUAGEOIP_CITY_DESCRIPTION \
        "Bindings for MaxMind's GeoIP library (city database)"

static GeoIP * check_city_db(lua_State * L, int idx)
{
  int type = 0;
  luageoip_DB * pDB = (luageoip_DB *)luaL_checkudata(L, idx, LUAGEOIP_CITY_MT);
  if (pDB == NULL)
  {
    lua_pushstring(L, "lua-geoip error: city db is null");
    return NULL;
  }

  if (pDB->pGeoIP == NULL)
  {
    lua_pushstring(L, "lua-geoip error: attempted to use closed city db");
    return NULL;
  }

  type = GeoIP_database_edition(pDB->pGeoIP);
  if (
      type != GEOIP_CITY_EDITION_REV0 &&
      type != GEOIP_CITY_EDITION_REV1
    )
  {
    lua_pushstring(L, "lua-geoip error: object is not a city db");
    return NULL;
  }

  return pDB->pGeoIP;
}

/* TODO: Generalize copy-paste with country code */
static int push_city_info(
    lua_State * L,
    int first_arg_idx,
    GeoIPRecord * pRecord
  )
{
  static const int NUM_OPTS = 13;
  static const char * const opts[] =
  {
    /* order is important! */
    /*  0 */ "country_code",
    /*  1 */ "country_code3",
    /*  2 */ "country_name",
    /*  3 */ "region",
    /*  4 */ "city",
    /*  5 */ "postal_code",
    /*  6 */ "latitude",
    /*  7 */ "longitude",
    /*  8 */ "metro_code",
    /*  9 */ "dma_code",
    /* 10 */ "area_code",
    /* 11 */ "charset",
    /* 12 */ "continent_code",
    NULL
  };

  int nargs = lua_gettop(L) - first_arg_idx + 1;
  int need_all = (nargs == 0);

  int i = 0;

  if (pRecord == NULL)
  {
    lua_pushnil(L);
    lua_pushliteral(L, "not found");
    return 2;
  }

  if (need_all)
  {
    nargs = NUM_OPTS;
    lua_newtable(L);
  }

  for (i = 0; i < nargs; ++i)
  {
    int idx = (need_all)
      ? i
      : luaL_checkoption(L, first_arg_idx + i, NULL, opts)
      ;

    /* TODO: Ugly */
    switch (idx)
    {
      case 0:  /* "country_code" */
        lua_pushstring(L, pRecord->country_code);
        break;

      case 1:  /* "country_code3" */
        lua_pushstring(L, pRecord->country_code3);
        break;

      case 2:  /* "country_name" */
        lua_pushstring(L, pRecord->country_name);
        break;

      case 3:  /* "region" */
        lua_pushstring(L, pRecord->region);
        break;

      case 4:  /* "city" */
        lua_pushstring(L, pRecord->city);
        break;

      case 5:  /* "postal_code" */
        lua_pushstring(L, pRecord->postal_code);
        break;

      case 6:  /* "latitude" */
        lua_pushnumber(L, pRecord->latitude);
        break;

      case 7:  /* "longitude" */
        lua_pushnumber(L, pRecord->longitude);
        break;

      case 8:  /* "metro_code" */
        lua_pushinteger(L, pRecord->metro_code);
        break;

      case 9:  /* "dma_code" */
        lua_pushinteger(L, pRecord->dma_code);
        break;

      case 10: /* "area_code" */
        lua_pushinteger(L, pRecord->area_code);
        break;

      case 11: /* "charset" */
        lua_pushinteger(L, pRecord->charset);
        break;

      case 12: /* "continent_code" */
        lua_pushstring(L, pRecord->continent_code);
        break;

      default:
        /* Hint: Did you synchronize switch cases with opts array? */
        return luaL_error(L, "lua-geoip error: bad implementation");
    }

    if (need_all)
    {
      lua_setfield(L, -2, opts[i]);
    }
  }

  GeoIPRecord_delete(pRecord);

  return (need_all) ? 1 : nargs;
}

/* TODO: Remove copy-paste below! */

static int lcity_query_by_name(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  const char * name = luaL_checkstring(L, 2);

  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  return push_city_info(
      L, 3, GeoIP_record_by_name(pGeoIP, name)
    );
}

static int lcity_query_by_addr(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  const char * addr = luaL_checkstring(L, 2);

  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  return push_city_info(
      L, 3, GeoIP_record_by_addr(pGeoIP, addr)
    );
}

static int lcity_query_by_ipnum(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  lua_Integer ipnum = luaL_checkinteger(L, 2); /* Hoping that value would fit */

  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  return push_city_info(
      L, 3, GeoIP_record_by_ipnum(pGeoIP, ipnum)
    );
}

static int lcity_charset(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  lua_pushinteger(L, GeoIP_charset(pGeoIP));

  return 1;
}

static int lcity_set_charset(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  int charset = luaL_checkint(L, 2);

  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  GeoIP_set_charset(pGeoIP, charset);

  return 0;
}

static int lcity_close(lua_State * L)
{
  luageoip_DB * pDB = (luageoip_DB *)luaL_checkudata(L, 1, LUAGEOIP_CITY_MT);

  if (pDB && pDB->pGeoIP != NULL)
  {
    GeoIP_delete(pDB->pGeoIP);
    pDB->pGeoIP = NULL;
  }

  return 0;
}

#define lcity_gc lcity_close

static int lcity_tostring(lua_State * L)
{
  GeoIP * pGeoIP = check_city_db(L, 1);
  if (pGeoIP == NULL)
  {
    return lua_error(L); /* Error message already on stack */
  }

  lua_pushstring(L, GeoIP_database_info(pGeoIP));

  return 1;
}

static const luaL_Reg M[] =
{
  { "query_by_name", lcity_query_by_name },
  { "query_by_addr", lcity_query_by_addr },
  { "query_by_ipnum", lcity_query_by_ipnum },

  { "charset", lcity_charset },
  { "set_charset", lcity_set_charset },
  { "close", lcity_close },
  { "__gc", lcity_gc },
  { "__tostring", lcity_tostring },

  { NULL, NULL }
};

static int lcity_open(lua_State * L)
{
  static const int allowed_types[] =
  {
    GEOIP_CITY_EDITION_REV0,
    GEOIP_CITY_EDITION_REV1
  };

  return luageoip_common_open_db(
      L,
      M,
      GEOIP_CITY_EDITION_REV1,
      GEOIP_MEMORY_CACHE,
      LUAGEOIP_CITY_MT,
      0, /* all flags allowed */
      2,
      allowed_types
    );
}

/* Lua module API */
static const struct luaL_Reg R[] =
{
  { "open", lcity_open },

  { NULL, NULL }
};

#ifdef __cplusplus
extern "C" {
#endif

LUALIB_API int luaopen_geoip_city(lua_State * L)
{
  /*
  * Register module
  */
#if !defined(LUA_VERSION_NUM) || LUA_VERSION_NUM < 502
  luaL_register(L, "geoip.city", R);
#else
  lua_newtable(L);
  luaL_setfuncs(L, R, 0);
#endif

  /*
  * Register module information
  */
  lua_pushliteral(L, LUAGEOIP_CITY_VERSION);
  lua_setfield(L, -2, "_VERSION");

  lua_pushliteral(L, LUAGEOIP_CITY_COPYRIGHT);
  lua_setfield(L, -2, "_COPYRIGHT");

  lua_pushliteral(L, LUAGEOIP_CITY_DESCRIPTION);
  lua_setfield(L, -2, "_DESCRIPTION");

  return 1;
}

#ifdef __cplusplus
}
#endif
