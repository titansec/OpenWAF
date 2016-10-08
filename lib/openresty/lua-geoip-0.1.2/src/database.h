/*
* database.h: Bindings for MaxMind's GeoIP library
*              See copyright information in file COPYRIGHT.
*/

#ifndef LUAGEOIP_DATABASE_H_
#define LUAGEOIP_DATABASE_H_

#define LUAGEOIP_COUNTRY_MT "lua-geoip.db.country"
#define LUAGEOIP_CITY_MT "lua-geoip.db.city"

int luageoip_common_open_db(
    lua_State * L,
    const luaL_Reg * M,
    int default_type,
    int default_flags,
    const char * mt_name,
    unsigned int bad_flags,
    size_t num_allowed_types,
    const int * allowed_types
  );

#endif /* LUAGEOIP_DATABASE_H_ */
