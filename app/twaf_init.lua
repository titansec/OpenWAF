--init

require "resty.core"

-- construct a new object - twaf_config
local twaf_config_m = require "lib.twaf.twaf_conf"
twaf_config = twaf_config_m:new()
twaf_config:load_default_config("/usr/local/openresty/lualib/openwaf/conf")
twaf_config:load_access_rule("/usr/local/openresty/lualib/openwaf/conf")
twaf_config:load_policy_config("/usr/local/openresty/lualib/openwaf/conf",
                               {twaf_global_conf = 1, twaf_policy_conf = 1})
twaf_config:load_rules()

-- GeoIP 
twaf_config:load_geoip_country_ipv4("/usr/local/openresty/lualib/openwaf/lib/twaf/inc/knowledge_db/geo_country/GeoIP.dat")
twaf_config:load_geoip_country_ipv6("/usr/local/openresty/lualib/openwaf/lib/twaf/inc/knowledge_db/geo_country/GeoIPv6.dat")

local twaf_reqstat_m = require "lib.twaf.twaf_reqstat"
twaf_reqstat = twaf_reqstat_m:new(twaf_config.twaf_default_conf.twaf_reqstat, twaf_config.twaf_policy.policy_uuids)

-- construct a new object - twaf
local twaf_lib = require "lib.twaf.twaf_core"
twaf = twaf_lib:new(twaf_config)

local default_init_register = twaf:get_default_config_param("init_register")
twaf:register_modules(default_init_register)
