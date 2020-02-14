--init

require "resty.core"
local errlog = require "ngx.errlog"
errlog.set_filter_level(ngx.WARN)

-- construct a new object - twaf_config
local twaf_config_m = require "lib.twaf.twaf_conf"
local twaf_config = twaf_config_m:new()
twaf_config:load_default_config("/opt/OpenWAF/conf/twaf_default_conf.json")
twaf_config:load_access_rule("/opt/OpenWAF/conf/twaf_access_rule.json")
twaf_config:load_policy_config("/opt/OpenWAF/conf", {twaf_policy_conf = 1})
twaf_config:load_rules()

-- GeoIP 
twaf_config:load_geoip_country_ipv4("/opt/OpenWAF/lib/twaf/inc/knowledge_db/geo_country/GeoIP.dat")
twaf_config:load_geoip_country_ipv6("/opt/OpenWAF/lib/twaf/inc/knowledge_db/geo_country/GeoIPv6.dat")

local twaf_reqstat_m = require "lib.twaf.twaf_reqstat"
twaf_reqstat = twaf_reqstat_m:new(twaf_config.twaf_default_conf.twaf_reqstat, twaf_config.twaf_policy.policy_uuids)

-- construct a new object - twaf
local twaf_lib = require "lib.twaf.twaf_core"
twaf = twaf_lib:new(twaf_config)

twaf:init()
