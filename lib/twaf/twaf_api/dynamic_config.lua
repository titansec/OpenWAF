
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local twaf_func = require "lib.twaf.inc.twaf_func"

_M.api = {}
_M.help = {}
_M.api.dynamic_config = {}

-- get dynamic config e.g: GET host/path/dynamic_config
_M.api.dynamic_config.get  = function(_twaf, log, u)
    local result = {}
    local config = _twaf.config
    
    result.twaf_policy      = config.twaf_policy
    result.twaf_access_rule = config.twaf_access_rule
    
    log.result = result
    
    return
end

-- post dynamic config e.g: POST host/path/dynamic_config
_M.api.dynamic_config.post = function(_twaf, log, u)

-- check request body
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    if type(data.config) ~= "table" then
        log.success = 0
        log.reason  = "rules: table expected, got "..type(data.config)
        return
    end
    
    if data.config.twaf_access_rule == nil or
       data.config.twaf_policy      == nil then
        log.success = 0
        log.reason  = "Wrong dynamic config"
        return false
    end
    
    local config = _twaf.config
    local p_conf = twaf_func:syn_config_process(_twaf, data.config)
    
    config.twaf_access_rule = p_conf.twaf_access_rule
    config.twaf_policy      = p_conf.twaf_policy
    
    log.result = p_conf
    return
end

_M.help.dynamic_config = {
    "GET host/path/access_rule/{user}/{uuid}",
    "POST host/path/access_rule/{user}/{pos}",
    "POST host/path/access_rule/{user}/uuid/{uuid}",
    "PUT host/path/access_rule/{user}/{uuid}",
    "DELETE host/path/access_rule/{user}/{uuid}"
}
    
return _M