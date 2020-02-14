
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.1"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local cjson     = require "cjson.safe"
local back_path = "/opt/OpenWAF/conf/dynamic_conf_back.json"

_M.api = {}
_M.help = {}
_M.api.dynamic_config = {}
_M.api.dynamic_config_back = {}

-- get dynamic config e.g: GET /api/dynamic_config
_M.api.dynamic_config.get  = function(_twaf, log, u)
    local result = {}
    local config = _twaf.config
    
    result.twaf_policy       = config.twaf_policy
    result.twaf_access_rule  = config.twaf_access_rule
  --result.rules             = config.rules
  --result.rules_id          = config.rules_id
    result.rule_sets         = config.rule_sets
  --result.twaf_default_conf = config.twaf_default_conf
    result.pset              = config.pset
    
    local f, err = io.open(back_path, "w+")
    if not f then 
        log.success = 0
        log.reason  = err
        return
    end
    
    f:write(twaf_func:table_to_string(result))
    f:close()
    
    log.result = result
    
    return
end

-- post dynamic config e.g: POST /api/dynamic_config
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
    
    for k, v in pairs(p_conf) do
        config[k] = v
    end
    
    log.result = p_conf
    return
end

-- post dynamic config back file e.g: POST /api/dynamic_config_back
_M.api.dynamic_config_back.post = function(_twaf, log, u)

    local f, err = io.open(back_path)
    if not f then 
        log.success = 0
        log.reason  = err
        return
    end
    
    local data = f:read("*a")
    if not data then 
        f:close()
        log.success = 0
        log.reason  = "f:read is nil"
        return
    end
    
    f:close()
    
    local res, config = pcall(cjson.decode, data)
    if not res or type(config) ~= "table" then
        log.success = 0
        log.reason  = "json expected, got " .. (data or "nil")
        return
    end
    
    if config.twaf_access_rule == nil or
       config.twaf_policy      == nil then
        log.success = 0
        log.reason  = "Wrong dynamic config"
        return
    end
    
    local p_conf = twaf_func:syn_config_process(_twaf, config)
    
    for k, v in pairs(p_conf) do
        _twaf.config[k] = v
    end
    
    log.result = p_conf
    return
end

_M.help.dynamic_config = {
    "GET /api/dynamic_config",
    "POST /api/dynamic_config"
}

_M.help.dynamic_config_back = {
    "POST /api/dynamic_config_back"
}
    
return _M