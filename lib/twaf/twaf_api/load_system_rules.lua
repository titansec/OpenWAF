
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.1"
}

local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.load_system_rules = {}

-- load_system_rules e.g: POST /api/load_system_rules
_M.api.load_system_rules.post = function(_twaf, log, u)

    local cf = _twaf.config or {}
    local rules_id = cf.rules_id or {}
    for rid, _ in pairs(cf.rules) do
        rules_id[rid] = nil
    end
    
    cf.rules = {}
    local ret, err = twaf_conf.load_rules(cf, true)
    if not ret then
        log.success = 0
        log.reason  = err
        return
    end
    
    return
end

_M.help.load_system_rules = {
    "POST /api/load_system_rules"
}
    
return _M