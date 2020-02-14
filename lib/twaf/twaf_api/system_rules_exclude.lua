
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func = require "lib.twaf.inc.twaf_func"

_M.api = {}
_M.help = {}
_M.api.system_rules_exclude = {}

-- get system_rules_exclude, e.g: GET /api/system_rules_exclude
-- get system_rules_exclude, e.g: GET /api/system_rules_exclude/{rule_id}
_M.api.system_rules_exclude.get    = function(_twaf, log, u)

    local exclude = _twaf.config.twaf_policy.system_rules_id
    
    if not exclude then
        log.success = 0
        log.reason  = "System rules exclude is nil."
        return
    end
    
    if not u[2] then
        log.result = exclude
        return
    end
    
    if not exclude[u[2]] then
        log.success = 0
        log.reason  = "No rule id '" .. u[2] .. "' in system rules exclude."
        return
    end
    
    log.result = exclude[u[2]]
end

-- post system_rules_exclude, e.g: POST /api/system_rules_exclude
_M.api.system_rules_exclude.post   = function(_twaf, log, u)

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
    
     log.result = data.config
    _twaf.config.twaf_policy.system_rules_id = data.config
end

-- delete system_rules_exclude, e.g: DELETE /api/system_rules_exclude
-- delete system_rules_exclude, e.g: DELETE /api/system_rules_exclude/{rule_id}
_M.api.system_rules_exclude.delete = function(_twaf, log, u)

    local policy = _twaf.config.twaf_policy
    
    if not policy.system_rules_id then
        log.result = "System rules exclude is nil."
        return
    end
    
    if not u[2] then
        log.result = policy.system_rules_id
        policy.system_rules_id = nil
        return
    end
    
    if not policy.system_rules_id[u[2]] then
        log.result = "No rule id '" .. u[2] .. "' in system rules exclude."
        return
    end
    
    log.result = policy.system_rules_id[u[2]]
    policy.system_rules_id[u[2]] = nil
end

_M.help.system_rules_exclude = {
    "GET /api/system_rules_exclude",
    "GET /api/system_rules_exclude/{rule_id}",
    "POST /api/system_rules_exclude",
    "DELETE /api/system_rules_exclude",
    "DELETE /api/system_rules_exclude/{rule_id}"
}
    
return _M