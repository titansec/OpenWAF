
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func = require "lib.twaf.inc.twaf_func"

_M.api = {}
_M.help = {}
_M.api.stat = {}

-- get stat, e.g: GET /api/stat
-- get stat, e.g: GET /api/stat/{policy_uuid}
-- get stat, e.g: GET /api/stat/policy_all
_M.api.stat.get       = function(_twaf, log, u)
    
    if not u[2] then
        log.result = twaf_reqstat:get_reqstat_main_info()
        return
    end
    
    local policy = _twaf.config.twaf_policy.policy_uuids or {}
    if not policy[u[2]] and u[2] ~= "policy_all" and u[2] ~= "GLOBAL" then
        log.success = 0
        log.reason  = "No policy '"..u[2].."'"
        return
    end
    
    log.result = twaf_reqstat:get_reqstat_uuid_info({u[2]})
    
    if not next(log.result) then
        log.result  = nil
        log.reason  = "uuid '"..u[2].."' is not exist"
        log.success = 0
        return
    end
    
    for i = 3, #u, 1 do
        log.result = log.result[u[i]]
        
        if log.result == nil then
            log.reason  = "No key named '"..u[i].."'"
            log.success = 0
            return
        end
    end
    
    return
end

-- delete stat, e.g: DELETE /api/stat
_M.api.stat.delete    = function(_twaf) twaf_reqstat:reqstat_clear() end

_M.help.stat = {
    "GET /api/stat",
    "GET /api/stat/{policy_uuid}",
    "GET /api/stat/policy_all",
    "DELETE /api/stat"
}
    
return _M