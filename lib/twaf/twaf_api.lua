
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local cjson        = require "cjson.safe"
local twaf_func    = require "lib.twaf.inc.twaf_func"
local twaf_conf    = require "lib.twaf.twaf_conf"
local prefix       = "/api/"
local arr_index    = "arr_tonumber"
local show         = {}
show["post"]       = {}
show["delete"]     = {}
show["put"]        = {}
show["get"]        = {}


-------------------------stat------------------------

-- get stat, e.g: GET host/path/stat/policy_uuid
show["get"][prefix.."stat"]       = function(_twaf, log, u)
    
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

-- delete stat, e.g: DELETE host/path/stat
show["delete"][prefix.."stat"]    = function(_twaf) twaf_reqstat:reqstat_clear() end

--[[
{"success": 1, "result":"xxx"}
{"success": 0, "reason":"xxx"}
]]
function _M.content(self, _twaf)

    local log   = {}
    log.success = 1
    log.reason  = nil
    
    local uri    = ngx.var.uri or "-"
    local method = (ngx.req.get_method() or "-"):lower()
    local gcf    = _twaf:get_default_config_param("twaf_global")
    local dict   = ngx.shared[gcf.dict_name]
    local wid    = ngx.worker.id()
    local wpid   = ngx.worker.pid()
    
    -- config synchronization
    twaf_func:syn_config(_twaf)
    
    repeat
    
    local from, to, u = uri:find(prefix.."(.*)")
    if not from then
        log.success = 0
        log.reason  = "uri not right"
        break
    end
    
    u = twaf_func:string_ssplit(u, "/")
    if type(u) ~= "table" then
        log.success = 0
        log.reason  = "string_ssplit was wrong in twaf_func.lua"
        break
    end
    
    uri = prefix..u[1]
    
    if not show[method][uri] then
        log.success = 0
        log.reason  = "no api -- " .. u[1]
        break
    end
    
    show[method][uri](_twaf, log, u)
    
    until true
    
    if method ~= "get" and log.success == 1 then
        local worker_config = twaf_func:table_to_string(_twaf.config)
        if worker_config then
            dict:set("worker_config", worker_config)
            local wcount = ngx.worker.count()
            for i = 0, wcount -1, 1 do
                dict:set("worker_process_"..i, true)
            end
            dict:set("worker_process_"..wid, wpid)
        else
            ngx.log(ngx.ERR, "synchronization Failure!")
        end
    end
    
    ngx.say(twaf_func:table_to_string(log))
end

return _M