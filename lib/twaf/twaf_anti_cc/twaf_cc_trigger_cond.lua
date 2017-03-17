
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local twaf_func    = require "lib.twaf.inc.twaf_func"

local modules_name = "twaf_limit_conn"
local people       = 1
local evil         = 2
local god          = 3

function _M.anti_cc_gcond(self, _twaf, ctx)

    local value
    local flags   = false
    local dict    = ctx.dict
    local cf      = ctx.cf
    local cond    = cf.trigger_thr
    local request = ctx.request
    
    if twaf_func:state(cf.trigger_state) == false then
        return god
    end
    
    local bytes_in = request.BYTES_IN
    if bytes_in == nil then
        cond.req_flow_max = 0
    end
    
    local key = modules_name.."_"..ctx.uuid
    
    if cond.req_flow_max ~= 0 then
    
        dict:add(key.."_req_flow", 0, 1)
        local req_flow = dict:incr(key.."_req_flow", bytes_in)
        
        if req_flow >= cond.req_flow_max then
            flags = req_flow
            value = "req_flow_max '"..cond.req_flow_max.."'"
        end
    end
    
    if cond.req_count_max ~= 0 then
    
        dict:add(key.."_req_count", 0, 1)
        local req_count = dict:incr(key.."_req_count", 1)
        
        if req_count >= cond.req_count_max then
            flags = req_count
            value = "req_count_max '"..cond.req_count_max.."'"
        end
    end
    
    if flags ~= false then
        dict:set(key.."_type", 1, ctx.timeout)
        dict:set(key.."_expire", ngx.now() + ctx.timeout)
        
        request.MATCHED_VAR      = flags
        request.MATCHED_VAR_NAME = value
        table.insert(request.MATCHED_VARS, flags)
        table.insert(request.MATCHED_VAR_NAMES, value)
        
        return evil
    end
    
    local typ = dict:get(key.."_type")
    if typ then
        return god
    end

    return people
end

return _M
