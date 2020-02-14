
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func    = require "lib.twaf.inc.twaf_func"

local modules_name = "twaf_limit_conn"
local people       = 1
local evil         = 2
local god          = 3
local ngx_now      = ngx.now
local table_insert = table.insert
local str_format   = string.format

function _M.anti_cc_gcond(self, _twaf, ctx)

    local value
    local tmp_key = ""
    local flags   = false
    local dict    = ctx.dict
    local cf      = ctx.cf
    local cond    = cf.trigger_thr
    local req     = ctx.req
    
    if twaf_func:state(cf.trigger_state) == false then
        return god
    end
    
    local bytes_in = _twaf:get_vars("BYTES_IN", req)
    if bytes_in == nil then
        cond.req_flow_max = 0
    end
    
    local key = str_format("%s_%s", modules_name, ctx.uuid)
    
    if cond.req_flow_max ~= 0 then
    
        tmp_key = key.."_req_flow"
        
        dict:add(tmp_key, 0, 1)
        local req_flow = dict:incr(tmp_key, bytes_in)
        
        if req_flow >= cond.req_flow_max then
            flags = req_flow
            value = str_format("req_flow_max '%s'", cond.req_flow_max)
        end
    end
    
    if cond.req_count_max ~= 0 then
    
        tmp_key = key.."_req_count"
    
        dict:add(tmp_key, 0, 1)
        local req_count = dict:incr(tmp_key, 1)
        
        if req_count >= cond.req_count_max then
            flags = req_count
            value = str_format("req_count_max '%s'", cond.req_count_max)
        end
    end
    
    if flags ~= false then
        dict:set(key.."_type", 1, ctx.timeout)
        dict:set(key.."_expire", ngx_now() + ctx.timeout)
        
        req.MATCHED_VAR      = flags
        req.MATCHED_VAR_NAME = value
        table_insert(req.MATCHED_VARS, flags)
        table_insert(req.MATCHED_VAR_NAMES, value)
        
        return evil
    end
    
    local typ = dict:get(key.."_type")
    if typ then
        return god
    end

    return people
end

return _M
