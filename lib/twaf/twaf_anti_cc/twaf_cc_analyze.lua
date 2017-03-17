
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local twaf_func        = require "lib.twaf.inc.twaf_func"

local modules_name     = "twaf_limit_conn"
local people           = 1
local evil             = 2
local god              = 3

function _M.anti_cc_kcond(self, _twaf, ctx)

    local cf           = ctx.cf
    local dict         = ctx.dict
    local request      = ctx.request
    
    local value  
    local flag         = false
    local clean_thr    = cf.clean_thr
    local uri          = request.URI or "-"
    local d_key        = twaf_func:key(cf.shared_dict_key)
    local key          = modules_name.."_"..ctx.uuid.."_"..d_key
    local uri_key      = modules_name.."_"..ctx.uuid.."_"..uri
    
    if twaf_func:state(cf.clean_state) == false then
        return false
    end
    
    if flag == false and request.CONNECTION_REQUESTS == 1 then
    
        if clean_thr.new_conn_max ~= 0 then
            dict:add(key.."_new_conn", 0, 1)
            local new_conn = dict:incr(key.."_new_conn", 1)
            
            if new_conn >= clean_thr.new_conn_max then
                 flag  = new_conn
                 value = "new_conn_max '"..clean_thr.new_conn_max.."'"
            end
        end
        
        if flag == false and clean_thr.conn_max ~= 0 then
        
            dict:add(key.."_conn", 0, 1)
            local conn = dict:incr(key.."_conn", 1)
            
            if ctx.typ == evil then
                dict:set(key.."_conn", conn, ctx.timeout)
            end
            
            if conn >= clean_thr.conn_max then
                 flag  = conn
                 value = "conn_max '"..clean_thr.conn_max.."'"
            end
        end
    end
    
    if flag == false and clean_thr.req_max ~= 0 then
        
        dict:add(key.."_req", 0, 1)
        local req = dict:incr(key.."_req", 1)
        
        if req >= clean_thr.req_max then
             flag  = req
             value = "request max '"..clean_thr.req_max.."'"
        end
    end
    
    if flag == false and clean_thr.uri_frequency_max ~= 0 then
        
        dict:add(uri_key, 0, 1)
        local u = dict:incr(uri_key, 1)
        
        if u >= clean_thr.uri_frequency_max then
            flag  = u
            value = "uri frequency max '"..clean_thr.uri_frequency_max.."'"
        end
    end
    
    if flag ~= false then
    
        request.MATCHED_VAR      = flag
        request.MATCHED_VAR_NAME = value
        table.insert(request.MATCHED_VARS, flag)
        table.insert(request.MATCHED_VAR_NAMES, value)
        
        return true
    end
    
    return false

end

return _M
