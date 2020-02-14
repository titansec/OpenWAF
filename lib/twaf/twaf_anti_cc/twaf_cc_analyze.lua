
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func        = require "lib.twaf.inc.twaf_func"

local modules_name     = "twaf_limit_conn"
local people           = 1
local evil             = 2
local god              = 3

local table_insert     = table.insert
local string_format    = string.format

function _M.anti_cc_kcond(self, _twaf, ctx)

    local cf           =  ctx.cf
    local dict         =  ctx.dict
    local req          =  ctx.req
    
    local value  
    local flag         =  false
    local clean_thr    =  cf.clean_thr
    local uri          = _twaf:get_vars("URI", req) or "-"
    local d_key        =  twaf_func:key(cf.shared_dict_key)
    local key          =  string_format("%s_%s_%s", modules_name, ctx.uuid, d_key)
    local uri_key      =  string_format("%s_%s_%s", modules_name, ctx.uuid, d_key)
    local tmp_key      =  ""
    
    if twaf_func:state(cf.clean_state) == false then
        return false
    end
    
    if flag == false and clean_thr.new_conn_max ~= 0 then
    
        tmp_key = key.."_new_conn"
        
        if _twaf:get_vars("CONNECTION_REQUESTS", req) == 1 then
            dict:add(tmp_key, 0, 1)
            dict:incr(tmp_key, 1)
        end
        
        local new_conn = dict:get(tmp_key) or 0
        
        if new_conn >= clean_thr.new_conn_max then
             flag  = new_conn
             value = string_format("new_conn_max '%d'", clean_thr.new_conn_max)
        end
    end
        
    if flag == false and clean_thr.conn_max ~= 0 then
    
        tmp_key = key.."_conn"
    
        if _twaf:get_vars("CONNECTION_REQUESTS", req) == 1 then
            dict:add(tmp_key, 0, ctx.timeout)
            dict:incr(tmp_key, 1)
        end
        
        local conn = dict:get(tmp_key) or 0
        
        if ctx.typ == evil then
            if conn == 0 then conn = 1 end
            dict:set(tmp_key, conn, ctx.timeout)
        end
        
        if conn >= clean_thr.conn_max then
             flag  = conn
             value = string_format("conn_max '%d'", clean_thr.conn_max)
        end
    end
    
    if flag == false and clean_thr.req_max ~= 0 then
    
        tmp_key = key.."_req"
        
        dict:add(tmp_key, 0, 1)
        local req = dict:incr(tmp_key, 1)
        
        if req >= clean_thr.req_max then
             flag  = req
             value = string_format("request max '%d'", clean_thr.req_max)
        end
    end
    
    if flag == false and clean_thr.uri_frequency_max ~= 0 then
        
        dict:add(uri_key, 0, 1)
        local u = dict:incr(uri_key, 1)
        
        if u >= clean_thr.uri_frequency_max then
            flag  = u
            value = string_format("uri frequency max '%d'", clean_thr.uri_frequency_max)
        end
    end
    
    if flag ~= false then
    
        req.MATCHED_VAR      = flag
        req.MATCHED_VAR_NAME = value
        table_insert(req.MATCHED_VARS, flag)
        table_insert(req.MATCHED_VAR_NAMES, value)
        
        return true
    end
    
    return false

end

return _M
