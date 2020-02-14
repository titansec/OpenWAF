
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local tctc             = require "lib.twaf.twaf_anti_cc.twaf_cc_trigger_cond"
local tca              = require "lib.twaf.twaf_anti_cc.twaf_cc_analyze"
local tcr              = require "lib.twaf.twaf_anti_cc.twaf_cc_res"
local twaf_func        = require "lib.twaf.inc.twaf_func"

local modules_name     = "twaf_limit_conn"
local ngx_shared       = ngx.shared
local ngx_timer_at     = ngx.timer.at
local people           = 1
local evil             = 2
local god              = 3

function _M.handler(self, _twaf)

    local cf    = _twaf:get_config_param(modules_name)
    local tctx  = _twaf:ctx()
    local trust =  tctx.trust
    
    if twaf_func:state(cf.state) == false or trust == true then
        return true
    end
    
    local ctx           =  {}
    local res           =  god
    local conn_dict     =  ngx_shared[cf.shared_dict_name]
    local timeout       =  cf.timeout
    local interval      =  cf.interval
    local req           =  tctx.req
    local uuid          =  req.POLICYID
    
    ctx.uuid     = uuid
    ctx.dict     = conn_dict
    ctx.timeout  = timeout
    ctx.interval = interval
    ctx.cf       = cf
    ctx.func     = twaf_func
    ctx.req      = req
    
    --flush expired
    twaf_func:dict_flush_expired(_twaf, conn_dict, cf.timer_flush_expired)
    
    -- trigger thr
    res = tctc:anti_cc_gcond(_twaf, ctx)
    if res == people then
        return true
    end
    
    ctx.typ = res
    res = false
    
    -- clean thr
    res = tca:anti_cc_kcond(_twaf, ctx)
    ctx.res = res
    
    -- action
    tcr:anti_cc_res(_twaf, ctx)
    return true
end

return _M
