
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local cjson            = require "cjson.safe"
local socket           = require "resty.logger.socket"
local twaf_action      = require "lib.twaf.inc.action"
local twaf_log         = require "lib.twaf.twaf_log"
local twaf_func        = require "lib.twaf.inc.twaf_func"

local event_id         = "710002"
local event_severity   = "high"
local modules_name     = "twaf_limit_conn"
local rule_name        = "ddos.cc"
local ngx_log          = ngx.log
local ngx_ERR          = ngx.ERR
local ngx_var          = ngx.var
local ngx_timer_at     = ngx.timer.at
local ngx_now          = ngx.now
local ngx_time         = ngx.time
local string_format    = string.format

local function _content_log(_twaf, ctx, status)

    local cf                          =  ctx.cf
    local log_cf                      =  ctx.log_cf
    local dict                        =  ctx.dict
    local key                         =  string_format("%s_%s", modules_name, ctx.uuid)
    
    local _log                        =  cjson.decode(dict:get(key.."_log")) or {}
    _log                              = _log.log                             or {}
    _log.status                       =  status
    _log.time                         =  ngx_now()
    _log.req_flow_rate                =  dict:get(key.."_req_flow")          or 0
    _log.req_count_rate               =  dict:get(key.."_req_count")         or 0
    
    ctx.events                        =  {}
    ctx.events.log                    =  {}
    ctx.events.log[rule_name]         = _log
    
    local function remove_func(req, log_format)
        for _, v in pairs(log_format) do 
            v = v:upper()
            req[v] = req[v] or "-"
        end
    end
    
    if cf.log_state == true then
    
        local req = ctx.req
        
        if log_cf.content_type == "INFLUXDB" then
            remove_func(req, log_cf.security_log.fileds)
        elseif log_cf.content_type == "JSON" then
            remove_func(req, log_cf.security_log)
        end
        
        req.TIME_EPOCH  =  ngx_time()
        req.MSEC        =  req.TIME_EPOCH
        req.TIME_LOCAL  =  "-"
        
        socket.init(log_cf)
        local security_msg = twaf_log:set_msg(ctx, log_cf, log_cf.security_log, "security_log")
        socket.log(security_msg)
    end
    
    return _log
end

local function _timer_log(premature, _twaf, ctx, stop)

    local dict        = ctx.dict
    local delay       = ctx.cf.interval
    local key         = string_format("%s_%s", modules_name, ctx.uuid)
    local status      = "end"
    
    if stop == false then
        local expire = dict:get(key.."_expire") or ngx_now()
        local diff = expire - ngx_now()
        if diff < delay + 0.49 then
            delay = diff
            stop = true
        end
        
        status = "middle"
    end
    
    _content_log(_twaf, ctx, status)
    
    if status == "middle" then
        ngx_timer_at(delay, _timer_log, _twaf, ctx, stop)
    else
        dict:set(key.."_log", nil)
        dict:set(key.."_expire", nil)
    end
end

local function _log_action(_twaf, req, cf, _log)

    if cf.log_state == true then
        _twaf:ctx().events.log[rule_name] = _log
    end
    
    if cf.action == "DENY" then
        ngx_var.twaf_attack_info = string_format("%s%s;", ngx_var.twaf_attack_info, rule_name)
    end
    
    req.MATCHED_VARS      = {}
    req.MATCHED_VAR_NAMES = {}
    
    return twaf_action:do_action(_twaf, cf.action, cf.action_meta)
end

local function _reqstat_total(req, tb)

    tb.log.req_total       = (tb.log.req_total or 0)      + 1
    tb.log.req_flow_total  = (tb.log.req_flow_total or 0) + twaf:get_vars("BYTES_IN", req)
    
    if twaf:get_vars("CONNECTION_REQUESTS", req) == 1 then
        tb.log.conns_total = (tb.log.conns_total or 0)    + 1
    end
end

local function _reqstat_clean(req, tb)

    local bytes_in = twaf:get_vars("BYTES_IN", req)
    local addr     = twaf:get_vars("REMOTE_ADDR", req)
    local ipaddr   = tb.ip[addr] or 0
    tb.ip[addr]    = ipaddr + 1
    
    if ipaddr == 0 then
        
        tb.log.ipaddr_total = (tb.log.ipaddr_total or 0) + 1
        
        if twaf:get_vars("CONNECTION_REQUESTS", req) ~= 1 then
            tb.log.conns_total = (tb.log.conns_total or 0) + 1
        end
    end
    
    tb.log.clean_req_flow_total = (tb.log.clean_req_flow_total or 0) + bytes_in
    
    tb.log.clean_req_total = (tb.log.clean_req_total or 0) + 1
    
    _reqstat_total(req, tb)
end

function _M.anti_cc_res(self, _twaf, ctx)

    local cf      =  ctx.cf
    local dict    =  ctx.dict
    local uuid    =  ctx.uuid
    local req     =  ctx.req
    local key     =  string_format("%s_%s", modules_name, uuid)
    local addr    = _twaf:get_vars("REMOTE_ADDR", req)
    
    local tb = dict:get(key.."_log")
    
    if tb then
        tb = cjson.decode(tb)
    end
    
    local info            =  {}
    info.id               =  event_id
    info.severity         =  event_severity
    info.rule_name        =  rule_name
    info.action           =  cf.action
    info.action_meta      =  cf.action_meta
    info.version          = _M._VERSION
    info.log_state        =  cf.log_state
    info.category         =  twaf_func:rule_category(_twaf, rule_name)
    
    if not tb then
    
        tb                    =  {}
        tb.ip                 =  {}
        tb.log                =  twaf_func:conf_log(_twaf, req, info)
        tb.log.req_flow_rate  =  dict:get(key.."_req_flow")   or 0
        tb.log.req_count_rate =  dict:get(key.."_req_count")  or 0
    else
    
        local value = twaf_func:conf_log(_twaf, req, info)
        for k, v in pairs(value) do
            tb.log[k] = v
        end
    end
    
    if tb.ip[addr] and cf.attacks and cf.attacks > 0 and tb.ip[addr] > cf.attacks then
        ctx.res = true
    end
    
    if ctx.res == false then
        if tb.ip[addr] then
            _reqstat_total(req, tb)
            dict:set(key.."_log", cjson.encode(tb))
        end
        
        return true
    end
    
    -- reqstat
    _reqstat_clean(req, tb)
    
    --timer: start middle end
    local _log =  nil
    if not tb.cc_start then
        
        local log_cf       = _twaf:get_config_param("twaf_log")
        ctx.log_cf         =  twaf_func:copy_table(log_cf)
        
        tb.cc_start        =  1
        tb.log.start_time  = _twaf:get_vars("TIME_NOW", req)
        tb.log.status      =  "start"
        tb.log.time        =  ngx_now()
        _log               =  tb.log
        
       --reqstat
        local stat         = _twaf:ctx().events.stat
        stat[_log.category] = 1
        
        local ok, err = ngx_timer_at(cf.interval, _timer_log, _twaf, ctx, false)
        if not ok then
            ngx_log(ngx_ERR, "twaf_limit_conn - failed to create timer: ", err)
            return
        end
        
    end
    
    dict:set(key.."_log", cjson.encode(tb))
    return _log_action(_twaf, req, cf, _log)
end

return _M
