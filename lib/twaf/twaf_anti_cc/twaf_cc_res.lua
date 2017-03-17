
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

local function _content_log(_twaf, ctx, status)

    local cf                          =  ctx.cf
    local log_cf                      =  ctx.log_cf
    local dict                        =  ctx.dict
    local key                         =  modules_name.."_"..ctx.uuid
    
    local log                         =  cjson.decode(dict:get(key.."_log")) or {}
    log                               =  log.log                             or {}
    log.status                        =  status
    log.time                          =  ngx.now()
    log.req_flow_rate                 =  dict:get(key.."_req_flow")          or 0
    log.req_count_rate                =  dict:get(key.."_req_count")         or 0
    
    ctx.events                        =  {}
    ctx.events.log                    =  {}
    ctx.events.log[rule_name]         =  log
    
    if cf.log_state == true then
        local log_format = log_cf.security_log
        if log_cf.content_type == "INFLUXDB" then
            log_cf.security_log.fileds = {"unique_id"}
        elseif log_cf.content_type == "JSON" then
            log_cf.security_log = {"unique_id"}
        end
        
        socket.init(log_cf)
        local security_msg = twaf_log:set_msg(ctx, log_cf, log_cf.security_log, 2)
        socket.log(security_msg)
    end
    
    return log
end

local function _timer_log(premature, _twaf, ctx, stop)

    local dict        = ctx.dict
    local delay       = ctx.cf.interval
    local key         = modules_name.."_"..ctx.uuid
    local status      = "end"
    
    if stop == false then
        local expire = dict:get(key.."_expire")
        local diff = expire - ngx.now()
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

local function _log_action(_twaf, request, cf, log)

    if cf.log_state == true then
        _twaf:ctx().events.log[rule_name] = log
    end
    
    if cf.action ~= "PASS" and cf.action ~= "ALLOW" and cf.action ~= "CHAIN" then
        ngx_var.twaf_attack_info = ngx_var.twaf_attack_info .. rule_name .. ";"
    end
    
    request.MATCHED_VARS      = {}
    request.MATCHED_VAR_NAMES = {}
    
    return twaf_action:do_action(_twaf, cf.action, cf.action_meta)
end

local function _reqstat_total(request, tb)
    
    tb.log.req_total       = (tb.log.req_total or 0)      + 1
    tb.log.req_flow_total  = (tb.log.req_flow_total or 0) + request.BYTES_IN
    
    if request.CONNECTION_REQUESTS == 1 then
        tb.log.conns_total = (tb.log.conns_total or 0)    + 1
    end
end

local function _reqstat_clean(request, tb)

    local bytes_in = request.BYTES_IN
    local addr     = request.REMOTE_ADDR
    local ipaddr   = tb.ip[addr] or 0
    tb.ip[addr]    = ipaddr + 1
    
    if ipaddr == 0 then
        
        tb.log.ipaddr_total = (tb.log.ipaddr_total or 0) + 1
        
        if request.CONNECTION_REQUESTS ~= 1 then
            tb.log.conns_total = (tb.log.conns_total or 0) + 1
        end
    end
    
    tb.log.clean_req_flow_total = (tb.log.clean_req_flow_total or 0) + bytes_in
    
    tb.log.clean_req_total = (tb.log.clean_req_total or 0) + 1
    
    _reqstat_total(request, tb)
end

function _M.anti_cc_res(self, _twaf, ctx)

    local log     = nil
    local cf      = ctx.cf
    local dict    = ctx.dict
    local uuid    = ctx.uuid
    local request = ctx.request
    local key     = modules_name.."_"..uuid
    local addr    = request.REMOTE_ADDR
    
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
        tb.log                =  twaf_func:conf_log(_twaf, request, info)
        tb.log.req_flow_rate  =  dict:get(key.."_req_flow")   or 0
        tb.log.req_count_rate =  dict:get(key.."_req_count")  or 0
    else
    
        local value = twaf_func:conf_log(_twaf, request, info)
        for k, v in pairs(value) do
            tb.log[k] = v
        end
    end
    
    if ctx.res == false then
        if tb.ip[addr] then
            _reqstat_total(request, tb)
            dict:set(key.."_log", cjson.encode(tb))
        end
        
        return true
    end
    
    -- reqstat
    _reqstat_clean(request, tb)
    
    --timer: start middle end
    if not tb.cc_start then
        
        local log_cf       = _twaf:get_config_param("twaf_log")
        ctx.log_cf         =  twaf_func:copy_table(log_cf)
        
        tb.cc_start        = 1
        tb.log.start_time  = request.TIME_NOW
        tb.log.status      = "start"
        tb.log.time        = ngx.now()
        log                = tb.log
        
       --reqstat
        local stat         = _twaf:ctx().events.stat
        stat[log.category] = 1
        
        local ok, err = ngx_timer_at(cf.interval, _timer_log, _twaf, ctx, false)
        if not ok then
            ngx_log(ngx_ERR, "twaf_limit_conn - failed to create timer: ", err)
            return
        end
        
    end
    
    dict:set(key.."_log", cjson.encode(tb))
    return _log_action(_twaf, request, cf, log)
end

return _M
