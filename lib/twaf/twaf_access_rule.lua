-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

local twaf_func            = require "lib.twaf.inc.twaf_func"
local twaf_action          = require "lib.twaf.inc.action"

local mt                   = { __index = _M, }
local event_id             = "910001"
local event_severity       = "low"
local category             = "5byC5bi46K+35rGC"  --异常请求
local modules_name         = "twaf_access_rule"
local modules_log_name     = "exception.access"
local ngx_var              = ngx.var
local ngx_exit             = ngx.exit
local ngx_shared           = ngx.shared
local ngx_req_get_headers  = ngx.req.get_headers

function _M.new_modules(self, config)
    return setmetatable({config = config}, mt)
end

local function _log_action(_twaf, cf)

    local log       =  {}
    local ctx       = _twaf:ctx()
    local log_state =  twaf_func:state(cf.log_state)
    
    log.id          = event_id
    log.severity    = event_severity
    log.meta        = cf.action_meta
    log.action      = cf.action
    
    local stat      = ctx.events.stat
    stat[category]  = (stat[category] or 0) + 1
    
    if log.action ~= "ALLOW" then
	    ngx_var.twaf_attack_info = ngx_var.twaf_attack_info .. modules_log_name .. ";"
	end
	
    if log_state == true then
        ctx.events.log[modules_log_name] = log
    end
    
    if log.action:upper() == "DENY" then
        ngx_exit(log.meta)
    end
    
    return twaf_action:do_action(_twaf, log.action, log.meta)
end

function _M.handler(self, _twaf)

    local host
    local server            =  nil
    local ctx               = _twaf:ctx()
    local uri               =  ngx_var.request_uri
    local twaf_https        =  ngx_var.twaf_https
    local request_host      =  ngx_req_get_headers()["host"]
    local original_dst_addr =  ngx_var.original_dst_addr
    local original_dst_port =  ngx_var.original_dst_port
    
    local cf  = _twaf.config.twaf_access_rule
    local gcf = _twaf:get_config_param("twaf_global")
    
    if type(request_host) == "table" then
        return _log_action(_twaf, cf)
    end
    
    if twaf_https == "1" then
        twaf_https = true
    else
        twaf_https = false
    end
    
    if cf.rules == nil then
        return _log_action(_twaf, cf)
    end

    for _, rule in ipairs(cf.rules) do
        local access_rule_flag = true
        host = request_host
        
        local ngx_ssl = twaf_func:state(rule["ngx_ssl"])
        if twaf_https ~= ngx_ssl then
            access_rule_flag = false
        end
        
        if access_rule_flag and rule["server"] then
            if original_dst_addr and original_dst_port then
                local original_dst = original_dst_addr..":"..original_dst_port
                local from, to, err = ngx.re.find(original_dst, rule["server"], "jo")
                if not from then
                    access_rule_flag = false
                end
            else
                ngx.log(ngx.ERR, "original_dst_addr or original_dst_port is nil")
                ngx.exit(502)
            end
        end
        
        local from, to, err = ngx.re.find(host, rule["host"], "jo")
        if access_rule_flag and from then
            if rule["path"] == "/" then
                server = rule
                break
            else
                local from = ngx.re.find(uri, rule["path"])
                if from == 1 then
                    server = rule
                    break
                end
            end
        end
    end
    
    if server == nil then
        if twaf_func:state(cf.unknown_host_state) == true then
            server = {}
            server.forward = cf.default_host
            ngx_var.twaf_modsecurity_flag = 0
            ctx.trust = true
        else
            return _log_action(_twaf, cf)
        end
    end
    
    if twaf_func:state(server["server_ssl"]) == true then
        ngx_var.twaf_upstream_server = "https://" .. server["forward"]
    else
        ngx_var.twaf_upstream_server = "http://" .. server["forward"]
    end
    
    ctx.policy_uuid = server.policy
    ctx.user        = server.user
    
    ctx.balancer      = {}
    ctx.balancer.addr = server.forward_addr
    ctx.balancer.port = server.forward_port
    
    -- statistic
    if server["uuid"] then
        local shared_dict_name  = cf.shared_dict_name or gcf.dict_name
        local access_rules_dict = ngx_shared[shared_dict_name]
        
        access_rules_dict:add(server["uuid"], 0)
        access_rules_dict:incr(server["uuid"], 1)
    end
    
    return true
end

return _M
