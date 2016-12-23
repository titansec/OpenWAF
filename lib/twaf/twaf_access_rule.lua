
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local twaf_func            = require "lib.twaf.inc.twaf_func"

local event_id             = "910001"
local event_severity       = "low"
local modules_name         = "twaf_access_rule"
local rule_name            = "exception.req.access_rule"
local ngx_var              = ngx.var
local ngx_exit             = ngx.exit
local ngx_shared           = ngx.shared
local ngx_req_get_headers  = ngx.req.get_headers

local function _log_action(_twaf, cf)

    local actx          =  {}
    
    actx.id             =  event_id
    actx.severity       =  event_severity
    actx.rule_name      =  rule_name
    actx.action         =  cf.action
    actx.action_meta    =  cf.action_meta
    actx.version        = _M._VERSION
    actx.log_state      =  cf.log_state
    
    return twaf_func:rule_log(_twaf, actx)
end

function _M.handler(self, _twaf)

    local host
    local server            =  nil
    local ctx               = _twaf:ctx()
    local request           =  ctx.request
    local uri               =  ngx_var.request_uri
    local twaf_https        =  ngx_var.twaf_https
    local request_host      =  ngx_req_get_headers()["host"]
    local request_port      =  tonumber(ngx.var.server_port) or 0
    local cf                = _twaf.config.twaf_access_rule
    
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
        
        if access_rule_flag and twaf_https ~= twaf_func:state(rule.ngx_ssl) then
            access_rule_flag = false
        end
        
        if access_rule_flag and (tonumber(rule.port) or 80) ~= request_port then
            access_rule_flag = false
        end
        
        if access_rule_flag and not ngx.re.find(host, rule.host, "jo") then
            access_rule_flag = false
        end
        
        if access_rule_flag and ngx.re.find(uri, rule.path) ~= 1 then
            access_rule_flag = false
        end
        
        if access_rule_flag then
            server = rule
            break
        end
    end
    
    if server == nil then
        return _log_action(_twaf, cf)
    end
    
    if twaf_func:state(server["server_ssl"]) == true then
        ngx_var.twaf_upstream_server = "https://" .. server["forward"]
    else
        ngx_var.twaf_upstream_server = "http://" .. server["forward"]
    end
    
    request.POLICYID = server.policy or _twaf.config.global_conf_uuid or "-"
    request.USERID   = server.user   or "-"
    
    ctx.balancer      = {}
    ctx.balancer.addr = server.forward_addr
    ctx.balancer.port = server.forward_port
    
    return true
end

return _M
