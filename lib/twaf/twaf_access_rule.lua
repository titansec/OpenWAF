
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.1"
}

local twaf_func            = require "lib.twaf.inc.twaf_func"
local twaf_action          = require "lib.twaf.inc.action"
local cidr                 = require "lib.twaf.inc.cidr"
local ssl                  = require "ngx.ssl"

local event_id             = "910001"
local event_severity       = "low"
local modules_name         = "twaf_access_rule"
local rule_name            = "exception.req.access_rule"
local ngx_var              = ngx.var
local ngx_shared           = ngx.shared
local ngx_re_find          = ngx.re.find
local io_open              = io.open
local _type                = type
local string_format        = string.format
local table_insert         = table.insert
local is_type              = {table = 1, string = 2}

local function _log_action(_twaf, cf, ctx)

    local actx          =  {}
    local _ctx          =  ctx or {}
    
    actx.id             =  event_id
    actx.severity       =  event_severity
    actx.rule_name      =  rule_name
    actx.action         =  cf.action
    actx.action_meta    = _ctx.resp_code or cf.action_meta
    actx.version        = _M._VERSION
    actx.log_state      =  cf.log_state
    
    return twaf_func:rule_log(_twaf, actx)
end

function _M.access_rule_rfast(self, ckey, ctx)

    local server = nil
    local access_rule_flag = true

    for _, rule in ipairs(ctx.rfast[ckey] or {}) do
    
        if ngx_re_find(ctx.uri, rule.path, rule.url_case_option) ~= 1 then
            access_rule_flag = false
        end

        if access_rule_flag == true then
            server = rule
            break
        end

        ctx.para = {}
        access_rule_flag = true
    end
    
    return server
end

--[[
    ctx.rules
    ctx.host
    ctx.https
    ctx.uri
    ctx.request_port
]]
function _M.access_rule(self, _twaf, ctx)

    local server =  nil
    local mhost  =  nil
    local tflag  =  false

    for _, rule in ipairs(ctx.rules) do
    
        local access_rule_flag = true
        
        -- enable
        if access_rule_flag and not rule.enable then
            access_rule_flag = false
        end
        
        -- ngx ssl
        if access_rule_flag and ctx.https ~= rule.ngx_ssl then
            access_rule_flag = false
        end
        
        -- host
        if access_rule_flag then
        
            mhost = rule.host
            
            if rule.host_type == 1 then -- "table"
            
                for _, h in ipairs(rule.host) do
                    local bool = cidr.contains(cidr.from_str(ctx.host), cidr.from_str(h))  -- ipv6
                    if bool == true or ngx_re_find(ctx.host, h, "jio") then
                        mhost = h
                        tflag = true
                        break
                    end
                end
                
                if not tflag then
                    access_rule_flag = false
                end
                
            else -- "string"
            
                local bool = cidr.contains(cidr.from_str(ctx.host), cidr.from_str(rule.host))  -- ipv6
                if bool ~= true and not ngx_re_find(ctx.host, rule.host, "jio") then
                    access_rule_flag = false
                end
            end
        end
        
        if access_rule_flag and ngx_re_find(ctx.uri, rule.path, rule.url_case_option) ~= 1 then
            access_rule_flag = false
        end
        
        if access_rule_flag and rule.port ~= ctx.request_port then
            access_rule_flag = false
        end
        
        if access_rule_flag then
            server = rule
            break
        end
        
        mhost = nil
        tflag = false
    end
    
    return server
end

function _M.handler(self, _twaf)

    local cf = _twaf.config.twaf_access_rule

    if not cf.state then return end

    local ctx          = _twaf:ctx()
    local req          =  ctx.req
    local uri          = _twaf:get_vars("URI", req)
    local is_https     = _twaf:get_vars("SCHEME", req) == "https" and true or false
    local request_host = _twaf:get_vars("REMOTE_HOST", req)
    local request_port = _twaf:get_vars("SERVER_PORT", req)

    local _ctx         =  {}
    _ctx.rules         =  cf.rules
    _ctx.rfast         =  cf.rfast
    _ctx.host          =  request_host
    _ctx.https         =  is_https
    _ctx.uri           =  uri
    _ctx.request_port  =  request_port
    _ctx.req           =  req
    
    local server, ckey, key
    local dict = ngx_shared[cf.shm]
    
    if cf.dict_state and dict then
        key  = string_format("%s%s%d", is_https, request_host, request_port)
        ckey = dict:get(key)
        
        if ckey then server = _M:access_rule_rfast(ckey, _ctx) end
    end
    
    if not ckey then server = _M:access_rule(_twaf, _ctx) end
    
    if not server then return _log_action(_twaf, cf) end
    
    if key and not ckey and server.cache_key then
        dict:set(key, server.cache_key)
    end
    
    local server_scheme = server.server_ssl and "https" or "http"
    ngx_var.twaf_upstream_server = string_format("%s://%s", server_scheme, server.forward)
    
    req.ACCESS_RULE = server
    req.POLICYID    = server.policy
    req.USERID      = server.user
    req.ACCESS_ID   = server.uuid
    
    local gcf = _twaf:get_config_param("twaf_global")
    if gcf["twaf_x_real_ip"] == "twaf_x_forwarded_for" then
        req.REMOTE_ADDR = _twaf:get_vars("REAL_IP", req)
        ngx_var.twaf_x_real_ip =  req.REMOTE_ADDR
    end
    
    ctx.balancer = {}
    ctx.balancer.timeout = server.forward_timeout
    ctx.balancer.addr = server.forward_addr
    ctx.balancer.port = server.forward_port
    
    return true
end

function _M.rules_cache_init(rules)

    local dst = {}

    for _, r in ipairs(rules) do
        if r.cache_key then
            dst[r.cache_key] = dst[r.cache_key] or {}
            table_insert(dst[r.cache_key], r)
        end
    end
    
    return dst
end

function _M.rule_init(r, err)

    if not err then err = {} end

    local cache_key = true

    r.enable = r.enable == nil and true or r.enable
    twaf_func.type_check(r.enable, "enable", "boolean", err)

    r.user = r.user or "-"
    twaf_func.type_check(r.user, "user", "string", err)

    r.client_ssl = r.client_ssl or false
    twaf_func.type_check(r.client_ssl, "client_ssl", "boolean", err)

    if r.client_ssl == true then
        twaf_func.type_check(r.client_ssl_cert, "client_ssl_cert", "string", err)
--[[
        local f = io_open(r.client_ssl_cert)
        if f then
            local pem_cert_chain = f:read("*a")
            f:close()

            local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
            if not der_cert_chain then
                table_insert(err, "failed to convert certificate chain from PEM to DER: ", err)
            end

            r.client_ssl_cert_chain = der_cert_chain
        else
            table_insert(err, "open client cert failed: " .. r.client_ssl_cert)
        end]]
    end

    r.ngx_ssl = r.ngx_ssl or false
    twaf_func.type_check(r.ngx_ssl, "ngx_ssl", "boolean", err)

    if r.ngx_ssl == true then
        twaf_func.type_check(r.ngx_ssl_key, "ngx_ssl_key", "string", err)
        twaf_func.type_check(r.ngx_ssl_cert, "ngx_ssl_cert", "string", err)
--[[
        local f = io_open(r.ngx_ssl_cert)
        if f then
            local pem_cert_chain = f:read("*a")
            f:close()

            local der_cert_chain, err = ssl.cert_pem_to_der(pem_cert_chain)
            if not der_cert_chain then
                table_insert(err, "failed to convert certificate chain from PEM to DER: ", err)
            end

            r.ngx_ssl_cert_chain = der_cert_chain
        else
            table_insert(err, "open ngx cert failed: " .. r.ngx_ssl_cert)
        end

        local f = io_open(r.ngx_ssl_key)
        if f then
            local pem_pkey = f:read("*a")
            f:close()

            local der_pkey, err = ssl.priv_key_pem_to_der(pem_pkey)
            if not der_pkey then
                table_insert(err, "failed to convert pkey from PEM to DER: ", err)
            end

            r.ngx_ssl_pkey = der_pkey
        else
            table_insert(err, "open ngx pkey failed: " .. r.ngx_ssl_key)
        end]]
    end

    -- server

    r.is_star = r.is_star or false
    twaf_func.type_check(r.is_star, "is_star", "boolean", err)
    
    if _type(r.host) == "table" and not r.host[2] then
        r.host = r.host[1]
    end

    if _type(r.host) == "string" then

        r.host_type = is_type.string

        if r.host == ".*" then
            r.is_star = true
            cache_key = false
        end

    elseif _type(r.host) == "table" then

        r.host_type = is_type.table

        for j, h in ipairs(r.host) do
            if h == ".*" then r.is_star = true end
            twaf_func.type_check(h, "host", "string", err)
        end
    else
        table_insert(err, "host: string or table expected, got " .. _type(r.host))
    end
    
    if not r.port then r.port = r.ngx_ssl and 443 or 80 end
    twaf_func.type_check(r.port, "port", "number", err)

    r.path = r.path or "/"
    twaf_func.type_check(r.path, "path", "string", err)

    r.url_case_sensitive = r.url_case_sensitive or false
    twaf_func.type_check(r.url_case_sensitive, "url_case_sensitive", "boolean", err)

    r.url_case_option = r.url_case_sensitive and "jo" or "jio"

    r.server_ssl = r.server_ssl or false
    twaf_func.type_check(r.server_ssl, "server_ssl", "boolean", err)

    r.forward = r.forward or ""
    twaf_func.type_check(r.forward, "forward", "string", err)

    if r.forward_addr then
        if _type(r.forward_addr) == "string" then

            r.forward_addr_type = is_type.string
            if not r.forward_port then r.forward_port = r.server_ssl and 443 or 80 end
            twaf_func.type_check(r.forward_port, "forward_port", "number", err)

            if r.forward_addr == ".*" then
                r.tflag = true
                cache_key = false
            end

        elseif _type(r.forward_addr) == "table" then

            r.forward_addr_type = is_type.table
            twaf_func.type_check(r.forward_port, "forward_port", "table", err)

            for j, a in ipairs(r.forward_addr) do
                twaf_func.type_check(a, "forward_addr", "string", err)
                twaf_func.type_check(r.forward_port[j], "forward_port", "number", err)
                if a == ".*" then
                    cache_key = false
                    table_insert(err, "not allow * in forward_addr array")
                end
            end

        else
            table_insert(err, "forward_addr: string or table expected, got " .. _type(r.forward_addr))
        end

    else -- r.forward_addr == nil
        r.forward_addr = ""
        r.forward_port = r.forward_port or 80
    end

    r.policy = r.policy or twaf.config.global_conf_uuid
    twaf_func.type_check(r.policy, "policy", "string", err)

    r.uuid = r.uuid or twaf_func:random_id(16, true)
    twaf_func.type_check(r.uuid, "uuid", "string", err)

    --------------------------------------

    local ft = r.forward_timeout
    if ft then
        if ft < 0 then
            table_insert(err, "forward_timeout must greater than 0")
        end
        if ft == 0 then
            r.forward_timeout = nil
        end
    end
    
    if cache_key == true then
        r.cache_key = string_format("%s%d%s", twaf_func:table_to_string(r.host), r.port, r.ngx_ssl)
    else
        r.cache_key = nil
    end
    
    if #err > 0 then return false, err end
    
    return true
end

function _M.init(_twaf, cf)

    local err =  {}

    -- state
    cf.state = cf.state == nil and true or cf.state
    twaf_func.type_check(cf.state, "state", "boolean", err)

    if not cf.state then -- cf.state == false
        return true
    end

    -- log_state
    cf.log_state = cf.log_state == nil and true or cf.log_state
    twaf_func.type_check(cf.log_state, "log_state", "boolean", err)

    twaf_func.type_check(cf.shm, "shm", "string", err)

    cf.dict_state = cf.dict_state or false
    twaf_func.type_check(cf.dict_state, "dict_state", "boolean", err)

    -- action  action_meta
    cf.action = cf.action or "DENY"
    local f, a, m = twaf_action.is_action(cf.action, cf.action_meta)
    if not f then table_insert(err, a) end
    cf.action = a
    cf.action_meta = m

    -- rules
    if _type(cf.rules) ~= "table" then
        table_insert(err, "rules: table expected, got " .. _type(cf.rules))
        return false, err
    end

    for _, r in ipairs(cf.rules) do
        _M.rule_init(r, err)
    end

    cf.rfast = _M.rules_cache_init(cf.rules)

    if #err > 0 then return false, err end

    return true
end

return _M
