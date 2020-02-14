
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.0"
}

local cjson                                = require "cjson"
local twaf_func                            = require "lib.twaf.inc.twaf_func"
local twaf_request                         = require "lib.twaf.inc.request"
local twaf_opts                            = require "lib.twaf.inc.opts"
local lrucache                             = require "resty.lrucache"

local mt            = { __index = _M, }
local ngx_log       = ngx.log
local ngx_WARN      = ngx.WARN
local ngx_ERR       = ngx.ERR
local ngx_DONE      = ngx.DONE
local ngx_time      = ngx.time
local ngx_get_phase = ngx.get_phase
local ngx_header    = ngx.header
local ngx_ERROR     = ngx.ERROR
local ngx_var       = ngx.var
local string_format = string.format
local table_insert  = table.insert
local table_concat  = table.concat
local _tostring     = tostring
local _type         = type

function _M.new(self, config)

    self.modfactory            = {}
    self.access_modules        = {}
    self.header_filter_modules = {}
    
    local lruc, err = lrucache.new(200)
    if not lruc then
        return error("failed to create the cache: " .. (err or "unknown"))
    end

    return setmetatable({
        config = config,
        lruc   = lruc
    }, mt)
end

-- A safe place in ngx.ctx for the current module instance (self).
function _M.ctx(self)
    local ctx = ngx.ctx
    if not ctx.req then
        ctx.req = {
            TX = {},
            MATCHED_VARS = {},
            MATCHED_VAR_NAMES = {},
            POLICYID = self.config.global_conf_uuid,
            NGX_VAR = ngx_var
        }
        ctx.storage = {}
        ctx.debug   = {}
        ctx.events  = {
            log     = {},
            stat    = {},
            info    = ""
        }
    end
    return ctx
end

function _M.get_vars(self, var, req)
    return req[var] or (twaf_request.vars[var] and twaf_request.vars[var](req) or nil)
end

function _M.get_vars_no_cache(self, var, req)
    return twaf_request.vars[var] and twaf_request.vars[var](req) or nil
end

function _M.register_modules(self, modules)

    if _type(modules) ~= "table" then
        return false
    end
    
    for modules_name, path in pairs(modules) do
        self.modfactory[modules_name] = require(path)
    end
    
    return true
end

function _M.get_default_config_param(self, param)
    return self.config.twaf_default_conf[param]
end

function _M.get_config_param(self, param)

    local policy_uuid = self:ctx().req.POLICYID
    
    if policy_uuid and policy_uuid ~= "twaf_default_conf" then
        local policy = self.config.twaf_policy[policy_uuid]
        if policy == nil then
            ngx_log(ngx_ERR, "No policy: "..policy_uuid)
            return
        end
        
        return policy[param]
    end
    
    return self.config.twaf_default_conf[param]
end

function _M.get_modules_config_param(self, modules, param)

    local policy_uuid = self:ctx().req.POLICYID
    
    if policy_uuid and policy_uuid ~= "twaf_default_conf" then
        local policy = self.config.twaf_policy[policy_uuid]
        if policy == nil then
            ngx_log(ngx_ERR, "No policy: "..policy_uuid)
            ngx.exit(500)
            return
        end
        
        local mod = policy[modules]
        if mod == nil then
            ngx_log(ngx_ERR, string_format("No module '%s' in policy '%s'", modules, policy_uuid))
            ngx.exit(500)
            return
        end
        
        return mod[param]
    end
    
    local mod = self.config.twaf_default_conf[modules]
    if mod == nil then
        ngx_log(ngx_ERR, string_format("No module '%s' in policy 'twaf_default_conf'", modules))
        ngx.exit(500)
        return
    end
    
    return mod[param]
end

local function _filter_order(_twaf, phase, modules_order)

    local tb = {}
    
    if modules_order[phase] and #modules_order[phase] ~= 0 then
        tb = modules_order[phase]
    else
        tb = modules_order.access
    end
    
    for i = #tb, 1, -1 do
        local mod = _twaf.modfactory[tb[i]]
        if mod and mod[phase] and mod[phase](mod, _twaf) == ngx_DONE then
            break
        end
    end
end

local function _add_resp_headers(_twaf, ctx)
    local cf = _twaf:get_config_param("twaf_add_resp_header") or {}
    ngx_header["X-Tt-Request-Id"] = _twaf:get_vars("UNIQUE_ID", ctx.req)
    
    for k, v in pairs(ctx.add_resp_headers or {}) do
        cf[k] = v
    end
    
    for k, v in pairs(cf) do
        if v ~= "nil" then
            ngx_header[k] = twaf_func:parse_dynamic_value(v, ctx.req)
        end
    end
end

local function _get_response_body(ctx)

    local req = ctx.req
    
    req.RESPONSE_BODY   = ngx.arg[1]
end

function _M.init(self)
    local default_init_register = self:get_default_config_param("init_register")
    _M:register_modules(default_init_register)

    local mod = self.modfactory
    local cf, res, err, policy

    -- access_rule
    cf  = self.config.twaf_access_rule
    res, err = self.modfactory.twaf_access_rule.init(self, cf)
    assert(res, twaf_func:table_to_string(err))

    -- rules -> twaf_conf.lua

    -- twaf_default_conf
    policy = self.config.twaf_default_conf or {}
    for pn, pv in pairs(policy) do
        if mod[pn] and mod[pn]["init"] then
            res, err = mod[pn]["init"](self, pv, policy)
            assert(res, twaf_func:table_to_string(err))
        end
    end

    -- policy
    cf = self.config.twaf_policy.policy_uuids or {}
    for uuid, _ in pairs(cf) do
        policy = self.config.twaf_policy[uuid] or {}
        for pn, pv in pairs(policy) do
            if mod[pn] and mod[pn]["init"] then
                res, err = mod[pn]["init"](self, pv, policy)
                assert(res, twaf_func:table_to_string(err))
            end
        end
    end
end

function _M.run(self, _twaf)

    local res
    local phase         =  ngx_get_phase()
    local modules_order = _twaf:get_config_param("modules_order") or {}
    local ctx           = _twaf:ctx()
    
    ctx.phase       =  phase
    ctx.req.phase_n =  twaf_request.phase[phase]
    
    if not modules_order.access or #modules_order.access == 0 then
        return
    end
    
    if phase == "init_worker" then
        
        for _, modules_name in ipairs(modules_order.access) do
            local mod = _twaf.modfactory[modules_name]
            if mod and mod[phase] then
                mod[phase](_twaf)
            end
        end
    
    elseif phase == "rewrite" then
    
        -- config synchronization
        twaf_func:syn_config(_twaf)
        
        _twaf:get_vars("HTTP_VERSION", ctx.req)
        _twaf:get_vars("RAW_HEADER", ctx.req)
        
        _twaf.modfactory.twaf_access_rule:handler(_twaf)
        
    elseif phase == "access" then
        
        for _, modules_name in ipairs(modules_order.access) do
            local mod = _twaf.modfactory[modules_name]
            if mod and mod["handler"] and mod:handler(_twaf) == ngx_DONE then
                break
            end
        end
        
    elseif phase == "header_filter" then
    
        _filter_order(_twaf, phase, modules_order)
        
        _add_resp_headers(_twaf, ctx)
        
    elseif phase == "body_filter" then
    
       _get_response_body(ctx)
    
        if ctx.reset_connection == true then return ngx_ERROR end
        
         twaf_opts:opts(_twaf, ctx, nil, nil, "respbody_replacement", {})
         
        _filter_order(_twaf, phase, modules_order)
        
        if ctx.reset_connection == true then return ngx_ERROR end
    
    elseif phase == "log" then
    
        -- reqstat
        twaf_reqstat:reqstat_log_handler(_twaf)
        
        -- log
        _twaf.modfactory.twaf_log:log(_twaf)
        
        -- print _G
        twaf_func:print_G(_twaf)
        
        -- print ctx
        twaf_func:print_ctx(_twaf)
        
        -- collect
        -- collectgarbage("collect")
        
    else -- "balancer" "ssl_cert"
    
        local mod = _twaf.modfactory["twaf_"..phase]
        if mod and mod[phase] then
            mod[phase](mod, _twaf)
        end
        
    end
end

return _M
