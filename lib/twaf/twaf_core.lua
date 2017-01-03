
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.3.170103_beta"
}

local cjson                                = require "cjson"
local twaf_func                            = require "lib.twaf.inc.twaf_func"
local twaf_request                         = require "lib.twaf.inc.request"

local mt            = { __index = _M, }
local ngx_log       = ngx.log
local ngx_WARN      = ngx.WARN
local ngx_ERR       = ngx.ERR
local ngx_DONE      = ngx.DONE
local ngx_time      = ngx.time
local ngx_get_phase = ngx.get_phase

function _M.new(self, config)

    self.modfactory            = {}
    self.access_modules        = {}
    self.header_filter_modules = {}

    return setmetatable({
        config = config
    }, mt)
end

-- A safe place in ngx.ctx for the current module instance (self).
function _M.ctx(self)
    local id  = tostring(self)
    local ctx = ngx.ctx[id]
    if not ctx then
        ctx = {
            request  = {},
            debug    = {},
            events   = {
                log  = {},
                stat = {},
                info = ""
            },
        }
        ngx.ctx[id] = ctx
    end
    return ctx
end

function _M.register_modules(self, modules)

    if type(modules) ~= "table" then
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

    local request     = self:ctx().request or {}
    local policy_uuid = request.POLICYID
    
    if policy_uuid and policy_uuid ~= "twaf_default_conf" then
        local policy = self.config.twaf_policy[policy_uuid]
        if policy == nil then
            ngx.log(ngx.ERR, "No policy '"..policy_uuid.."'")
            return
        end
        
        return policy[param]
    end
    
    return self.config.twaf_default_conf[param]
end

function _M.get_modules_config_param(self, modules, param)

    local request     = self:ctx().request or {}
    local policy_uuid = request.POLICYID
    
    if policy_uuid and policy_uuid ~= "twaf_default_conf" then
        local policy = self.config.twaf_policy[policy_uuid]
        if policy == nil then
            ngx.log(ngx.ERR, "No policy '"..policy_uuid.."'")
            ngx.exit(500)
            return
        end
        
        local mod = policy[modules]
        if mod == nil then
            ngx.log(ngx.ERR, "No module '"..modules.."' in policy '"..policy_uuid.."'")
            ngx.exit(500)
            return
        end
        
        return mod[param]
    end
    
    local mod = self.config.twaf_default_conf[modules]
    if mod == nil then
        ngx.log(ngx.ERR, "No module '"..modules.."' in policy 'twaf_default_conf'")
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

function _M.run(self, _twaf)

    local res
    local phase         =  ngx.get_phase()
    local modules_order = _twaf:get_config_param("modules_order") or {}
    local ctx           = _twaf:ctx()
    local request       =  ctx.request
    
    -- request variables
    if twaf_request.request[phase] then
        twaf_request.request[phase](_twaf, request, ctx)
    end
    
    ctx.phase   =  phase
    
    if not modules_order.access or #modules_order.access == 0 then
        return
    end
    
    if phase == "rewrite" then
    
        -- config synchronization
        twaf_func:syn_config(_twaf)
        
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
        
    elseif phase == "body_filter" then
    
        if ngx.ctx.reset_connection == true then return ngx.ERROR end
        
        _filter_order(_twaf, phase, modules_order)
        
        if ngx.ctx.reset_connection == true then return ngx.ERROR end
        
    elseif phase == "log" then
    
        -- reqstat
        twaf_reqstat:reqstat_log_handler(ctx.events.stat, request.POLICYID)
        
        -- log
        local mod = _twaf.modfactory["twaf_log"]
        if mod and mod.log then
            mod:log(_twaf)
        end
        
        -- collect
        collectgarbage("collect")
        
    else -- "balancer" "ssl_cert"
    
        local mod = _twaf.modfactory["twaf_"..phase]
        if mod and mod[phase] then
            mod[phase](mod, _twaf)
        end
        
    end
end

return _M
