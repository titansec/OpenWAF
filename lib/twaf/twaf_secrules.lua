
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.5"
}

local cjson                = require "cjson.safe"
local twaf_opts            = require "lib.twaf.inc.opts"
local twaf_func            = require "lib.twaf.inc.twaf_func"
local twaf_request         = require "lib.twaf.inc.request"
local twaf_operators       = require "lib.twaf.inc.operators"
local twaf_transforms      = require "lib.twaf.inc.transforms"

local modules_name         = "twaf_secrules"
local ngx_var              = ngx.var
local ngx_shared           = ngx.shared
local ngx_req_get_method   = ngx.req.get_method
local ngx_req_http_version = ngx.req.http_version
local ngx_req_get_headers  = ngx.req.get_headers

local function _log_action(_twaf, sctx)

    local opts =  sctx.opts or {}
    
    if opts.nolog == false or opts.log == true then
        sctx.log_state = true
    else
        sctx.log_state = false
    end
    
    return twaf_func:rule_log(_twaf, sctx)
end

local function _parse_var(_twaf, gcf, var, parse)

    if type(var) ~= "table" then
        if not parse then
            return var
        else
            -- TODO: set invalid rule
            return nil
        end
    end
    
    if not parse then
        return var
    end
    
    -- just one pair data in this parse
    local key, value = next(parse)
    
    return twaf_request.parse_var[key](_twaf, gcf, var, value)
end

local function _do_transform(_twaf, data, transform)

    if transform == "counter" then
        return twaf_transforms:transforms(transform, data)
    end

    local t = {}
    
    if type(transform) == "table" then
        for _, v in ipairs(transform) do 
            t = _do_transform(_twaf, data, v)
        end
    else
        if type(data) == "table" then
            for k, v in pairs(data) do
                t[k] = _do_transform(_twaf, v, transform)
            end
        else
            if not data then
                return data
            end
            
            return twaf_transforms:transforms(transform, data)
        end
    end
    
    return t
end

local function _do_operator(_twaf, sctx, rule, data, pattern, request, pf)

    -- get pattern from file
    -- not support multi files
    if pf then
        local patterns = sctx.patterns
        local gcf      = sctx.gcf
        local shm      = sctx.rules_shm
        
        if patterns == false then
            return false
        end
            
        if not patterns then
            local patterns = cjson.decode(shm:get(pf))
            if not patterns then 
                patterns = {}
                
                local f = io.open(pf)
                if not f then
                    ngx.log(ngx[gcf.debug_log_level], "open failed -- "..tostring(pf))
                    return false
                end
                
                repeat
                
                local n = f:read()
                if not n then break end
                table.insert(patterns, n)
                
                until false
                
                f:close()
                shm:set(pf, twaf_func:table_to_string(patterns))
            end
            
            sctx.patterns = patterns
            
            if not next(patterns) then
                ngx.log(ngx[gcf.debug_log_level], "file empty -- "..tostring(pf))
                sctx.patterns = false
                return false
            end
        end
        
        pattern = patterns
    end
    
    local value = "nil"
    
    if type(data) == "table" then
        for _, v in pairs(data) do
            local match, value = _do_operator(_twaf, sctx, rule, v, pattern, request)
            if match then
                return true, value
            end
        end
    else
        if data == nil then
            return false
        end
        
        if type(pattern) == "table" then
            for _, v in pairs(pattern) do
                local match, value = _do_operator(_twaf, sctx, rule, data, v, request)
                if match then
                    return true, value
                end
            end
        else
            
            if rule.parse_pattern == true then
                pattern = twaf_func:parse_dynamic_value(pattern, request)
            end
            
            return twaf_operators:operators(rule.operator, data, pattern, sctx)
        end
    end
    
    return false, value
end

local function _parse_vars(_twaf, rule, ctx, sctx)

    local match         = false
    local value         = nil
    local pf            = rule.pf
    local vars          = rule.vars
    local transform     = rule.transform
    local pattern       = rule.pattern
    local operator      = rule.operator
    local op_negated    = rule.op_negated or false
    local request       = ctx.request
    
    for _, v in ipairs(vars) do
    
        repeat
        
        ctx.var = tostring(v)
        
        -- check phase
        if v.phase and ctx.phase ~= v.phase then
            break
        end
        
        local data = nil
        
        if type(v.var) == "function" then
            match, value = v.var(_twaf, rule, ctx)
            
        elseif v["function"] then
            local modules_name = v.var:lower()
            local func         = v["function"]
            match, value = _twaf.modfactory[modules_name][func](nil, _twaf)
            
        elseif type(request[v.var]) == "function" then
            data = request[v.var](_twaf)
            
        else
            if not v.storage then
                data = _parse_var(_twaf, sctx.gcf, request[v.var], v.parse)
            else
                data = _parse_var(_twaf, sctx.gcf, sctx.storage[v.var], v.parse)
            end
        end
        
        if type(data) == "table" and not next(data) then
            data = nil
        end
        
        if transform then
            data = _do_transform(_twaf, data, transform)
        end
        
        if data == nil then
            break
        end
        
        if operator then
            match, value = _do_operator(_twaf, sctx, rule, data, pattern, request, pf)
        end
        
        if match ~= op_negated then
            -- capture
            if operator == "regex" and type(value) == "table" then
                request.TX["0"] = value[0]
                for m, n in ipairs(value) do
                    request.TX[tostring(m)] = n
                end
            else
                request.TX["0"] = value
            end
            
            request.MATCHED_VAR_NAME = v
            table.insert(request.MATCHED_VAR_NAMES, v)
            
            if value then
                request.MATCHED_VAR  = "\""..request.TX["0"].."\""
                table.insert(request.MATCHED_VARS, request.TX["0"])
            end
            
            return true
        else
            ctx.mp = nil
        end
        
        until true
    end
    
    return false
end

local function _parse_fn(_twaf, rule, request, ctx)

    local fn      = rule[ctx.phase]
    
    if type(fn) ~= "function" then
        return false
    end
    
    local match, value = fn(_twaf, rule, request, ctx)
    
    if match then
        if value then
            request.MATCHED_VAR = "\""..value.."\""
            table.insert(request.MATCHED_VARS, value)
        end
        
        return true
    end
    
    return false
end

local function _process_rule(_twaf, rule, ctx, sctx)

    local gcf            =  sctx.gcf
    local weight         =  rule.weight
    local opts           =  rule.opts or {}
    local rv             =  rule.release_version or "-"
    local cv             =  rule.charactor_version or "-"
    local request        =  ctx.request
    
    sctx.id              =  rule.id or "-"
    sctx.opts            =  opts
    sctx.action_meta     =  tostring(rule.meta) or "-"
    sctx.action          =  (rule.action or "pass"):upper()
    sctx.version         =  rv.."-"..cv
    sctx.severity        =  rule.severity or "-"
    sctx.rule_name       =  rule.rule_name
    
    if (tonumber(rule.recommend) or 9) < (tonumber(sctx.cf.recommend) or 9) then
        sctx.action = "WARN"
    end
    
    local rule_match = true
    
    if not rule.match then
        rule_match = _parse_fn(_twaf, rule, request, ctx)
        
    else
        for k, r in ipairs(rule.match) do
            
            ngx.log(ngx[gcf.debug_log_level], "ID: "..rule.id.." layer: "..tostring(k))
            
            local res = _parse_vars(_twaf, r, ctx, sctx)
            if res == false then
                rule_match                = false
                request.MATCHED_VARS      = {}
                request.MATCHED_VAR_NAMES = {}
                break
            end
            
            -- delete patterns from pf
            sctx.patterns = nil
        end
    end
    
    ngx.log(ngx[gcf.debug_log_level], "ID: "..rule.id.." match: "..tostring(rule_match))
    
    if rule_match == true then
        request.RULE = rule
        
        for k, v in pairs(opts) do
            twaf_opts:opts(_twaf, ctx, sctx, request, k, v)
        end
        
        return _log_action(_twaf, sctx)
    end
    
    return false
end

local function _enable_id(_twaf, cf, rule, ctx)

    local flag
    local request    =  ctx.request
    local system_rid = _twaf.config.twaf_policy.system_rules_id or {}
    local id         = system_rid[rule.id] or cf.rules_id[rule.id] or {}
    
    if rule.disable then
        return false
    end
    
    for _, r in ipairs(id) do
        
        flag = true
        
        for k, v in pairs(r) do
            local from, to, err = ngx.re.find(request[k], v)
            if not from then
                flag = false
                break
            end
        end
        
        if flag then
            -- disable
            return false
        end
    end
    
    return true

end

local function _process_rules(_twaf, rules, ctx, sctx)

    local phase = ctx.phase
    local cf    = sctx.cf
    local gcf   = sctx.gcf
    
    for _, rule in ipairs(rules or {}) do
        if _enable_id(_twaf, cf, rule, ctx) then
            if type(rule.phase) ~= "table" then
                rule.phase = {rule.phase}
            end
            
            local flags = twaf_func:table_has_value(rule.phase, phase)
            
            if flags == true then
                local res = _process_rule(_twaf, rule, ctx, sctx)
                -- res: true false ngx.OK ngx.DONE
                if res == true or res == ngx.DONE then
                    return res
                end
            end
        end
    end
    
    return false
end

local function _process(_twaf, ctx, sctx)

    if sctx.message and sctx.gcf.simulation == false then
        return true
    end
    
    local res       =  false
    local rules     =  {}
    local storage   =  sctx.storage
    local shm       =  sctx.rules_shm
    local request   =  ctx.request
    local key       =  modules_name.."_"..request.POLICYID
    local var_store =  {}
    
    for _, v in pairs(sctx.cf.disable_vars or {}) do
        var_store[v] = twaf_func:copy_value(request[v])
        request[v]   = nil
    end
    
    repeat
    
    -- user defined rules
    rules = sctx.cf.user_defined_rules or {}
    res = _process_rules(_twaf, rules, ctx, sctx)
    if res ~= false then break end
    
    -- system rules
    local iwsc_result = true
    if type(ctx.iwsc_result) == "number" and ctx.iwsc_result >= 0 then
        iwsc_result = false
    end
    
    if sctx.cf.system_rules_state ~= true then
        iwsc_result = false
    end
    
    if iwsc_result == true then
        rules = _twaf.config.rules[ctx.phase] or {}
        res   = _process_rules(_twaf, rules, ctx, sctx)
        if res ~= false then break end
    end
    
    until true
    
    for var_k, var_v in pairs(var_store) do
        request[var_k] = var_v
    end
    
    if type(storage) == "table" and next(storage) then
        shm:set(key.."_storage", cjson.encode(storage))
    end
    
    return res
end

function _M.handler(self, _twaf)

    local ctx  = _twaf:ctx()
    local cf   = _twaf:get_config_param(modules_name)
    local gcf  = _twaf:get_config_param("twaf_global")
    
    if not twaf_func:state(cf.state) or ctx.trust == true then
        return true
    end
    
    if not ctx[modules_name] then ctx[modules_name] = {} end
    local sctx =  ctx[modules_name]
    
    local request    = ctx.request
    local dict_name  = cf.shared_dict_name or gcf.dict_name
    local shm        = ngx_shared[dict_name]
    local key        = modules_name.."_"..request.POLICYID
    
    sctx.cf          = cf
    sctx.gcf         = gcf
    sctx.rules_shm   = shm
    sctx.phase       = ctx.phase
    sctx.storage     = cjson.decode(shm:get(key.."_storage"))
    
    if not cf.reqbody_state or request.BYTES_IN > cf.reqbody_limit then
        sctx.REQUEST_BODY    = twaf_func:copy_value(request.REQUEST_BODY)
        request.REQUEST_BODY = nil
    end
        
    local res = _process(_twaf, ctx, sctx)
    
    request.REQUEST_BODY = request.REQUEST_BODY or sctx.REQUEST_BODY
    
    return res
end

function _M.header_filter(self, _twaf)

    local ctx  = _twaf:ctx()
    local sctx =  ctx[modules_name]
    
    if  not sctx or sctx.header_filter or 
        not twaf_func:state(sctx.cf.header_filter_state) or 
        ctx.trust == true then
        return true
    end
    
    sctx.header_filter = true
    
    return _process(_twaf, ctx, sctx)
end

function _M.body_filter(self, _twaf)

    local ctx  = _twaf:ctx()
    local sctx =  ctx[modules_name]
    
    if  not sctx or ctx.short_circuit or 
        not twaf_func:state(sctx.cf.body_filter_state) or
        ctx.trust == true then
        return true
    end
    
    local bytes_sent = tonumber(ngx.var.bytes_sent) or 0
    if bytes_sent and bytes_sent > sctx.cf.respbody_limit then
        return true
    end
    
    return _process(_twaf, ctx, sctx)
end

return _M
