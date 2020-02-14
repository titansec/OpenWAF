
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.1"
}

local  cjson                = require "cjson.safe"
local  twaf_opts            = require "lib.twaf.inc.opts"
local  twaf_func            = require "lib.twaf.inc.twaf_func"
local  twaf_request         = require "lib.twaf.inc.request"
local  twaf_operators       = require "lib.twaf.inc.operators"
local  twaf_transforms      = require "lib.twaf.inc.transforms"
local  twaf_conf            = require "lib.twaf.twaf_conf"

local  modules_name         = "twaf_secrules"
local  ngx_var              = ngx.var
local  ngx_shared           = ngx.shared
local  ngx_req_get_method   = ngx.req.get_method
local  ngx_req_http_version = ngx.req.http_version
local  ngx_req_get_headers  = ngx.req.get_headers
local  ngx_log              = ngx.log
local  ngx_ERR              = ngx.ERR
local  ngx_DONE             = ngx.DONE
local  ngx_re_find          = ngx.re.find
local  ngx_header           = ngx.header
local  io_open              = io.open
local _type                 = type
local _next                 = next
local _tostring             = tostring
local _tonumber             = tonumber
local  table_insert         = table.insert
local  str_upper            = string.upper
local  str_lower            = string.lower
local _transforms           = twaf_transforms.transforms
local _opts                 = twaf_opts.opts
local _copy_table           = twaf_func.copy_value
local _operators            = twaf_operators.operators
local _parse_dynamic_value  = twaf_func.parse_dynamic_value
local _table_to_string      = twaf_func.table_to_string
local  func_parse_var       = twaf_request.parse_var
local _get_vars             = twaf.get_vars

local function _log_action(_twaf, rule, sctx)

    local info       = {}
    info.id          =  rule.id
    info.opts        =  rule.opts
    info.action_meta = _tostring(rule.meta) or "-"
    info.action      =  sctx.action or rule.action
    info.version     =  rule.release_version.."-"..rule.charactor_version
    info.severity    =  rule.severity
    info.rule_name   =  rule.rule_name
    info.log_state   =  rule.log_state
    sctx.action      =  nil

    return twaf_func:rule_log(_twaf, info)
end

local function _parse_var(_twaf, gcf, var, parse)

    if _type(var) ~= "table" then
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
    
    return func_parse_var[parse[1]](_twaf, gcf, var, parse[2])
end

local function _do_transform(_twaf, data, transform, t_type)

    if transform == "counter" then
        return _transforms(nil, transform, data)
    end

    if t_type == 1 then -- is_type = {table = 1, string = 2}
        for _, v in ipairs(transform) do 
            data = _do_transform(_twaf, data, v, 2)
        end
    else
        if _type(data) == "table" then
            for k, v in pairs(data) do
                data[k] = _do_transform(_twaf, v, transform, 2)
            end
        else
            if not data then
                return data
            end

            return _transforms(nil, transform, data)
        end
    end

    return data
end



local function _do_operator(_twaf, sctx, rule, data, pattern, req, p_is_table)

    local value = "nil"
    
    if _type(data) == "table" then
        for _, v in pairs(data) do
            local _match, value = _do_operator(_twaf, sctx, rule, v, pattern, req, p_is_table)
            if _match then
                return true, value
            end
        end
    else
        if data == nil then
            return false
        end
        
        if p_is_table == true then -- pattern is table
            for _, v in pairs(pattern) do
                local _match, value = _do_operator(_twaf, sctx, rule, data, v, req, false)
                if _match then
                    return true, value
                end
            end
        else
            
            if rule.parse_pattern == true then
                pattern = _parse_dynamic_value(nil, pattern, req)
            end
            
            return _operators(nil, rule.operator, data, pattern, sctx)
        end
    end
    
    return false, value
end

local function _parse_vars(_twaf, rule, ctx, sctx)

    local is_match      = false
    local value         = nil
    local data          = nil
    local transform     = rule.transform
    local req           = ctx.req
    local dis_var       = sctx.cf.disable_vars
    local v_cache       = sctx.v_cache
    local v_cache_k     = sctx.v_cache_k
    local t_cache       = sctx.t_cache
    local t_cache_k     = sctx.t_cache_k
    local skipe         = false
    local flag          = false

    if rule.pset then rule.pattern = _twaf.config.pset[rule.pset] end

    for _, v in ipairs(rule.vars) do
--[[
        if v.var_type == "function" then
            is_match, value = v.var(_twaf, rule, ctx)
            
        elseif v["function"] then
            is_match, value = _twaf.modfactory[v.var][v.function](nil, _twaf)
        elseif _type(req[v.var]) == "function" then
            data = req[v.var](_twaf)
        else
]]
        if not v.storage then
        
            if v.shm_key or ngx_shared[v.var] then
	    
                local specific = v.parse.specific
		
                if not specific then
                    data = nil
                else
		
                    local dict = _get_vars(nil, v.var, req)
                    local key = v.shm_key
		    
                    if not key then
                        key = ""
                        if dict then key = dict:get("default_key") or "" end
                    end
		    
                    key = _parse_dynamic_value(nil, key .. specific, req)
                    data = dict:get(key)
                end
            else
	    
                data = t_cache[v.cache_vt]
                
                if not data and not t_cache_k[v.cache_vt] then 
                
                    data = v_cache[v.cache_v]
                    
                    if not data and not v_cache_k[v.cache_v] then
                        if dis_var and dis_var[v.var] then 
                            skipe = true 
                            data = nil
                        else
                            data = _parse_var(_twaf, sctx.gcf, _get_vars(nil, v.var, req), v.parse)  -- 800 -> 500 ----_twaf.get_vars to _get_vars----> 520     870->575    900->640
                        end
                        
                        if v.cache_v then -- cache var value
                            v_cache[v.cache_v] = data
                            if data == nil then v_cache_k[v.cache_v] = true end
                        end
                    end
                else
                    skipe = true
                end
            end
            
        else
            data = _parse_var(_twaf, sctx.gcf, sctx.storage[v.var], v.parse)
        end
	
      --end

        if not skipe then
            data = _copy_table(nil, data)

            if _type(data) == "table" and not _next(data) then
                data = nil
            end

            if transform then
                data = _do_transform(_twaf, data, transform, rule.transform_type)
                if v.cache_vt then -- cache
                    t_cache[v.cache_vt] = data
                    if data == nil then t_cache_k[v.cache_vt] = true end
                end
            end

        end

        if data ~= nil then
            is_match, value = _do_operator(_twaf, sctx, rule, data, rule.pattern, req, rule.p_is_table)
            if is_match ~= rule.op_negated then  -- 160 -> 146
                -- capture
                if rule.operator == "regex" and _type(value) == "table" then
                    req.TX["0"] = value[0]
                    for m, n in ipairs(value) do
                        req.TX[_tostring(m)] = n
                    end
                else
                    req.TX["0"] = value
                end
                
                if value then
                    twaf_func.matched_var(req, v, req.TX["0"])
                end
                
                return true
            end
        end

        data     = nil
        value    = nil
        is_match = false
        skipe    = false
    end
    
    return false
end

local function _parse_fn(_twaf, rule, req, ctx)

    local fn = rule[ctx.phase]
    
    if _type(fn) ~= "function" then
        return false
    end
    
    local is_match, value = fn(_twaf, rule, req, ctx)
    
    if is_match then
        if value then
            twaf_func.matched_var(req, "fn: " .. rule.id, value)
        end
        
        return true
    end
    
    return false
end

local function _process_rule(_twaf, rule, ctx, sctx)

    local  req      =  ctx.req
    local  is_match =  true
    local _match    =  rule.match
    
    if not _match then
        is_match = _parse_fn(_twaf, rule, req, ctx)
    else
        for k, r in ipairs(_match) do

            local res = _parse_vars(_twaf, r, ctx, sctx)
            
            -- delete patterns from pf
            sctx.patterns = nil
            
            if res == false then
                is_match              = false
                req.MATCHED_VARS      = {}
                req.MATCHED_VAR_NAMES = {}
                break
            end
        end
        
    end

    if is_match == true then
        req.RULE = rule

        for k, v in pairs(rule.opts) do
            _opts(nil, _twaf, ctx, sctx, req, k, v)
        end

        return _log_action(_twaf, rule, sctx)
    end
    
    sctx.action = nil
    
    return false
end

local function _enable_id(_twaf, cf, rule, ctx, sctx)

    local flag
    local id         =  rule.id
    local req        =  ctx.req
    local system_rid =  sctx.system_rules_id
    local exclude    =  system_rid[id] or cf.rules_id[id] or {}
    
    if rule.disable or rule.phase ~= ctx.phase then return false end
    
    if rule.recommend < cf.recommend then
            sctx.action = "WARN"
    end
    
    if rule.disable then
        return false
    end
    
    for _, r in ipairs(exclude) do
        
        flag = true
        
        for k, v in pairs(r) do
            local from, to, err = ngx_re_find(_get_vars(nil, k, req), v)
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

    for _, rule in ipairs(rules or {}) do
        if _enable_id(_twaf, sctx.cf, rule, ctx, sctx) then
            local res = _process_rule(_twaf, rule, ctx, sctx)
            -- res: true false ngx.OK ngx.DONE
            if res == true or res == ngx_DONE then
                return res
            end
        end
    end

    return false
end

local function _process_rules_ids(_twaf, rids, ctx, sctx)
    local rule
    local rules = _twaf.config.rules
    for _, rid in ipairs(rids or {}) do
        rule = rules[rid]
        if rule and _enable_id(_twaf, sctx.cf, rule, ctx, sctx) then
            local res = _process_rule(_twaf, rule, ctx, sctx)
            -- res: true false ngx.OK ngx.DONE
            if res == true or res == ngx_DONE then
                return res
            end
        end
    end

    return false
end

local function _process(_twaf, ctx, sctx)

    if sctx.message and sctx.gcf.simulation == false then
        return true
    end
    
    if ctx.interrupt == true then
        return true
    end
    
    local res       =  false
    local rules     =  {}
    local storage   =  sctx.storage
    local shm       =  sctx.rules_shm
    local req       =  ctx.req
    local key       =  modules_name.."_"..req.POLICYID
    
    repeat
    
    -- user defined rules
    rules = (sctx.cf.user_defined_rules or {})[ctx.phase]
    res = _process_rules(_twaf, rules, ctx, sctx)
    if res ~= false then break end
    
    -- system rules
    local iwsc_result = true
    if _type(ctx.iwsc_result) == "number" and ctx.iwsc_result >= 0 then
        iwsc_result = false
    end
    
    if sctx.cf.system_rules_state ~= true then
        iwsc_result = false
    end
    
    if iwsc_result == true then
        local set_ids = sctx.cf.ruleset_ids
        if not set_ids then
            rules = _twaf.config.rule_sets.twaf_default_rule_set[ctx.phase]
            res   = _process_rules_ids(_twaf, rules, ctx, sctx)
        else
            for _, sid in ipairs(set_ids) do
                rules = _twaf.config.rule_sets[sid][ctx.phase]
                res = _process_rules_ids(_twaf, rules, ctx, sctx)
                if res ~= false then break end
            end
        end
    end
    
    until true
    
    if _type(storage) == "table" and _next(storage) then
        shm:set(key.."_storage", cjson.encode(storage))
    end
    
    return res
end

function _M.handler(self, _twaf)

    local ctx  = _twaf:ctx()
    local cf   = _twaf:get_config_param(modules_name)
    local gcf  = _twaf:get_config_param("twaf_global")
    
    if not cf.state or ctx.trust == true then
        return true
    end
    
    if not ctx[modules_name] then ctx[modules_name] = {} end
    local sctx =  ctx[modules_name]
    
    local req        =  ctx.req
    local dict_name  =  cf.shared_dict_name or gcf.dict_name
    local shm        =  ngx_shared[dict_name]
    local key        =  modules_name.."_"..req.POLICYID
    local bytes_in   = _twaf:get_vars("BYTES_IN", req)
    
    sctx.cf          = cf
    sctx.gcf         = gcf
    sctx.rules_shm   = shm
    sctx.phase       = ctx.phase
    sctx.storage     = cjson.decode(shm:get(key.."_storage"))
    sctx.v_cache     = {}
    sctx.v_cache_k   = {}
    sctx.t_cache     = {}
    sctx.t_cache_k   = {}
    sctx.system_rules_id = _twaf.config.twaf_policy.system_rules_id or {}
    
    if not cf.reqbody_state or bytes_in > cf.reqbody_limit then
        cf.disable_vars["REQUEST_BODY"] = 1
    end
    
    local res = _process(_twaf, ctx, sctx)
    
    return res
end

function _M.header_filter(self, _twaf)

    local ctx  = _twaf:ctx()
    local sctx =  ctx[modules_name]
    
    if  not sctx or sctx.header_filter or 
        not sctx.cf.header_filter_state or 
        ctx.trust == true then
        return true
    end
    
    sctx.header_filter = true
    
    local res = _process(_twaf, ctx, sctx)
    
    if sctx.cf.body_filter_state then
        ngx_header['Content-Length'] = nil
    end
    
    return res
end

function _M.body_filter(self, _twaf)

    local ctx  = _twaf:ctx()
    local sctx =  ctx[modules_name]
    
    if  not sctx or ctx.short_circuit or 
        not sctx.cf.body_filter_state or
        ctx.trust == true then
        return true
    end
    
    local bytes_sent = _twaf:get_vars("BYTES_SENT", ctx.req)
    if bytes_sent and bytes_sent > sctx.cf.respbody_limit then
        return true
    end
    
    return _process(_twaf, ctx, sctx)
end

function _M.init(_twaf, cf)
    local err =  {}

    cf.state = cf.state == nil and true or cf.state
    twaf_func.type_check(cf.state, "state", "boolean", err)

    cf.reqbody_state = cf.reqbody_state or false
    twaf_func.type_check(cf.reqbody_state, "reqbody_state", "boolean", err)

    cf.header_filter_state = cf.header_filter_state or false
    twaf_func.type_check(cf.header_filter_state, "header_filter_state", "boolean", err)

    cf.body_filter_state = cf.body_filter_state or false
    twaf_func.type_check(cf.body_filter_state, "body_filter_state", "boolean", err)

    cf.system_rules_state = cf.system_rules_state or false
    twaf_func.type_check(cf.system_rules_state, "system_rules_state", "boolean", err)

    if cf.reqbody_limit then
        twaf_func.type_check(cf.reqbody_limit, "reqbody_limit", "number", err)
    end

    if cf.respbody_limit then 
        twaf_func.type_check(cf.respbody_limit, "respbody_limit", "number", err)
    end

    twaf_func.type_check(cf.pre_path, "pre_path", "string", err)
    twaf_func.type_check(cf.path, "path", "string", err)
    
    if cf.disable_vars then
        twaf_func.type_check(cf.disable_vars, "disable_vars", "table", err)
    end

    if _type(cf.disable_vars) == "table" then
        local tb = {}
        for _, dv in ipairs(cf.disable_vars) do
            tb[str_upper(dv)] = 1
        end
        cf.disable_vars = tb
    end

    cf.recommend = cf.recommend or 9
    twaf_func.type_check(cf.recommend, "recommend", "number", err)

    cf.user_defined_rules = cf.user_defined_rules or {}
    twaf_func.type_check(cf.user_defined_rules, "user_defined_rules", "table", err)
    
    cf.user_defined_rules_id = {}

    local reason = {}
    local tb = {}
    for _, r in ipairs(cf.user_defined_rules) do
        local res, er = twaf_func:check_rules(cf.user_defined_rules_id, r)
        if res then
            tb[r.id] = r.phase
        else
            table_insert(reason, er)
        end
    end

    if #reason > 0 then
        table_insert(err, "user_defined_rules: " .. twaf_func:table_to_string(reason))
        return false, err
    end
    
    twaf_func.table_merge(cf.user_defined_rules_id, tb)

    cf.user_defined_rules = twaf_conf:rule_group_phase_by_list(nil, cf.user_defined_rules)

    -- cf.ruleset_ids
    -- cf.rule_sets
    local rset
    local rids = {access = {}, header_filter = {}, body_filter = {}}
    local rsets = _twaf.config.rule_sets
    if not cf.ruleset_ids then 
        cf.rule_sets = rsets.twaf_default_rule_set
    else
        for _, sid in ipairs(cf.ruleset_ids) do
            rset = rsets[sid]
            if not rset then 
                table_insert(reason, "in rule_sets not found "..sid) 
            else
                for phase, ids in pairs(rset) do
                    rids[phase] = rids[phase] or {}
                    for _, rid in ipairs(ids) do
                        table_insert(rids[phase], rid)
                    end
                end
            end
        end

        if #reason > 0 then
            table_insert(err, "ruleset_ids: " .. twaf_func:table_to_string(reason))
            return false, err
        end

        cf.rule_sets = rids
    end

    if #err > 0 then return false, err end

    return true
end

return _M
