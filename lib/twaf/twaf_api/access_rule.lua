
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.6.0"
}

local twaf_func    = require "lib.twaf.inc.twaf_func"
local twaf_accr    = require "lib.twaf.twaf_access_rule"

_M.api = {}
_M.help = {}
_M.api.access_rule = {}

local ngx_shared    = ngx.shared
local table_insert  = table.insert

-- get access_rule, e.g: GET /api/access_rule/{user}/{uuid}
_M.api.access_rule.get        = function(_twaf, log, u)

    local rules    = _twaf.config.twaf_access_rule.rules
    
    if not u[2] then
        log.result = rules
        return
    end
    
    if not u[3] then
    
        local flag = false
        log.result = {}
        
        for i, rule in ipairs(rules) do
            if rule.user == u[2] then
                flag = true
                table_insert(log.result, rule)
            end
        end
        
        if flag == false then
            log.success = 0
            log.result  = nil
            log.reason  = "No any rule in user '"..u[2].."'"
        end
        
        return
    end
    
    local flag = false
    
    for i, rule in ipairs(rules) do
        if rule.user == u[2] then
            flag = true
            if rule.uuid == u[3] then
                log.result = rule
                return
            end
        end
    end
    
    log.success = 0
    
    if flag == true then
        log.reason  = "Not found access rule uuid: "..u[3].." in user: "..u[2]
    else
        log.reason  = "Not found access rule user: "..u[2]
    end
end

-- post access_rule, e.g: POST /api/access_rule/{user}/{pos}
-- post access_rule, e.g: POST /api/access_rule/{user}/uuid/{uuid}
_M.api.access_rule.post       = function(_twaf, log, u)

    -- post rules in batches
    local function _table_insert(rules, index, config, no_cache)
        local ret, err
        local ckey = false
        local am = _twaf.modfactory.twaf_access_rule
    
        if config[1] then
            for _, r in ipairs(config) do
                ret, err = am.rule_init(r)
                if ret == false then
                    log.success = 0
                    log.reason  = err
                    log.result  = nil
                    return
                end
                
                table_insert(rules, index, r)
                index = index + 1
                if r.cache_key then ckey = true end
            end
        else
            ret, err = am.rule_init(config)
            if ret == false then
                log.success = 0
                log.reason  = err
                log.result  = nil
                return
            end
            
            table_insert(rules, index, config)
            if config.cache_key then ckey = true end
        end
        
        if not no_cache and ckey then
            local cf = _twaf.config.twaf_access_rule
            local dict = ngx_shared[cf.shm]
            if not dict then
                log.success = 0
                log.reason = "no shm"
                log.result = nil
                return
            end
            
            local rfast = am.rules_cache_init(cf.rules)
            
            dict:flush_all()
            dict:flush_expired()
            
            cf.rfast = rfast
        end
    end

    local mstsc =  "twaf_mstsc"
    local rules = _twaf.config.twaf_access_rule.rules or {}
    
    local data = twaf_func.api_check_json_body(log)
    if not data then return end
    
    if not u[2] then
        log.success = 0
        log.reason  = "Not specified user"
        return
    end
    
    if u[2] == mstsc then
        log.result = data.config
       _table_insert(rules, 1, data.config, true)
        return
    end
    
    local first = 0
    local count = 0
    local maxn  = table.maxn(rules)
    
    for i, rule in ipairs(rules) do
    
        if rule.user == u[2] then
            if count == 0 then
                first = i
            end
            
            count = count + 1
        else
            if count ~= 0 then
                break
            end
        end
    end
    
    if first == 0 then
        
        if u[3] and u[3] ~= "1" and (u[3] ~= "uuid" or u[4]) then
            log.success = 0
            log.reason  = "invalid parameter '"..ngx.var.uri.."'"
            return
        end
        
        local index = maxn + 1
        
        if rules[maxn] and rules[maxn].is_default and data.config.is_default then
            log.success = 0
            log.reason  = "just can set one default access_rule"
            return
        end
        
        log.result = data.config
       _table_insert(rules, index, data.config)
        
        return
    end
    
    -- found {user} access rule
    local max_len = first + count
    
    -- /access_rule/{user}/
    -- not defined position, insert rules after the last rule of user
    if not u[3] then
        
        if rules[max_len - 1].is_default then
            if data.config.is_default then
                log.success = 0
                log.reason  = "just can set one default access_rule"
                return
            end
            
            _table_insert(rules, max_len - 1, data.config)
        else
            if data.config.is_default and rules[max_len] then
                log.success = 0 
                log.reason  = "default access_rule should be one user"
                return
            end
            
            _table_insert(rules, max_len, data.config)
        end
        log.result = data.config
        return
    end
    
    -- /access_rule/{user}/uuid/{uuid}
    if u[3] == "uuid" then
    
        -- /access_rule/{user}/uuid/
        -- not defined {uuid}, insert rules before the first rule of user
        if not u[4] then 
            log.result = data.config
           _table_insert(rules, first, data.config)
            return
        end
    
        for i=first, max_len - 1 do
            if rules[i].uuid == u[4] then
                log.result = data.config
               _table_insert(rules, i + 1, data.config)
                return
            end
        end
        
        log.success = 0
        log.reason  = "Not found uuid '"..u[4].."' in user '"..u[2].."'"
        return
    end
    
    -- /access_rule/{user}/{pos}
    local pos = tonumber(u[3])
    if type(pos) ~= "number" then
        log.success = 0
        log.reason = "expected number, but got ".."'"..type(pos).."'"
        return
    end
    
    if pos == 0 then
        log.success = 0
        log.reason = "the minimum value is 1, not 0"
        return
    end
        
    if pos > max_len then
        log.success = 0
        log.reason = "the value of pos can't be greater than "..max_len
        return
    end
    
    local index = first + pos - 1
    log.result  = data.config
    
   _table_insert(rules, index, data.config)
end

-- put access_rule, e.g: PUT /api/access_rule/{user}/{uuid}
_M.api.access_rule.put        = function(_twaf, log, u)

    local user     =  u[2]
    local uuid     =  u[3]
    local tgt_rule =  nil
    local tgt_user =  nil
    local rules    = _twaf.config.twaf_access_rule.rules or {}
    
    -- check request body
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    if not user then
        log.success = 0
        log.reason = "Not specified user"
        return
    end
    
    if not uuid then
        log.success = 0
        log.reason = "Not specified access rule uuid"
        return
    end
    
    for i, rule in pairs(rules) do
        if rule.user == user then
            tgt_user = true
            if rule.uuid == uuid then
                tgt_rule = i
                break
            end
        end
    end
    
    if not tgt_rule then
        if tgt_user then
            log.reason  = "Not found access rule uuid '"..uuid.."' in "..user.."'s"
        else
            log.reason  = "Not found access rule user '"..user.."'"
        end
        
        log.success = 0
        return
    end
    
    local am = _twaf.modfactory.twaf_access_rule
    local config = data.config
    
    local ret, err = am.rule_init(config)
    if ret == false then
        log.success = 0
        log.reason  = err
        log.result  = nil
        return
    end
    
    local o_ckey = rules[tgt_rule].cache_key
    local cf = _twaf.config.twaf_access_rule
    local dict = ngx_shared[cf.shm]
    if not dict then
        log.success = 0
        log.reason = "no shm"
        log.result = nil
        return
    end
    
    rules[tgt_rule] = config
    
    local n_ckey = config.cache_key
    
    if o_ckey ~= n_ckey then
        local rfast = am.rules_cache_init(cf.rules)
        
        dict:flush_all()
        dict:flush_expired()
        
        cf.rfast = rfast
    elseif n_ckey then
        cf.rfast = am.rules_cache_init(cf.rules)
    end
    
    log.result = rules[tgt_rule]
end

-- patch access_rule, e.g: PATCH host/path/access_rule/{user}/{uuid}
_M.api.access_rule.patch      = function(_twaf, log, u)

    local user     =  u[2]
    local uuid     =  u[3]
    local tgt_rule =  nil
    local tgt_user =  nil
    local rules    = _twaf.config.twaf_access_rule.rules or {}
    
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    if not user then
        log.success = 0
        log.reason = "Not specified user"
        return
    end
    
    if not uuid then
        log.success = 0
        log.reason = "Not specified access rule uuid"
        return
    end
    
    for i, rule in pairs(rules) do
        if rule.user == user then
            tgt_user = true
            if rule.uuid == uuid then
                tgt_rule = i
                break
            end
        end
    end
    
    if not tgt_rule then
        if tgt_user then
            log.reason  = "Not found access rule uuid '"..uuid.."' in "..user.."'s"
        else
            log.reason  = "Not found access rule user '"..user.."'"
        end
        
        log.success = 0
        return
    end
    
    local am = _twaf.modfactory.twaf_access_rule
    local cp =  twaf_func:copy_table(rules[tgt_rule])
    
    for k, v in pairs(data.config) do
        cp[k] = v
    end
    
    local ret, err = am.rule_init(cp)
    if ret == false then
        log.success = 0
        log.reason  = err
        log.result  = nil
        return
    end
    
    local o_ckey = rules[tgt_rule].cache_key
    local cf = _twaf.config.twaf_access_rule
    local dict = ngx_shared[cf.shm]
    if not dict then
        log.success = 0
        log.reason = "no shm"
        log.result = nil
        return
    end
    
    rules[tgt_rule] = cp
    
    local n_ckey = cp.cache_key
    
    if o_ckey ~= n_ckey then
        local rfast = am.rules_cache_init(cf.rules)
        
        dict:flush_all()
        dict:flush_expired()
        
        cf.rfast = rfast
    elseif n_ckey then
        cf.rfast = am.rules_cache_init(cf.rules)
    end
    
    log.result = rules[tgt_rule]
end

-- delete access_rule, e.g: DELETE /api/access_rule/{user}/{uuid}
_M.api.access_rule.delete     = function(_twaf, log, u)

    local rules    = _twaf.config.twaf_access_rule.rules
    
    if not u[2] then
        log.success = 0
        log.reason = "Not specified user"
        return
    end
    
    if not u[3] then
        log.success = 0
        log.reason = "Not specified access rule uuid"
        return
    end
    
    log.result = {}
    local del_num   = 0
    local del_uuids = {}
    local del_index = {}
    
    for i = 3, #u do
        table_insert(del_uuids, u[i])
        del_num = del_num + 1
    end
    
    local ckey = false
    local cf = _twaf.config.twaf_access_rule
    local dict = ngx_shared[cf.shm]
    if not dict then
        log.success = 0
        log.reason = "no shm"
        log.result = nil
        return
    end
    
    -- find rules
    for i, rule in ipairs(rules) do
        if rule.user == u[2] and twaf_func:table_has_value(del_uuids, rule.uuid) then
            table_insert(del_index, i)
            table_insert(log.result, rule.uuid)
            if rule.cache_key then ckey = true end
            del_num = del_num - 1
            if del_num == 0 then break end
        end
    end
    
    -- delete rules
    for i, index in ipairs(del_index) do
        table.remove(rules, index - i + 1)
    end
    
    if ckey then
        local rfast = _twaf.modfactory.twaf_access_rule.rules_cache_init(cf.rules)
        
        dict:flush_all()
        dict:flush_expired()
        
        cf.rfast = rfast
    end
    
    return
end

_M.help.access_rule = {
    "GET /api/access_rule/{user}/{uuid}",
    "POST /api/access_rule/{user}/{pos}",
    "POST /api/access_rule/{user}/uuid/{uuid}",
    "PUT /api/access_rule/{user}/{uuid}",
    "PATCH /api/access_rule/{user}/{uuid}",
    "DELETE /api/access_rule/{user}/{uuid}"
}
    
return _M