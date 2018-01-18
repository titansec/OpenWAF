
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local twaf_func = require "lib.twaf.inc.twaf_func"

_M.api = {}
_M.help = {}
_M.api.access_rule = {}

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
                table.insert(log.result, rule)
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

    local mstsc =  "twaf_mstsc"
    local sduer =  "twaf_system_default_user"
    local rules = _twaf.config.twaf_access_rule.rules
    
    local data = twaf_func.api_check_json_body(log)
    if not data then return end
    
    if not u[2] then
        log.success = 0
        log.reason  = "Not specified user"
        return
    end
    
    if u[2] == mstsc then
        log.result = data.config
        table.insert(rules, 1, data.config)
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
        
        if rules[maxn] and rules[maxn].user == sduer then
            index = maxn
        end
        
        log.result = data.config
        table.insert(rules, index, data.config)
        
        return
    end
    
    if u[2] == sduer then
        log.success = 0
        log.reason = "user '"..sduer.."' already have one rule"
        return
    end
    
    if not u[3] then
        log.result = data.config
        table.insert(rules, first + count, data.config)
        return
    end
    
    local max_len = first + count
    
    -- /{user}/uuid/{uuid}
    if u[3] == "uuid" then
        if not u[4] then 
            log.result = data.config
            table.insert(rules, first, data.config)
            return
        end
    
        for i=first, max_len - 1 do
            if rules[i].uuid == u[4] then
                log.result = data.config
                table.insert(rules, i + 1, data.config)
                return
            end
        end
        
        log.success = 0
        log.reason  = "Not found uuid '"..u[4].."' in user '"..u[2].."'"
        return
    end
    
    -- /{user}/{pos}
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
    log.result  = rules[index]
    
    table.insert(rules, index, data.config)
end

-- put access_rule, e.g: PUT /api/access_rule/{user}/{uuid}
_M.api.access_rule.put        = function(_twaf, log, u)

    local find_out = false
    local rules    = _twaf.config.twaf_access_rule.rules
    
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
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
    
    local flag = false
    
    for i, rule in pairs(rules) do
        if rule.user == u[2] then
            flag = true
            if rule.uuid == u[3] then
                find_out = rules[i]
            end
        end
    end
    
    if find_out == false then
        if flag == true then
            log.reason  = "Not found access rule uuid: "..u[3].." in user: "..u[2]
        else
            log.reason  = "Not found access rule user: "..u[2]
        end
        
        log.success = 0
        return
    end
    
    for k, v in pairs(data.config) do
        find_out[k] = v
    end
    
    log.result = find_out
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
    
    for i, rule in pairs(rules) do
        if rule.user == u[2] and rule.uuid == u[3] then
            log.result = rule
            table.remove(rules, i)
            return
        end
    end
    
    
    log.result = {}
    return
end

_M.help.access_rule = {
    "GET /api/access_rule/{user}/{uuid}",
    "POST /api/access_rule/{user}/{pos}",
    "POST /api/access_rule/{user}/uuid/{uuid}",
    "PUT /api/access_rule/{user}/{uuid}",
    "DELETE /api/access_rule/{user}/{uuid}"
}
    
return _M