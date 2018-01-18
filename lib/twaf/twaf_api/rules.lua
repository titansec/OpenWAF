
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.rules = {}

-- get rules, e.g: GET /api/rules/{rule_id}
_M.api.rules.get         = function(_twaf, log, u)

    local conf  = _twaf.config
    
    if not u[2] then
        log.result = conf.rules
        return
    end
    
    if not conf.rules_id[u[2]] then
        log.success = 0
        log.reason  = "no rule id: "..u[2]
        return
    end
    
    for phase, rules in pairs(conf.rules) do
        for _, r in pairs(rules) do
            if r.id == u[2] then
                log.result = r
                return
            end
        end
    end
    
    if not log.result then
        log.success = 0
        log.reason  = "no rule id: "..u[2]
        return
    end
end

-- post rules, e.g: POST /api/rules
-- post rules, e.g: POST /api/rules/checking
_M.api.rules.post        = function(_twaf, log, u)

-- check request body
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    if type(data.config) ~= "table" then
        log.success = 0
        log.reason  = "rules: table expected, got "..type(data.config)
        return
    end
    
    if #data.config == 0 then
        data.config = {data.config}
    end
    
-- check rules
    local back = {}
    local conf = _twaf.config
    
    for _, r in ipairs(data.config) do
        local res, err = twaf_func:check_rules(conf, r)
        if res == true then
            table.insert(back, r.id)
            conf.rules_id[r.id] = 1
        else
            if log.reason then
                table.insert(log.reason, err)
            else
                log.success = 0
                log.reason  = {}
                table.insert(log.reason, err)
            end
        end
    end
    
    if log.success == 0 then
        for _, v in ipairs(back) do
            conf.rules_id[v] = nil
        end
        
        return
    end
    
    log.result = data.config
    
    if u[2] and u[2]:lower() == "checking" then
        for _, v in ipairs(back) do
            conf.rules_id[v] = nil
        end
        
        return
    end
    
-- add to conf.rules
    
    if not conf.rules then
        conf.rules = {}
    end
    
    twaf_conf:rule_group_phase(conf.rules, data.config)
end

-- update rules, e.g: PUT /api/rules
_M.api.rules.put         = function(_twaf, log, u)

-- check request body
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    if type(data.config) ~= "table" then
        log.success = 0
        log.reason  = "rules: table expected, got "..type(data.config)
        return
    end
    
    if #data.config == 0 then
        data.config = {data.config}
    end
    
    local conf = _twaf.config
    
    if type(conf.rules) ~= "table" then
        log.success = 0
        log.reason  = "No system rules"
        return
    end
    
    for _, r in ipairs(data.config) do
        if type(r.id) ~= "string" then
            log.success = 0
            log.reason  = "No key 'id' in rules"
            return
        end
        
        if not conf.rules_id[r.id] then
            log.success = 0
            log.reason  = "System rules no rule id '"..r.id.."'"
            return
        end
    end
    
-- check rules
    
    local back = {}
    
    for _, r in ipairs(data.config) do
        local res, err = twaf_func:check_rules(conf, r)
        
        if type(err) == "table" then
            for k, v in pairs(err) do
                if ngx.re.find(v, "^ID.*duplicate$") then
                    table.remove(err, k)
                end
            end
            
            if #err == 0 then
                res = true
            end
        end
        
        if res == true then
            table.insert(back, r.id)
            conf.rules_id[r.id] = 1
        else
            if log.reason then
                table.insert(log.reason, err)
            else
                log.success = 0
                log.reason  = {}
                table.insert(log.reason, err)
            end
        end
    end
    
    if log.success == 0 then
        for _, v in ipairs(back) do
            conf.rules_id[v] = nil
        end
        
        return
    end
    
    log.result = data.config
    
-- add to conf.rules
    
    for _, r in ipairs(data.config) do
        local phase = r.phase
        
        if type(phase) ~= "table" then
            phase = {phase}
        end
        
        for _, p in pairs(phase) do
            repeat
            
            if not conf.rules[p] then
                conf.rules[p] = {}
                table.insert(conf.rules[p], r)
                break
            end
            
            for i, rule in ipairs(conf.rules[p]) do
                if r.id == rule.id then
                    conf.rules[p][i] = r
                    break
                end
            end
            
            table.insert(conf.rules[p], r)
            
            until true
        end
    end
    
    if not log.result then
        log.success = 0
        log.reason = "No rule id '"..u[3].."' in policy uuid '"..u[2].."'"
    end
    
    return
end

-- delete rules, e.g: DELETE /api/rules/{rule_id}
_M.api.rules.delete      = function(_twaf, log, u)
end

_M.help.rules = {
    "GET /api/rules",
    "GET /api/rules/{rule_id}",
    "POST /api/rules",
    "POST /api/rules/checking",
    "PUT /api/rules"
}
    
return _M