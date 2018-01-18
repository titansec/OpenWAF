
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.user_defined_rules = {}

-- get user defined rules, e.g: GET /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.get    = function(_twaf, log, u)

    if not u[2] then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[u[2]]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..u[2]
        return
    end
    
    local conf = policy.twaf_secrules.user_defined_rules
    
    if not u[3] then
        log.result = conf or {}
        return
    end
    
    if type(conf) ~= "table" then
        log.success = 0
        log.reason  = "No user defined rules in policy uuid '"..u[2].."'"
        return
    end
    
    for phase, rules in pairs(conf) do
        for _, r in ipairs(rules) do
            if r.id == u[3] then
                log.result = r
                return
            end
        end
    end
    
    log.success = 0
    log.reason  = "No such user defined rule id '"..u[3].."' in policy uuid '"..u[2].."'"
    return
end

-- post user_defined_rules, e.g: POST /api/user_defined_rules/{policy_uuid}
_M.api.user_defined_rules.post   = function(_twaf, log, u)

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
    
    if not u[2] then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[u[2]]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..u[2]
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
    
-- add to conf.user_defined_rules
    
    conf = policy.twaf_secrules
    if not conf.user_defined_rules then
        conf.user_defined_rules = {}
    end
    
    twaf_conf:rule_group_phase(conf.user_defined_rules, data.config)
end

-- put user_defined_rules, e.g: PUT /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.put    = function(_twaf, log, u)

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

    if not u[2] then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[u[2]]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..u[2]
        return
    end
    
    local conf = policy.twaf_secrules.user_defined_rules
    
    if not u[3] then
        log.success = 0
        log.reason  = "Not specified rule id"
        return
    end
    
    if not _twaf.config.rules_id[u[3]] then
        log.success = 0
        log.reason  = "No such rule id: "..u[2]
        return
    end
    
    if type(conf) ~= "table" then
        log.success = 0
        log.reason = "No rule id '"..u[3].."' in policy uuid '"..u[2].."'"
        return
    end
    
    for phase, rules in pairs(conf) do
        for i, r in ipairs(rules) do
            if r.id == u[3] then
                rules[i] = data.config
                log.result = data.config
                break
            end
        end
    end
    
    if not log.result then
        log.success = 0
        log.reason = "No rule id '"..u[3].."' in policy uuid '"..u[2].."'"
    end
    
    return
end

-- delete user_defined_rules, e.g: DELETE /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.delete = function(_twaf, log, u)
    
    if not u[2] then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[u[2]]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..u[2]
        return
    end
    
    local conf = policy.twaf_secrules.user_defined_rules
    
    if not u[3] then
        log.success = 0
        log.reason  = "Not specified rule id"
        return
    end
    
    if not _twaf.config.rules_id[u[3]] then
        log.result = "No actived rule ID: "..u[3]
        return
    end
    
    if type(conf) ~= "table" then
        log.result = "nil"
        return
    end
    
    for phase, rules in pairs(conf) do
        for i, r in ipairs(rules) do
            if r.id == u[3] then
                log.result = r
                table.remove(rules, i)
                _twaf.config.rules_id[u[3]] = nil
                break
            end
        end
    end
    
    if not log.result then
        log.result = "No rule id '"..u[3].."' in policy '"..u[2].."'"
    end
end

_M.help.user_defined_rules = {
    "GET /api/user_defined_rules/{policy_uuid}/{rule_id}",
    "POST /api/user_defined_rules/{policy_uuid}",
    "PUT /api/user_defined_rules/{policy_uuid}/{rule_id}",
    "DELETE /api/user_defined_rules/{policy_uuid}/{rule_id}"
}
    
return _M