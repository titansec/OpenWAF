
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.0"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.user_defined_rules = {}

-- get user defined rules, e.g: GET /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.get    = function(_twaf, log, u)

    local pid = u[2]
    local rid = u[3]

    if not pid then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[pid]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..pid
        return
    end
    
    local conf = policy.twaf_secrules.user_defined_rules
    
    if not rid then
        log.result = conf or {}
        return
    end
    
    if type(conf) ~= "table" then
        log.success = 0
        log.reason  = "No user defined rules in policy uuid '"..pid.."'"
        return
    end
    
    local ids  = policy.twaf_secrules.user_defined_rules_id
    if not ids[rid] then
        log.success = 0
        log.reason  = "No such rule id: "..rid
        return
    end
    
    for _, r in ipairs(conf[ids[rid]]) do
        if r.id == rid then
            log.result = r
            return
        end
    end
    
    log.success = 0
    log.reason  = "No such user defined rule id '"..rid.."' in policy uuid '"..pid.."'"
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
    local reason = {}
    local conf = policy.twaf_secrules.user_defined_rules
    local ids  = policy.twaf_secrules.user_defined_rules_id
    local tb   = {}
    
    for _, r in ipairs(data.config) do
        local res, err = twaf_func:check_rules(ids, r)
        if res then
            tb[r.id] = r.phase
        else
            table.insert(reason, err)
        end
    end
    
    if #reason > 0 then
        log.success = 0
        log.reason  = reason
        return false, err
    end
    
    twaf_func.table_merge(ids, tb)
    
    log.result = data.config
    
-- add to user_defined_rules
--[[
    if u[3] then
        local index = tonumber(u[3])
        
        for _, r in pairs(data.config) do
            table.insert(conf, index, r)
            index = index + 1
        end
        
        return
    end
]]
    -- not u[3]
    for _, r in pairs(data.config) do
        if r.action == "DENY" or r.action == "RESET_CONNECTION" then
            table.insert(conf[r.phase], r)
        else
            table.insert(conf[r.phase], 1, r)
        end
    end
end

-- put user_defined_rules, e.g: PUT /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.put    = function(_twaf, log, u)

    local pid = u[2]
    local rid = u[3]

-- check request body
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    local r = data.config
    
    if type(r) ~= "table" then
        log.success = 0
        log.reason  = "rules: table expected, got "..type(r)
        return
    end

    if not pid then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[pid]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..pid
        return
    end

    if not rid then
        log.success = 0
        log.reason  = "Not specified rule id"
        return
    end

    local conf = policy.twaf_secrules.user_defined_rules
    local ids  = policy.twaf_secrules.user_defined_rules_id
    
    if not ids[rid] then
        log.success = 0
        log.reason  = "No such rule id: "..rid
        return
    end

    local phase_before = ids[rid]
    ids[rid] = nil
    local res, err = twaf_func:check_rules(ids, r)
    if res then
        ids[r.id] = r.phase
    else
        log.success = 0
        log.reason  = err
        return
    end
    
    if phase_before == r.phase then
        for i, ru in ipairs(conf[phase_before]) do
            if ru.id == rid then
                conf[phase_before][i] = r
                log.result = r
                break
            end
        end
    else
        for i, ru in ipairs(conf[phase_before]) do
            if ru.id == rid then
                table.remove(conf[phase_before], i)
                break
            end
        end
        if r.action == "DENY" or r.action == "RESET_CONNECTION" then
            table.insert(conf[r.phase], r)
        else
            table.insert(conf[r.phase], 1, r)
        end
        log.result = r
    end
    
    if not log.result then
        log.success = 0
        log.reason = "No rule id '"..u[3].."' in policy uuid '"..u[2].."'"
    end
    
    return
end

-- delete user_defined_rules, e.g: DELETE /api/user_defined_rules/{policy_uuid}/{rule_id}
_M.api.user_defined_rules.delete = function(_twaf, log, u)

    local pid = u[2]
    local rid = u[3]
    
    if not pid then
        log.success = 0
        log.reason  = "Not specified policy uuid"
        return
    end
    
    local policy = _twaf.config.twaf_policy[pid]
    if not policy then
        log.success = 0
        log.reason  = "No such policy uuid: "..pid
        return
    end

    if not rid then
        log.success = 0
        log.reason  = "Not specified rule id"
        return
    end
    
    local conf = policy.twaf_secrules.user_defined_rules
    local ids  = policy.twaf_secrules.user_defined_rules_id
    
    if not ids[rid] then
        log.result = "No actived rule ID: "..rid
        return
    end
    
    for i, r in ipairs(conf[ids[rid]]) do
        if r.id == rid then
            log.result = r
            table.remove(conf[ids[rid]], i)
            ids[rid] = nil
            break
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