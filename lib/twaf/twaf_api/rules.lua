
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.1"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.rules = {}

-- get rules, e.g: GET /api/rules/{rule_id}
_M.api.rules.get         = function(_twaf, log, u)

    local rid   =  u[2]
    local conf  = _twaf.config
    
    if not rid then
        log.result = conf.rules
        return
    end
    
    local rule = conf.rules[rid]
    
    if not rule then
        log.success = 0
        log.reason  = "no rule id: "..rid
        return
    end
    
    log.result = rule
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
    local reason = {}
    local tb = {}
    local conf = _twaf.config
    
    for _, r in ipairs(data.config) do
        local res, err = twaf_func:check_rules(conf.rules_id, r)
        if res == true then
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
    
    if u[2] and u[2]:lower() == "checking" then return end
    
    twaf_func.table_merge(conf.rules_id, tb)
    
    log.result = data.config
    
-- add to conf.rules
    
    conf.rules  = conf.rules or {}
    local drset = conf.rule_sets.twaf_default_rule_set
    for _, r in ipairs(data.config) do
        conf.rules[r.id] = r
        table.insert(drset[r.phase], r.id)
    end
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
    
    local tb = {}
    local reason = {}
    local phase
    
    for _, r in ipairs(data.config) do
        phase = conf.rules_id[r.id]
        conf.rules_id[r.id] = nil
        local res, err = twaf_func:check_rules(conf.rules_id, r)
        if res then
            tb[r.id] = r.phase
        else
            table.insert(reason, err)
        end
        conf.rules_id[r.id] = phase
    end
    
    if #reason > 0 then
        log.success = 0
        log.reason  = reason
        return false, err
    end
    
    log.result = data.config
    
-- add to conf.rules

    for _, r in ipairs(data.config) do
        conf.rules[r.id] = r
        conf.rules_id[r.id] = r.phase
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