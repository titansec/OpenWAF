
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "1.0.2"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.rule_set = {}

local function set_rules(_twaf, rids)
    local rules  = _twaf.config.rules
    local reason =  {}
    for _, rid in ipairs(rids) do
        if not rules[rid] then
            table.insert(reason, rid)
        end
    end
    
    if #reason > 0 then
        return false, reason
    end
    
    return true, twaf_conf:rule_group_phase(rules, rids)
end

-- get rule_set config e.g: GET host/path/rule_set/{rule_set_uuid}
_M.api.rule_set.get    = function(_twaf, _log, u)

    local rule_sets = _twaf.config.rule_sets or {}
    
    if not u[2] then
        _log.result = rule_sets
        return
    end
    
    local info = rule_sets[u[2]]
    if not info then
        _log.success = 0
        _log.reason  = "No rule set '"..u[2].."'"
    end
    
    _log.result = info
    return

end

-- post rule_set config e.g: POST host/path/rule_set/{rule_set_uuid}
_M.api.rule_set.post   = function(_twaf, _log, u)

    -- check request body
    local data = twaf_func.api_check_json_body(_log)
    if not data then
        return
    end
    
    local rids = data.config
    if type(rids) ~= "table" then
        _log.success = 0
        _log.reason  = "rules: table expected, got "..type(rids)
        return
    end
    
    local uuid = u[2]
    if not uuid then
        _log.success = 0
        _log.reason  = "Not specified rule set uuid"
        return
    end
    
    local conf = _twaf.config.rule_sets
    if not conf then
        _twaf.config.rule_sets = {}
        conf = _twaf.config.rule_sets
    end
    
    if conf[uuid] then
        _log.success = 0
        _log.reason  = "Rule set '"..uuid.."' have exist"
        return
    end
    
    local ret, rules = set_rules(_twaf, rids)
    if not ret then
        _log.success = 0
        _log.reason  = "in rules not found rule: " .. twaf_func:table_to_string(rules)
        return
    end
    
    conf[uuid]  = rules
    _log.result = rules
    return
end

-- put rule_set config e.g: PUT host/path/rule_set/{rule_set_uuid}
_M.api.rule_set.put    = function(_twaf, _log, u)

    -- check request body
    local data = twaf_func.api_check_json_body(_log)
    if not data then
        return
    end
    
    local rids = data.config
    if type(rids) ~= "table" then
        _log.success = 0
        _log.reason  = "Table expected, got '"..type(rids).."'"
        return
    end
    
    local uuid =  u[2]
    local conf = _twaf.config.rule_sets
    
    if not uuid then
        -- 更新所有规则集
        -- k —> uuid, v -> rids
        local ret, rules
        local sets = {}
        for k, v in pairs(rids) do
            ret, rules = set_rules(_twaf, v)
            if not ret then
                _log.success = 0
                _log.reason  = "in rules not found rule: " .. twaf_func:table_to_string(rules)
                return
            end

            sets[k] = rules
        end
        
        sets["twaf_default_rule_set"] = conf["twaf_default_rule_set"]
        _twaf.config.rule_sets = sets
        _log.result = sets
        return
    end
    
    if not conf[uuid] then
        _log.success = 0
        _log.reason  = "Not found rule set '"..uuid.."'"
        return
    end
    
    local ret, rules = set_rules(_twaf, rids)
    if not ret then
        _log.success = 0
        _log.reason  = "in rules not found rule: " .. twaf_func:table_to_string(rules)
        return
    end
    
    conf[uuid]  = rules
    _log.result = rules
    return
end

-- delete rule_set config e.g: DELETE host/path/rule_set/{rule_set_uuid}
_M.api.rule_set.delete = function(_twaf, _log, u)

    local rule_sets = _twaf.config.rule_sets or {}
    
    if not u[2] then
        _log.success = 0
        _log.reason  = "Not specified rule set uuid"
        return
    end
    
    _log.result = rule_sets[u[2]] or "No rule set '"..u[2].."'"
    rule_sets[u[2]] = nil
    
    return
end

_M.help.rule_set = {
    "GET host/path/rule_set/{rule_set_uuid}",
    "POST host/path/rule_set/{rule_set_uuid}",
    "PUT host/path/rule_set/{rule_set_uuid}",
    "DELETE host/path/rule_set/{rule_set_uuid}"
}

_M.ChangeList = {
    ["0.1.0"] = {"2019-05-17 - miracle - Upload rule_set APIs",
                 "2019-05-20 - miracle - fix: wrong config"},
    ["1.0.0"] =  "2019-09-11 - miracle - production version",
    ["1.0.1"] =  "2019-11-06 - miracle - set rule_group_phase when post and put",
    ["1.0.2"] =  "2019-11-08 - miracle - suppose batch processing in put"
}

return _M