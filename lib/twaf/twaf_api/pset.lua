
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "1.0.0β"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
--local twaf_conf = require "lib.twaf.twaf_conf"

_M.api = {}
_M.help = {}
_M.api.pset = {}

-- get pset config e.g: GET host/path/pset/{pset_uuid}
_M.api.pset.get    = function(_twaf, _log, u)

    local pset = _twaf.config.pset or {}
    
    if not u[2] then
        _log.result = pset
        return
    end
    
    local info = pset[u[2]]
    if not info then
        _log.success = 0
        _log.reason  = "No pset '"..u[2].."'"
    end
    
    _log.result = info
    return

end

-- post pset config e.g: POST host/path/pset/{pset_uuid}
_M.api.pset.post   = function(_twaf, _log, u)

    -- check request body
    local data = twaf_func.api_check_json_body(_log)
    if not data then
        return
    end
    
    if type(data.config) ~= "table" then
        _log.success = 0
        _log.reason  = "rules: table expected, got "..type(data.config)
        return
    end
    
    local uuid = u[2]
    if not uuid then
        _log.success = 0
        _log.reason  = "Not specified pset uuid"
        return
    end
    
    local pset = _twaf.config.pset
    if not pset then
        _twaf.config.pset = {}
        pset = _twaf.config.pset
    end
    
    if pset[uuid] then
        _log.success = 0
        _log.reason  = "pset '"..uuid.."' have exist"
        return
    end
    
    pset[uuid]  = data.config
    _log.result = pset[uuid]
    
    return
end

-- put pset config e.g: PUT host/path/pset/{pset_uuid}
_M.api.pset.put    = function(_twaf, _log, u)

    -- check request body
    local data = twaf_func.api_check_json_body(_log)
    if not data then
        return
    end
    
    if type(data.config) ~= "table" then
        _log.success = 0
        _log.reason  = "Table expected, got '"..type(data.config).."'"
        return
    end
    
    local uuid =  u[2]
    local pset = _twaf.config.pset
    
    if not uuid then
        _log.success = 0
        _log.reason  = "Not specified pset uuid"
        return
    end
    
    if not pset[uuid] then
        _log.success = 0
        _log.reason  = "Not found pset '"..uuid.."'"
        return
    end
    
    pset[uuid]  = data.config
    _log.result = pset[uuid]
    
    return
end

-- delete pset config e.g: DELETE host/path/pset/{pset_uuid}
_M.api.pset.delete = function(_twaf, _log, u)

    local pset = _twaf.config.pset or {}
    
    if not u[2] then
        _log.success = 0
        _log.reason  = "Not specified pset uuid"
        return
    end
    
    _log.result = pset[u[2]] or "No rule set '"..u[2].."'"
    pset[u[2]] = nil
    
    return
end

_M.help.pset = {
    "GET host/path/pset/{pset_uuid}",
    "POST host/path/pset/{pset_uuid}",
    "PUT host/path/pset/{pset_uuid}",
    "DELETE host/path/pset/{pset_uuid}"
}

_M.ChangeList = {
    ["1.0.0β"] =  "2019-11-07 - miracle - new api pset"
}

return _M