
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local arr_index = "arr_tonumber"

_M.api = {}
_M.help = {}
_M.api.config = {}

-- get config, e.g: GET /api/config/{policy}/{module}/{key}
_M.api.config.get        = function(_twaf, log, u)
    
    local i =  2
    local v = _twaf.config
    repeat
    
    local str = u[i]
    if not str then
        break
    end
    
    if type(v) ~= "table" then
        log.success = 0
        log.reason  = "the value of "..u[i-1].." is not a table"
        return
    end
    
    local from, to, err = str:find(arr_index)
    if from and to then
    
        local t = next(v)
        if t and t~= 1 then
            log.success = 0
            log.reason  = "the value of "..u[i-1].."is not a array"
            return
        end
        
        local max_len = #v -- post + 1
        
        str = tonumber(str:sub(to+1))
        
        if type(str) ~= "number" then
            log.success = 0
            log.reason = "the value of "..arr_index.." must be a number"
            return
        end
        
        if str == 0 then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be '0'"
            return
        end
        
        if str > max_len then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be greater than "..max_len
            return
        end
    end
    
    v = v[str]
    if v == nil then v = "nil" end
    
    i = i + 1
    
    until false
    
    log.result = v
end

-- post config, e.g: POST /api/config/{policy}/{module}/{key}
_M.api.config.post       = function(_twaf, log, u)
    local i =  2
    local v = _twaf.config
    
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    repeat
    
    local str1 = u[i]
    local str2 = u[i+1]
    if not str1 then
        break
    end
    
    if type(v) ~= "table" then
        log.success = 0
        log.reason  = "the value of "..u[i-1].." is not a table"
        return
    end
    
    local from, to, err = str1:find(arr_index)
    if from and to then
    
        local t = next(v)
        if t and t~= 1 then
            log.success = 0
            log.reason  = "the value of "..u[i-1].."is not a array"
            return
        end
        
        local max_len = #v + 1
        
        if to == #str1 then
            str1 = max_len
        else
            str1 = tonumber(str1:sub(to+1))
        end
        
        if type(str1) ~= "number" then
            log.success = 0
            log.reason = "the value of "..arr_index.." must be a number"
            return
        end
        
        if str1 == 0 then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be '0'"
            return
        end
        
        if str1 > max_len then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be greater than "..max_len
            return
        end
        
        if not str2 then
            log.result = data.config
            table.insert(v, str1, data.config)
            break
        end
    end
    
    if not str2 then
        log.result = data.config
        v[str1] = data.config
        break
    end
    
    v = v[str1]
    
    i = i + 1
    
    until false
end

-- update config, e.g: PUT /api/config/{policy}/{module}/{key}
_M.api.config.put        = function(_twaf, log, u)
    local i =  2
    local v = _twaf.config
    
    local data = twaf_func.api_check_json_body(log)
    if not data then
        return
    end
    
    repeat
    
    local str1 = u[i]
    local str2 = u[i+1]
    if not str1 then
        break
    end
    
    if type(v) ~= "table" then
        log.success = 0
        log.reason  = "the value of "..u[i-1].." is not a table"
        return
    end
    
    local from, to, err = str1:find(arr_index)
    if from and to then
    
        local t = next(v)
        if t and t~= 1 then
            log.success = 0
            log.reason  = "the value of "..u[i-1].."is not a array"
            return
        end
        
        local max_len = #v + 1
        
        if to == #str1 then
            str1 = max_len
        else
            str1 = tonumber(str1:sub(to+1))
        end
        
        if type(str1) ~= "number" then
            log.success = 0
            log.reason = "the value of "..arr_index.." must be a number"
            return
        end
        
        if str1 == 0 then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be '0'"
            return
        end
        
        if str1 > max_len then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be greater than "..max_len
            return
        end
    end
    
    if not str2 then
        log.result = data.config
        v[str1] = data.config
        break
    end
    
    v = v[str1]
    
    i = i + 1
    
    until false
end

-- delete config, e.g: DELETE /api/config/{policy}/{module}/{key}
_M.api.config.delete     = function(_twaf, log, u)
    local i =  2
    local v = _twaf.config
    
    repeat
    
    local str1 = u[i]
    local str2 = u[i+1]
    
    if not str1 then
        ngx.log(ngx.ERR, "break: ", i)
        break
    end
    
    if type(v) ~= "table" then
        log.success = 0
        log.reason  = "the value of "..u[i-1].." is not a table"
        return
    end
    
    local from, to, err = str1:find(arr_index)
    if from and to then
    
        local t = next(v)
        if t and t~= 1 then
            log.success = 0
            log.reason  = "the value of "..u[i-1].."is not a array"
            return
        end
        
        local max_len = #v
        
        str1 = tonumber(str1:sub(to+1))
        
        if type(str1) ~= "number" then
            log.success = 0
            log.reason = "the value of "..arr_index.." must be a number"
            return
        end
        
        if str1 == 0 then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be '0'"
            return
        end
        
        if str1 > max_len then
            log.success = 0
            log.reason = "the value of "..arr_index.." can't be greater than "..max_len
            return
        end
        
        if not str2 then
            log.result = v[str1]
            table.remove(v, str1)
            break
        end
    end
    
    if not str2 then
        
        if v[str1] == nil then
            log.success = 0
            log.reason = "Can't find '"..str1.."'"
            return
        end
    
        log.result = v[str1]
        v[str1] = nil
        break
    end
    
    v = v[str1]
    
    i = i + 1
    
    until false
end

_M.help.config = {
    "GET /api/config/{policy}/{module}/{key}",
    "POST /api/config/{policy}/{module}/{key}",
    "PUT /api/config/{policy}/{module}/{key}",
    "DELETE /api/config/{policy}/{module}/{key}"
}
    
return _M