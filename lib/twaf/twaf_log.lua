
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local twaf_func           = require "lib.twaf.inc.twaf_func"
local twaf_socket         = require "resty.logger.socket"
local cjson               = require "cjson.safe"

-- " --> \"
local function _transfer_quotation_mark(str)
    local func = function(m)
        if m[0] == '\\"' then
            return m[0]
        end
                    
        return m[0]:sub(1,1)..'\\"'
    end
    
    if str:sub(1,1) == '"' then
        str = '\\'..str
    end
    
    return ngx.re.gsub(str, [=[."]=], func, "oij")
end

local function _get_var(request, key, size_limit)

    local str = nil
    
    if type(request[key]) == "function" then
        str = twaf_func:table_to_string(request[key]())
    else
        str = twaf_func:table_to_string(request[key])
    end
    
    if type(str) == "string" then
        str = _transfer_quotation_mark(str)
        local len = #str
        if len > size_limit then
            str = str:sub(1, size_limit).." - left "..tostring(len - size_limit)
        end
    end
    
    if str == nil then
        return "-"
    end
    
    return str
end

local function _add_tags_and_fileds(request, raw_msg, size_limit, counter)
    local log = ""
    
    if raw_msg.db then
        log = raw_msg.db..","
    end
    
    if raw_msg.tags then
        for _, v in ipairs(raw_msg.tags) do
            local value = _get_var(request, v:upper(), size_limit)
            
            log = log..v.."=".."\""..value.."\""..","
        end
    end
    
    log     = log .. "point=" .. counter
    log     = log .. " "
    
    for i, v in ipairs(raw_msg.fileds) do
        local value = _get_var(request, v:upper(), size_limit)
        log = log..v.."=".."\""..value.."\""..","
    end
    
    log = log:sub(1, -2)
    
    return log
end

local function _add_timestamp(request, raw_msg, log)
    if raw_msg.time and request.TIME_EPOCH then
        log = log .. " " .. request.TIME_EPOCH.."000000000"
    end
    
    log = log .. "\n"
    
    return log
end

local function _set_msg_influxdb(request, events, raw_msg, size_limit, flag)

    local log     = ""
    local counter = 1
    
    if type(raw_msg) ~= "table" then
        ngx.log(ngx.ERR, "the format of message is not a table")
        return false
    end
    
    if flag == "access_log" then
        local tf = _add_tags_and_fileds(request, raw_msg, size_limit, counter)
        return _add_timestamp(request, raw_msg, tf)
    end
    
    for modules_name, event in pairs(events) do
        local tf = _add_tags_and_fileds(request, raw_msg, size_limit, counter)
        log = log .. tf
        
        for k, v in pairs(event) do
            if type(v) == "string" then v = "\"".._transfer_quotation_mark(v).."\"" end
            log = log..","..k.."="..v
        end
        
        log = _add_timestamp(request, raw_msg, log)
        counter = counter + 1
    end
    
    if counter > 1 then
        return log
    end
    
    return false
end

local function _set_msg_json(request, events, raw_msg, size_limit, flag)

    if type(raw_msg) ~= "table" then
        ngx.log(ngx.ERR, "the format of message is not a table")
        return false
    end
    
    local log = {}
    
    for _, v in pairs(raw_msg) do
        if type(v) == "string" then
            log[v] = _get_var(request, v:upper(), size_limit)
        end
    end
    
    log["log_type"] = flag
    
    if flag == "access_log" then
        local jlog = cjson.encode(log)
        if jlog then
            return jlog .. "\n"
        end
        
        return false
    end
    
    local ret       = ""
    local safe_flag = 0
    
    for modules_name, event in pairs(events) do
        safe_flag      = 1
        log.safe_event = event
        
        local json_log = cjson.encode(log)
        if not json_log then
            ngx.log(ngx.ERR, "cjson encode failed in _set_msg_json of twaf_log module.")
            return false
        end
        
        ret = ret .. json_log .. "\n"
        log.safe_event = nil
    end
    
    if safe_flag == 1 then
        return ret
    end
    
    return false
end

function _M:set_msg(ctx, cf, log_format, flag)

    if not ctx then return false end
    
    local request    =  ctx.request
    local events     =  ctx.events.log
    local size_limit =  tonumber(cf.size_limit)
    
    if not size_limit or size_limit <= 20 or size_limit >= 1000 then
        size_limit = 200
    end
    
    if cf.content_type == "JSON" then
        return _set_msg_json(request, events, log_format, size_limit, flag)
    elseif cf.content_type == "INFLUXDB" then
        return _set_msg_influxdb(request, events, log_format, size_limit, flag)
    end
    
    return false
end

function _M.log(self, _twaf)

    local cf = _twaf:get_config_param("twaf_log")
    if not cf then
        ngx.log(ngx.ERR, "Can't get config of twaf_log")
        return
    end
    
    local ok, err = twaf_socket.init(cf)
    if not ok then
        ngx.log(ngx.ERR, "failed to initalized the twaf_socket:", err)
        return false
    end
    
    if twaf_func:state(cf.access_log_state) == true then
        local access_msg = _M:set_msg(_twaf:ctx(), cf, cf.access_log, "access_log")
        if access_msg ~= false then
            local bytes, err = twaf_socket.log(access_msg)
            if err then
                ngx.log(ngx.ERR, "failed to send log message: ", err)
            end
        end
    end
    
    if twaf_func:state(cf.security_log_state) == true then
        local security_msg = _M:set_msg(_twaf:ctx(), cf, cf.security_log, "security_log")
        if security_msg ~= false then
            local bytes, err = twaf_socket.log(security_msg)
            if err then
                ngx.log(ngx.ERR, "failed to send log message: ", err)
            end
        end
    end
    
    return true
end

return _M
