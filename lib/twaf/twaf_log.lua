
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func           = require "lib.twaf.inc.twaf_func"
local twaf_socket         = require "resty.logger.socket"
local file_access         = require "resty.logger.file_access"
local file_security       = require "resty.logger.file_security"
local cjson               = require "cjson.safe"

local ngx_re_gsub         = ngx.re.gsub
local ngx_var             = ngx.var
local ngx_log             = ngx.log
local ngx_ERR             = ngx.ERR
local _type               = type
local _tostring           = tostring
local _tonumber           = tonumber
local string_format       = string.format
local string_sub          = string.sub
local string_lower        = string.lower
local string_upper        = string.upper

-- " --> \"
local function _transfer_quotation_mark(str)
    local func = function(m)
        if m[0] == '\\"' then
            return m[0]
        end
        
        return string_sub(m[0], 1, 1) .. '\\"'
    end
    
    if string_sub(str, 1, 1) == '"' then
        str = '\\'..str
    end
    
    return ngx_re_gsub(str, [=[."]=], func, "oij")
end

local function _get_var(req, key, size_limit)

    local str = nil
    
    if string_sub(key, 1, 1) == "%" then
        str = twaf_func:parse_dynamic_value(key ,req)
    else
        str = twaf_func:table_to_string(twaf:get_vars(key, req) or 
                                        ngx_var[string_lower(key)])
    end
    
    if _type(str) == "string" then
        str = _transfer_quotation_mark(str)
        local _len = #str
        if _len > size_limit then
            str = string_format("%s - left %d", string_sub(str, 1, size_limit), _len - size_limit)
        end
    end
    
    if str == nil then
        return "-"
    end
    
    return str
end

local function _init(cf)

    if not twaf_socket.initted() then
        local ok, err = twaf_socket.init(cf)
        if not ok then
            ngx_log(ngx_ERR, "failed to initalized the twaf_socket:", err)
            return false
        end
    end
    
    if not file_access.initted() then
    
        local ok, err
        local path = cf.path
        
        cf.path = cf.file_access_log_path
        ok, err = file_access.init(cf)
        cf.path = path
        
        if not ok then
            ngx_log(ngx_ERR, "failed to initalized the file_access:", err)
            return false
        end
    end
    
    if not file_security.initted() then
    
        local ok, err
        local path = cf.path
        
        cf.path = cf.file_security_log_path
        ok, err = file_security.init(cf)
        cf.path = path
        
        if not ok then
            ngx_log(ngx_ERR, "failed to initalized the file_security:", err)
            return false
        end
    end
    
    return true
end

local function _add_tags_and_fileds(req, raw_msg, size_limit, counter)
    local _log = ""
    
    if raw_msg.db then
        _log = raw_msg.db..","
    end
    
    if raw_msg.tags then
        for _, v in ipairs(raw_msg.tags) do
            local value = _get_var(req, string_upper(v), size_limit)
            
            _log = string_format("%s%s=\"%s\",", _log, v, value)
        end
    end
    
    _log     =  string_format("%spoint=%d", _log, counter)
    _log     = _log .. " "
    
    for i, v in ipairs(raw_msg.fileds) do
        local value = _get_var(req, string_upper(v), size_limit)
        _log = string_format("%s%s=\"%s\",", _log, v, value)
    end
    
    _log = string_sub(_log, 1, -2)
    
    return _log
end

local function _add_timestamp(req, raw_msg, _log)
    local t = twaf:get_vars("TIME_EPOCH", req)
    if raw_msg.time and t then
        _log = string_format("%s %d000000000", _log, t)
    end
    
    _log = _log .. "\n"
    
    return _log
end

local function _set_msg_influxdb(req, events, raw_msg, size_limit, flag)

    local _log    = ""
    local counter = 1
    
    if _type(raw_msg) ~= "table" then
        ngx_log(ngx_ERR, "the format of message is not a table")
        return false
    end
    
    if flag == "access_log" then
        local tf = _add_tags_and_fileds(req, raw_msg, size_limit, counter)
        return _add_timestamp(req, raw_msg, tf)
    end
    
    for modules_name, event in pairs(events) do
        local tf = _add_tags_and_fileds(req, raw_msg, size_limit, counter)
        _log = _log .. tf
        
        for k, v in pairs(event) do
            if _type(v) == "string" then v = string_format("\"%s\"", _transfer_quotation_mark(v)) end
            _log = string_format("%s,%s=%s", _log, k, v)
        end
        
        _log = _add_timestamp(req, raw_msg, _log)
        counter = counter + 1
    end
    
    if counter > 1 then
        return _log
    end
    
    return false
end

local function _set_log(req, raw_msg, size_limit, flag)
    local _log = {}

    for _, v in pairs(raw_msg) do
        if _type(v) == "string" then
            _log[v] = _get_var(req, string_upper(v), size_limit)
        end
    end
    
    _log["log_type"] = flag
    
    return _log
end

local function _set_msg_json(req, events, raw_msg, size_limit, flag)

    if _type(raw_msg) ~= "table" then
        ngx_log(ngx_ERR, "the format of message is not a table")
        return false
    end

    if flag == "access_log" then
        local _log = _set_log(req, raw_msg, size_limit, flag)

        local jlog = cjson.encode(_log)
        if jlog then
            return jlog .. "\n"
        end
        
        return false
    end
    
    local _log = nil
    local  ret = ""
    for modules_name, event in pairs(events) do
    
        _log = _log or _set_log(req, raw_msg, size_limit, flag)
        
        _log.safe_event = event
        
        local json_log = cjson.encode(_log)
        if not json_log then
            ngx_log(ngx_ERR, "cjson encode failed in _set_msg_json of twaf_log module.")
            return false
        end
        
        ret = string_format("%s%s\n", ret, json_log)
        _log.safe_event = nil
    end
    
    return _log and ret or false
end

local function _set_msg_w3c(req, events, raw_msg, size_limit, flag)

    if flag == "access_log" then
        local _log = twaf_func:parse_dynamic_value(raw_msg ,req)
        if _log then
            return _log .. "\n"
        end
        
        return false
    end
    
    local _log      = ""
    local ret       = ""
    local safe_flag = 0
    
    for modules_name, event in pairs(events) do
        safe_flag      = 1
        
        for k, v in pairs(event) do
            req[string_upper(k)] = v
        end
        
        _log = twaf_func:parse_dynamic_value(raw_msg ,req)
        
        ret = string_format("%s%s\n", ret, _log)
    end
    
    if safe_flag == 1 then
        return ret
    end
    
    return false
end

function _M:set_msg(ctx, cf, content_type, flag)

    if not ctx then return false end
    
    local req        =  ctx.req
    local events     =  ctx.events.log
    local size_limit = _tonumber(cf.size_limit)
    
    if not size_limit or size_limit <= 20 or size_limit >= 1000 then
        size_limit = 200
    end
    
    if content_type == "JSON" then
        return _set_msg_json(req, events, cf[flag], size_limit, flag)
    elseif content_type == "INFLUXDB" then
        return _set_msg_influxdb(req, events, cf[flag], size_limit, flag)
    elseif content_type == "W3C" then
        return _set_msg_w3c(req, events, cf[flag.."_w3c"], size_limit, flag)
    end
    
    return false
end

function _M.log(self, _twaf)

    local cf = _twaf:get_config_param("twaf_log")
    if not cf then
        ngx_log(ngx_ERR, "Can't get config of twaf_log")
        return
    end
    
    local ok, err = _init(cf)
    if not ok then
        return false
    end
    
    local ctx = _twaf:ctx()
    
    if twaf_func:state(cf.access_log_state) == true then
        
        -- log access_log by socket
        if cf.socket_access_log_state == true then
            local access_msg = _M:set_msg(ctx, cf, cf.content_type, "access_log")
            if access_msg ~= false then
                local bytes, err = twaf_socket.log(access_msg)
                if err then
                    ngx_log(ngx_ERR, "failed to send log message: ", err)
                end
            end
        end
        
        -- log access_log to file
        if cf.file_access_log_state == true then
            local access_msg = _M:set_msg(ctx, cf, cf.file_content_type, "access_log")
            if access_msg ~= false then
                local bytes, err = file_access.log(access_msg)
                if err then
                    ngx_log(ngx_ERR, "failed to send log message: ", err)
                end
            end
        end
    end
    
    if twaf_func:state(cf.security_log_state) == true then
    
        -- log security_log by socket
        if cf.socket_security_log_state == true then
            local security_msg = _M:set_msg(ctx, cf, cf.content_type, "security_log")
            if security_msg ~= false then
                local bytes, err = twaf_socket.log(security_msg)
                if err then
                    ngx_log(ngx_ERR, "failed to send log message: ", err)
                end
            end
        end
        
        -- log security_log to file
        if cf.file_security_log_state == true then
            local security_msg = _M:set_msg(ctx, cf, cf.file_content_type, "security_log")
            if security_msg ~= false then
                local bytes, err = file_security.log(security_msg)
                if err then
                    ngx_log(ngx_ERR, "failed to send log message: ", err)
                end
            end
        end
    end
    
    return true
end

return _M
