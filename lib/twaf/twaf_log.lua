
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.10"
}

local twaf_func           = require "lib.twaf.inc.twaf_func"
local twaf_socket         = require "resty.logger.socket"
local cjson               = require "cjson.safe"
local ngx_log             = ngx.log
local DEBUG               = ngx.DEBUG
local NOTICE              = ngx.NOTICE
local WARN                = ngx.WARN
local ERR                 = ngx.ERR
local CRIT                = ngx.CRIT
local ngx_var             = ngx.var
local access_log_flag     = 1
local security_log_flag   = 2

--     " --> \"
local function _transfer_quotation_mark(str)
    local func = function(m)
        if m[0] == '\\"' then
            return m[0]
        end
                    
        return m[0]:sub(1,1)..'\\"'
    end
                
    return ngx.re.gsub(str, [=[."]=], func, "oij")
end

local function _get_var(request, key)

    local str = nil
    
    if type(request[key]) == "function" then
        str = request[key]()
    else
        str = request[key]
    end
    
    if type(str) == "string" then
        str = _transfer_quotation_mark(str)
    end
    
    if str == nil then
        return "-"
    end
    
    return str
end

local function _add_tags_and_fileds(request, events, raw_msg, counter)
    local log = ""
    
    if raw_msg.db then
        log = raw_msg.db..","
    end
    
    if raw_msg.tags then
        for _, v in ipairs(raw_msg.tags) do
            local value = _get_var(request, v:upper())
            if type(value) == "string" then value = "\""..value.."\"" end
            log = log..v.."="..value..","
        end
    end
    
    log     = log .. "point=" .. counter
    log     = log .. " "
    
    for i, v in ipairs(raw_msg.fileds) do
        local value = _get_var(request, v:upper())
        if type(value) == "string" then value = "\""..value.."\"" end
        log = log..v.."="..value..","
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

local function _set_msg_influxdb(request, events, raw_msg, flag)

    local log     = ""
    local counter = 1
    
    if flag == access_log_flag then
        local tf = _add_tags_and_fileds(request, events, raw_msg, counter)
        return _add_timestamp(request, raw_msg, tf)
    end
    
    for modules_name, event in pairs(events) do
        local tf = _add_tags_and_fileds(request, events, raw_msg, counter)
        log = log .. tf
        
        for k, v in pairs(event) do
            if type(v) == "string" then v = "\""..v.."\"" end
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

local function _set_msg_json(request, events, raw_msg, flag)

    local log       = {}
    local safe_flag = 0
    
    if type(raw_msg) ~= "table" then
        ngx_log(WARN, "the type of message is not table")
        return false
    end
    
    for k, v in pairs(events) do
        safe_flag = 1
        break
    end
    
    if flag == security_log_flag and safe_flag == 0 then
        return false
    end
    
    for i = 1, #raw_msg do
        if type(raw_msg[i]) == "string" then
            log[raw_msg[i]] = _get_var(request, raw_msg[i]:upper())
            
        elseif type(raw_msg[i]) == "table" then
            local v = _get_var(request, raw_msg[i][2]:upper())
            log[raw_msg[i][2]] = raw_msg[i][1]..v..raw_msg[i][3]
        end
    end

    if flag == security_log_flag then
        log["safe_event"] = events
    end
    
    return cjson.encode(log) or false
end

function _M:set_msg(ctx, cf, log_format, flag)

    if not ctx then
        return false
    end
    
    local request =  ctx.request
    local events  =  ctx.events.log
    
    if cf.content_type == "JSON" then
        return _set_msg_json(request, events, log_format, flag)
    elseif cf.content_type == "INFLUXDB" then
        return _set_msg_influxdb(request, events, log_format, flag)
    end
    
    return false
end

function _M.log(self, _twaf)

    local cf = _twaf:get_config_param("twaf_log")
    if not cf then
        ngx_log(WARN, "Can't get log config")
        return
    end
    
    local ok, err = twaf_socket.init(cf)
    if not ok then
        ngx_log(ERR, "failed to initalized the twaf_socket:", err)
        return false
    end
    
    if twaf_func:state(cf.access_log_state) == true then
        local security_msg = _M:set_msg(_twaf:ctx(), cf, cf.security_log, access_log_flag)
        if access_msg ~= false then
            local bytes, err = twaf_socket.log(access_msg)
            if err then
                ngx_log(WARN, "failed to log message: ", err)
            end
        end
    end
    
    if twaf_func:state(cf.security_log_state) == true then
        local security_msg = _M:set_msg(_twaf:ctx(), cf, cf.security_log, security_log_flag)
        if security_msg ~= false then
            local bytes, err = twaf_socket.log(security_msg)
            if err then
                ngx_log(WARN, "failed to log message: ", err)
            end
        end
    end
    
    return true
end

return _M
