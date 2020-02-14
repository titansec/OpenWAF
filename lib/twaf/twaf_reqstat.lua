
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local cjson                = require "cjson.safe"
local twaf_func            = require "lib.twaf.inc.twaf_func"

local mt                   = { __index = _M }
local ngx_header           = ngx.header
local ngx_HTTP_OK          = ngx.HTTP_OK
local ngx_log              = ngx.log
local ngx_var              = ngx.var
local ngx_shared           = ngx.shared
local ngx_ERR              = ngx.ERR
local ngx_send_headers     = ngx.send_headers
local ngx_req_get_uri_args = ngx.req.get_uri_args
local ngx_time             = ngx.time
local ngx_timer_at         = ngx.timer.at

local _tonumber            = tonumber

local modules_name         = "twaf_reqstat"
local global_uuid          = "GLOBAL"
local start_sec
local state
local safe_state
local access_state
local upstream_state
local shared_dict_name
local reqstat_dict


local stat_access   = {"addr_total", "req_total", "bytes_in", "attack_total",
                       "bytes_out", "conn_total", "1xx", "2xx", "3xx", "4xx", "5xx"}
local stat_safe     = {}
local stat_upstream = {"req_total", "bytes_in", "bytes_out", "1xx", "2xx", "3xx", 
                       "4xx", "400", "401", "403", "404", "405", "406", "407", "408", 
                       "409", "410", "411", "412", "413", "414", "415", "416", "417",
                       "5xx", "500", "501", "502", "503", "504", "505", "507"}

local stat_action   = {"DENY", "WARN", "RESET_CONNECTION", "OPAGE"}

local function _get_dict_info(key)
    return reqstat_dict:get(key) or 0
end

function _M.reqstat_clear(self)

    reqstat_dict:flush_all()
    reqstat_dict:flush_expired()
    reqstat_dict:add(modules_name.."_reset_sec", ngx_time())
    
    return true
end

--content

local function _get_reqstat_access_info(info, key)

    for _, v in pairs(stat_access) do
        info[v] = _get_dict_info(key.."_"..v)
    end
end

local function _get_reqstat_safe_info(info, key)

    local d_key     = modules_name.."_safe_keys"
    local stat_safe = cjson.decode(reqstat_dict:get(d_key)) or {}
    
    for k, _ in pairs(stat_safe) do
        info[k] = _get_dict_info(key.."_"..k)
    end
end

local function _get_reqstat_upstream_info(info, key)

    for _, v in pairs(stat_upstream) do
        info[v] = _get_dict_info(key.."_upstream_"..v)
    end
end

local function _get_reqstat_info(info, key)

     info.safe = {}
    _get_reqstat_safe_info(info.safe, key)
    
     info.access = {}
    _get_reqstat_access_info(info.access, key)
    
     info.upstream = {}
    _get_reqstat_upstream_info(info.upstream, key)

end

function _M.get_reqstat_main_info(self)

    local info                    =  {}
    info.main                     =  {}
    info.main.connection          =  {}
    info.main.loadsec             =  start_sec
    info.main.resetsec            = _get_dict_info("reset_sec")
    info.main.nginx_version       =  ngx_var.nginx_version                 or "-"
    info.main.connection.active   = _tonumber(ngx_var.connections_active)  or 0
    info.main.connection.reading  = _tonumber(ngx_var.connections_reading) or 0
    info.main.connection.writing  = _tonumber(ngx_var.connections_writing) or 0
    info.main.connection.waiting  = _tonumber(ngx_var.connections_waiting) or 0
    info.main.connection.accepted = _tonumber(ngx_var.stat_accepted)       or 0
    info.main.connection.handled  = _tonumber(ngx_var.stat_handled)        or 0
    info.main.connection.requests = _tonumber(ngx_var.stat_requests)       or 0
    
    _get_reqstat_info(info.main, modules_name.."_"..global_uuid)
    
    return info
end

function _M.get_reqstat_uuid_info(self, uuids)

    local info = {}
    
    local stat_keys  = reqstat_dict:get(modules_name.."_stat_uuids")
    local stat_uuids = cjson.decode(stat_keys) or {}
    
    if uuids[1] == "policy_all" then
        for uuid, _ in pairs(stat_uuids) do
             info[uuid] = {}
            _get_reqstat_info(info[uuid], modules_name.."_"..uuid)
        end
        
        return info
    end
    
    for _, uuid in ipairs(uuids) do
        if stat_uuids[uuid] then
             info[uuid] = {}
            _get_reqstat_info(info[uuid], modules_name.."_"..uuid)
        else
            ngx_log(ngx_ERR, "uuid \""..uuid.."\" is not exist")
        end
    end
    
    return info
end

function _M.reqstat_show_handler(self)
    
    local reqstat_info  =  {}
    local show_uuid     =  ngx_req_get_uri_args()["uuid"]
    
    if type(show_uuid) == "string" then
        show_uuid = {show_uuid}
    end
    
    ngx_header['Content_Type'] = "application/json"
    ngx.status = ngx_HTTP_OK
    ngx_header['Content_Length'] = nil
    
    local ok, err = ngx_send_headers()
    if err then
        ngx_log(ngx_ERR, "failed to send headers -- ", err)
        ngx.exit(500)
    end
    
    if show_uuid == nil then
        reqstat_info = _M:get_reqstat_main_info()
    else
        reqstat_info = _M:get_reqstat_uuid_info(show_uuid)
    end
    
    ngx.say(cjson.encode(reqstat_info))
    
    return true
end

--log

local function _reqstat_access_init(key)
    for _, v in pairs(stat_access) do
        reqstat_dict:add(key.."_"..v, 0)
    end
end

local function _reqstat_safe_init(key)
    for k, _ in pairs(stat_safe) do
        reqstat_dict:add(key.."_"..k, 0)
    end
end

local function _reqstat_upstream_init(key)
    for _, v in pairs(stat_upstream) do
        reqstat_dict:add(key.."_upstream_"..v, 0)
    end
end

local function _log_access_stat(safe_event, key, ctx)

    local status       = ctx.RESPONSE_STATUS
    local bytes_in     = ctx.BYTES_IN
    local bytes_sent   = ctx.BYTES_SENT
    local conn         = ctx.CONNECTION_REQUESTS
    
    reqstat_dict:incr(key.."_req_total", 1)
    reqstat_dict:incr(key.."_bytes_in", bytes_in)
    reqstat_dict:incr(key.."_bytes_out", bytes_sent)
    
    if conn == "1" then
        reqstat_dict:incr(key.."_conn_total", 1)
    end
    
    if safe_event then
        for k, v in pairs(safe_event) do
            if twaf_func:table_has_value(stat_action, v) then
                reqstat_dict:incr(key.."_attack_total", 1)
                break
            end
        end
    end
	
    if status >= 100 and status < 200 then
        reqstat_dict:incr(key.."_1xx", 1)
    elseif status >= 200 and status < 300 then
        reqstat_dict:incr(key.."_2xx", 1)
    elseif status >= 300 and status < 400 then
        reqstat_dict:incr(key.."_3xx", 1)
    elseif status >= 400 and status < 500 then
        reqstat_dict:incr(key.."_4xx", 1)
    elseif status >= 500 and status < 600 then
        reqstat_dict:incr(key.."_5xx", 1)
    end
end

local function _log_safe_stat(safe_event, key)

    if safe_event == nil then
        return
    end
    
    for k, v in pairs(safe_event) do
        if twaf_func:table_has_value(stat_action, v) then
            reqstat_dict:add(key.."_"..k, 0)
            reqstat_dict:incr(key.."_"..k, 1)
            
            if not reqstat_dict:get(k) then
                local d_key = modules_name.."_safe_keys"
                local stat_safe = cjson.decode(reqstat_dict:get(d_key)) or {}
                stat_safe[k] = 1
                reqstat_dict:set(d_key, cjson.encode(stat_safe))
            end
        end
    end
end

local function _log_upstream_stat(key, ctx)

    local status    = ctx.UPSTREAM_STATUS
    local bytes_in  = ctx.UPSTREAM_BYTES_SENT
    local bytes_out = ctx.UPSTREAM_BYTES_RECEIVED
    
    if status == nil or bytes_in == nil or bytes_out == nil then
        return
    end
    
    reqstat_dict:incr(key.."_upstream_req_total", 1)
    reqstat_dict:incr(key.."_upstream_bytes_in", bytes_in)
    reqstat_dict:incr(key.."_upstream_bytes_out", bytes_out)
    
    if status >= 100 and status < 200 then
        reqstat_dict:incr(key.."_upstream_1xx", 1)
    elseif status >= 200 and status < 300 then
        reqstat_dict:incr(key.."_upstream_2xx", 1)
    elseif status >= 300 and status < 400 then
        reqstat_dict:incr(key.."_upstream_3xx", 1)
    elseif status >= 400 and status < 500 then
        reqstat_dict:incr(key.."_upstream_4xx", 1)
        reqstat_dict:incr(key.."_upstream_"..tostring(status), 1)
    elseif status >= 500 and status < 600 then
        reqstat_dict:incr(key.."_upstream_5xx", 1)
        reqstat_dict:incr(key.."_upstream_"..tostring(status), 1)
    end
end

local function _reqstat(events, uuid, ctx)

    access_state   = twaf_func:state(access_state)
    safe_state     = twaf_func:state(safe_state)
    upstream_state = twaf_func:state(upstream_state)
    
    local key      = modules_name.."_"..uuid
    
    if not reqstat_dict:get(key) then
        reqstat_dict:add(key, 1)
        _reqstat_access_init(key)
        _reqstat_safe_init(key)
        _reqstat_upstream_init(key)
        
        local d_key      = modules_name.."_stat_uuids"
        local stat_uuids = cjson.decode(reqstat_dict:get(d_key)) or {}
        stat_uuids[uuid] = 1
        reqstat_dict:set(d_key, cjson.encode(stat_uuids))
    end
    
    if safe_state == true then
        _log_safe_stat(events, key)
    end
	
    if access_state == true then
        _log_access_stat(events, key, ctx)
    end
    
    if upstream_state == true then
        _log_upstream_stat(key, ctx)
    end

end

local _timer_log = function (premature, events, ctx, uuid)
    _reqstat(events, global_uuid, ctx)
    
    if uuid then
        _reqstat(events, uuid, ctx)
    end
end

function _M.reqstat_log_handler(self, _twaf)

    if twaf_func:state(state) == false then
        return true
    end
    
    local cf      = _twaf:get_config_param(modules_name)
    local tctx    = _twaf:ctx()
    local req     =  tctx.req
    local key     =  twaf_func:key(cf.shared_dict_key)
    local events  =  tctx.events.stat
    local ctx     =  {}
    
    ctx.RESPONSE_STATUS         = _twaf:get_vars("RESPONSE_STATUS", req)
    ctx.BYTES_IN                = _twaf:get_vars("BYTES_IN", req)
    ctx.BYTES_SENT              = _twaf:get_vars("BYTES_SENT", req)
    ctx.CONNECTION_REQUESTS     = _twaf:get_vars("CONNECTION_REQUESTS", req)
    ctx.UPSTREAM_STATUS         = _twaf:get_vars("UPSTREAM_STATUS", req)
    ctx.UPSTREAM_BYTES_SENT     = _twaf:get_vars("BYTES_IN", req)  -- UPSTREAM_BYTES_SENT
    ctx.UPSTREAM_BYTES_RECEIVED = _twaf:get_vars("UPSTREAM_BYTES_RECEIVED", req)
    
    local ok, err = ngx_timer_at(0, _timer_log, events, ctx, key)
    if not ok then
        ngx_log(ngx_ERR, "twaf_limit_conn - failed to create timer: ", err)
        return
    end
    
    return true
end

--init

function _M.new(self, reqstat_conf, uuids)

    if type(reqstat_conf) ~= "table" then
        ngx_log(ngx_ERR, "the type of reqstat config must be table")
        return false
    end
    
    for k, v in pairs(reqstat_conf) do 
        if k == "state" then
            state = v
        elseif k == "safe_state" then
            safe_state = v
        elseif k == "access_state" then
            access_state = v
        elseif k == "upstream_state" then
            upstream_state = v
        elseif k == "shared_dict_name" then
            reqstat_dict = assert(ngx_shared[v], "no shared dict " .. v)
        end
    end
    
    if not reqstat_dict then assert(nil, "no shared dict") end
    
    local d_key     = modules_name.."_stat_uuids"
    if not reqstat_dict:get(d_key) then
        local stat_uuids = {}
        stat_uuids[global_uuid] = 1
        reqstat_dict:set(d_key, cjson.encode(stat_uuids))
    end
    
    return setmetatable({config = reqstat_conf} , mt)
end

return _M
