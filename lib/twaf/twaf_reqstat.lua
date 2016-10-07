-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
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
local ngx_null             = ngx.null
local ngx_send_headers     = ngx.send_headers
local ngx_req_get_uri_args = ngx.req.get_uri_args
local ngx_time             = ngx.time

local modules_name         = "twaf_reqstat"
local global_uuid          = "GLOBAL"
local stat_uuids           = {}
local start_sec
local state
local safe_state
local access_state
local upstream_state
local shared_dict_name

local delay
local reqstat_dict

local stat_safe     = {}
local stat_access   = {"addr_total", "req_total", "bytes_in", "attack_total",
                       "bytes_out", "conn_total", "1xx", "2xx", "3xx", "4xx", "5xx"}
local stat_upstream = {"req_total", "bytes_in", "bytes_out", "1xx", "2xx", "3xx", 
                       "4xx", "400", "401", "403", "404", "405", "406", "407", "408", 
                       "409", "410", "411", "412", "413", "414", "415", "416", "417",
                       "5xx", "500", "501", "502", "503", "504", "505", "507"}					   

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

    

    local nginx_version =  twaf_func:get_variable("nginx_version")
    local active        =  twaf_func:get_variable("connections_active")
    local reading       =  twaf_func:get_variable("connections_reading")
    local writing       =  twaf_func:get_variable("connections_writing")
    local waiting       =  twaf_func:get_variable("connections_waiting")
    local accepted      =  twaf_func:get_variable("stat_accepted")
    local handled       =  twaf_func:get_variable("stat_handled")
    local requests      =  twaf_func:get_variable("stat_requests")
    local reset_sec     = _get_dict_info("reset_sec")

    local info                    = {}
    info.main                     = {}
    info.main.connection          = {}
    info.main.nginx_version       = nginx_version
    info.main.loadsec             = start_sec
    info.main.resetsec            = reset_sec
    info.main.connection.active   = active
    info.main.connection.reading  = reading
    info.main.connection.writing  = writing
    info.main.connection.waiting  = waiting
    info.main.connection.accepted = accepted
    info.main.connection.handled  = handled
    info.main.connection.requests = requests

    _get_reqstat_info(info.main, modules_name.."_"..global_uuid)

    return info
end

function _M.get_reqstat_uuid_info(self, uuids)

    local info = {}

    if uuids[1] == "policy_all" then
        for uuid, _ in pairs(stat_uuids) do
             info[uuid] = {}
            _get_reqstat_info(info[uuid], modules_name.."_"..uuid)
        end
    end
    
    for _, uuid in ipairs(uuids) do
        if stat_uuids[uuid] then
             info[uuid] = {}
            _get_reqstat_info(info[uuid], modules_name.."_"..uuid)
        else
            ngx_log(ngx.ERR, "uuid \""..uuid.."\" is not exist")
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

local function _log_access_stat(safe_event, key)

    local status       = tonumber(ngx.status)
    local bytes_in     = tonumber(ngx_var.bytes_in) or 0
    local bytes_sent   = tonumber(ngx_var.bytes_sent) or 0
    local conn         = ngx_var.connection_requests

    reqstat_dict:incr(key.."_req_total", 1)
    reqstat_dict:incr(key.."_bytes_in", bytes_in)
    reqstat_dict:incr(key.."_bytes_out", bytes_sent)
    
    if conn == "1" then
        reqstat_dict:incr(key.."_conn_total", 1)
    end
    
    if safe_event then
        for k, _ in pairs(safe_event) do
            reqstat_dict:incr(key.."_attack_total", 1)
            break
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
    
    for k, _ in pairs(safe_event) do
        stat_safe[k] = 1
        reqstat_dict:add(key.."_"..k, 0)
        reqstat_dict:incr(key.."_"..k, 1)
    end
end

local function _log_upstream_stat(key)

    local status    = tonumber(ngx_var.upstream_status)
    local bytes_in  = tonumber(ngx_var.bytes_in) or 0
    local bytes_out = tonumber(ngx_var.upstream_response_length) or 0
    
    if status == nil or bytes_in == nil or bytes_out == nil then
        return
    end
    
--  bytes_in  = bytes_in  or 0
--  bytes_out = bytes_out or 0

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

local function _reqstat(events, uuid)

    access_state   = twaf_func:state(access_state)
    safe_state     = twaf_func:state(safe_state)
    upstream_state = twaf_func:state(upstream_state)

    local key      = modules_name.."_"..uuid
    local value    = reqstat_dict:get(key)
    
    if value == nil then
        stat_uuids[uuid] = 1
        reqstat_dict:add(key, 1)
        _reqstat_access_init(key)
        _reqstat_safe_init(key)
        _reqstat_upstream_init(key)
    end

    if safe_state == true then
        _log_safe_stat(events, key)
    end
	
    if access_state == true then
        _log_access_stat(events, key)
    end

    if upstream_state == true then
        _log_upstream_stat(key)
    end

end

function _M.reqstat_log_handler(self, events, uuid)

    if twaf_func:state(state) == false then
        return true
    end

    _reqstat(events, global_uuid)
    -- policy test
    if uuid then
        _reqstat(events, uuid)
    end
    -- test end
    return true
end

--init

local function _reqstat_init()

    reqstat_dict = ngx_shared[shared_dict_name]

    reqstat_dict:delete(modules_name.."_init")
    
    for uuid, _ in pairs(stat_uuids) do
        local key   = modules_name.."_"..uuid
        local value = reqstat_dict:get(key)
        if value == nil then
             reqstat_dict:add(key, 1)
            _reqstat_access_init(key)
            _reqstat_safe_init(key)
            _reqstat_upstream_init(key)
        end
    end
    
    local key = modules_name.."_start_sec"
    start_sec = reqstat_dict:get(key)
    if not start_sec then
        start_sec = ngx_time()
        reqstat_dict:add(key, start_sec)
    end
end

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
            shared_dict_name = v
        elseif k == "delay" then
            delay = v
        end
    end
    
    stat_uuids = twaf_func:copy_table(uuids)
    stat_uuids[global_uuid] = 1
    
    _reqstat_init()

    return setmetatable({config = reqstat_conf} , mt)
end

return _M
