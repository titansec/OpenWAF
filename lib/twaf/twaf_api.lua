
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func          = require "lib.twaf.inc.twaf_func"

local io_popen           = io.popen
local _type              = type
local string_format      = string.format
local ngx_say            = ngx.say
local ngx_var            = ngx.var
local ngx_log            = ngx.log
local ngx_ERR            = ngx.ERR
local ngx_req_get_method = ngx.req.get_method
local ngx_shared         = ngx.shared
local ngx_worker_id      = ngx.worker.id
local ngx_worker_pid     = ngx.worker.pid
local ngx_worker_count   = ngx.worker.count

local api          = {}
local prefix       = "/api/"
local api_path     = "lib/twaf/twaf_api"
local api_pre_path = "/opt/OpenWAF/"

api.help                 = {}
api.help_tb              = {}

local function _load_api_file(tb)
    local f = io_popen(string_format("ls %s%s/*.lua 2>/dev/null", api_pre_path, api_path))
    if not f then return end
    
    local paths = f:read("*a")
    f:close()
    
    if _type(paths) == "string" and #paths == 0 then
        return
    end
    
    paths = twaf_func:string_trim(paths)
    paths = twaf_func:string_ssplit(paths,string.char(10))
    
    for _, p in pairs(paths) do
        p = p:sub(#api_pre_path + 1, -5)
        local mod = require(p)
        twaf_func.table_merge(tb, mod.api)
        twaf_func.table_merge(tb.help_tb, mod.help)
    end
    
    return tb
end

_load_api_file(api)

api.help.get = function(_twaf, _log, u)

    if u[2] then
        _log.result = api.help_tb[u[2]]
        return
    end

    _log.result = api.help_tb
    
    -- TODO:
    -- 1. 替换 host/path/
    -- 2. 详细说明每一个 API
end

--[[
{"success": 1, "result":"xxx"}
{"success": 0, "reason":"xxx"}
]]
function _M.content(self, _twaf)

    local _log   = {}
    _log.success = 1
    _log.reason  = nil
    
    local uri    = ngx_var.uri or "-"
    local method = (ngx_req_get_method() or "-"):lower()
    
    -- config synchronization
    twaf_func:syn_config(_twaf)
    
    repeat
    
    local from, to, u = uri:find(prefix.."(.*)")
    if not from then
        _log.success = 0
        _log.reason  = "uri not right"
        break
    end
    
    u = twaf_func:string_ssplit(u, "/")
    if _type(u) ~= "table" then
        _log.success = 0
        _log.reason  = "string_ssplit was wrong in twaf_func.lua"
        break
    end
    
    if not api[u[1]] then
        _log.success = 0
        _log.reason  = string_format("no api -- %s", u[1])
        break
    end
    
    if not api[u[1]][method] then
        _log.success = 0
        _log.reason  = string_format("%s: no method %s", u[1], method)
        break
    end
    
    if #u[#u] == 0 then
        u[#u] = nil
    end
    
    api[u[1]][method](_twaf, _log, u)
    
    if u[1] == "web_tamper_protecting_download" 
    or u[1] == "web_tamper_tampered_download" then
        ngx_say(twaf_func:table_to_string(_log.result))
        return
    end
    
    until true
    
    if method ~= "get" and _log.success == 1 then
        local worker_config = twaf_func:table_to_string(_twaf.config)
        if worker_config then
            local gcf    = _twaf:get_default_config_param("twaf_global")
            local dict   =  ngx_shared[gcf.dict_name]
            local wid    =  ngx_worker_id()
            local wpid   =  ngx_worker_pid()
            local wcount =  ngx_worker_count()
            
            dict:set("worker_config", worker_config)
            
            for i = 0, wcount -1, 1 do
                dict:set("worker_process_"..i, true)
            end
            dict:set("worker_process_"..wid, wpid)
        else
            ngx_log(ngx_ERR, "synchronization Failure!")
        end
    end
    
    ngx_say(twaf_func:table_to_string(_log))
end

return _M
