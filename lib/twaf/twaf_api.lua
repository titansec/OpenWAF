
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local twaf_func    = require "lib.twaf.inc.twaf_func"
local api          = {}
local prefix       = "/api/"
local api_path     = "lib/twaf/twaf_api"
local api_pre_path = "/opt/OpenWAF/"

api.help           = {}
api.help_tb        = {}

local function _load_api_file(tb)
    local f = io.popen("ls "..api_pre_path..api_path.."/*.lua 2>/dev/null")
    if not f then return end
    
    local paths = f:read("*a")
    f:close()
    
    if type(paths) == "string" and #paths == 0 then
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

api.help.get = function(_twaf, log, u)

    if u[2] then
        log.result = api.help_tb[u[2]]
        return
    end

    log.result = api.help_tb
    
    -- TODO:
    -- 1. 替换 host/path/
    -- 2. 详细说明每一个 API
end

--[[
{"success": 1, "result":"xxx"}
{"success": 0, "reason":"xxx"}
]]
function _M.content(self, _twaf)

    local log   = {}
    log.success = 1
    log.reason  = nil
    
    local uri    = ngx.var.uri or "-"
    local method = (ngx.req.get_method() or "-"):lower()
    
    -- config synchronization
    twaf_func:syn_config(_twaf)
    
    repeat
    
    local from, to, u = uri:find(prefix.."(.*)")
    if not from then
        log.success = 0
        log.reason  = "uri not right"
        break
    end
    
    u = twaf_func:string_ssplit(u, "/")
    if type(u) ~= "table" then
        log.success = 0
        log.reason  = "string_ssplit was wrong in twaf_func.lua"
        break
    end
    
    if not api[u[1]] then
        log.success = 0
        log.reason  = "no api -- " .. u[1]
        break
    end
    
    if not api[u[1]][method] then
        log.success = 0
        log.reason  = "no api -- " .. u[1]
        break
    end
    
    if #u[#u] == 0 then
        u[#u] = nil
    end
    
    api[u[1]][method](_twaf, log, u)
    
    until true
    
    if method ~= "get" and log.success == 1 then
        local worker_config = twaf_func:table_to_string(_twaf.config)
        if worker_config then
            local gcf    = _twaf:get_default_config_param("twaf_global")
            local dict   = ngx.shared[gcf.dict_name]
            local wid    = ngx.worker.id()
            local wpid   = ngx.worker.pid()
            local wcount = ngx.worker.count()
            
            dict:set("worker_config", worker_config)
            
            for i = 0, wcount -1, 1 do
                dict:set("worker_process_"..i, true)
            end
            dict:set("worker_process_"..wid, wpid)
        else
            ngx.log(ngx.ERR, "synchronization Failure!")
        end
    end
    
    ngx.say(twaf_func:table_to_string(log))
end

return _M
