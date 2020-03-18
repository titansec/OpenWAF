
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.1"
}

_M.api = {}
_M.help = {}
_M.api.collectgarbage = {}
_M.api.engine_info = {}
_M.api.timer_count = {}
_M.api.shm = {}
_M.api.ctx = {}
_M.api._G = {}
_M.api.version = {}
_M.api.luajit = {}
_M.api.errlog = {}

local  errlog   = require "ngx.errlog"
local  new_tab  = require "table.new"

local _tonumber = tonumber

-- get engine info, e.g: GET /api/collectgarbage
_M.api.collectgarbage.get = function(_twaf, log, u)

    local res = {}
    res.before = collectgarbage("count")
    collectgarbage("collect")
    res.after = collectgarbage("count")
    
    log.result = res
end

-- get engine info, e.g: GET /api/engine_info
_M.api.engine_info.get = function(_twaf, log, u)

    local res = {}
    
    res.timer_running_count    = ngx.timer.running_count()
    res.timer_pending_count    = ngx.timer.pending_count()
    res.config_subsystem       = ngx.config.subsystem
    res.config_debug           = ngx.config.debug
    res.config_prefix          = ngx.config.prefix()
    res.config_nginx_version   = ngx.config.nginx_version
    res.config_nginx_configure = ngx.config.nginx_configure()
    res.config_ngx_lua_version = ngx.config.ngx_lua_version
    res.worker_exiting         = ngx.worker.exiting()
    res.worker_pid             = ngx.worker.pid()
    res.worker_count           = ngx.worker.count()
    
    log.result = res
    return
end

-- get timer count, e.g: GET /api/timer_count
_M.api.timer_count.get = function(_twaf, log, u)
    local res         = {}
    res.running_count = ngx.timer.running_count()
    res.pending_count = ngx.timer.pending_count()
    log.result        = res
    return
end

-- get shm, e.g: GET /api/shm/{shared_dict_name}/{key}
_M.api.shm.get  = function(_twaf, log, u)
    
    if not u[2] then
        log.success = 0
        log.reason = "Not specified shared dict name"
        return
    end
    
    local dict = ngx.shared[u[2]]
    
    if not dict then
        log.success = 0
        log.reason = "invalid shared dict '"..u[2].."'"
        return
    end
    
    if u[3] then
        log.result = dict:get(u[3]) or "nil"
        return
    end
    
    local data = {}
    local keys = dict:get_keys()
    
    for _, k in ipairs(keys) do
        data[k] = dict:get(k) or "nil"
    end
    
    log.result = data
    return
end

-- get ctx, e.g: GET /api/ctx/{output_file_path}
_M.api.ctx.get  = function(_twaf, log, u)

    local path =  u[2] or "/var/log/twaf_ctx.json"
    local gcf  = _twaf:get_config_param("twaf_global")
    local shm  =  gcf.dict_name
    
    if not shm then
        log.success = 0
        log.reason = "Not found shared dict in twaf_global config"
        return
    end
    
    local dict = ngx.shared[shm]
    
    if not dict then
        log.success = 0
        log.reason = "ngx.shared failed '"..tostring(shm).."'"
        return
    end
    
    dict:set("twaf_print_ctx", path)
    
    log.result = "Please request again, then ctx will be written in "..path

end

-- get _G, e.g: GET /api/_G/{output_file_path}
_M.api._G.get  = function(_twaf, log, u)

    local path =  u[2] or "/var/log/twaf_G.json"
    local gcf  = _twaf:get_config_param("twaf_global")
    local shm  =  gcf.dict_name
    
    if not shm then
        log.success = 0
        log.reason = "Not found shared dict in twaf_global config"
        return
    end
    
    local dict = ngx.shared[shm]
    
    if not dict then
        log.success = 0
        log.reason = "ngx.shared failed '"..tostring(shm).."'"
        return
    end
    
    dict:set("twaf_print_G", path)
    
    log.result = "Please request again, then _G will be written in "..path

end

-- get version, e.g: GET /api/version
-- get version, e.g: GET /api/version/{module_name}
_M.api.version.get  = function(_twaf, log, u)
    if not u[2] then
        log.result = _twaf._VERSION
        return
    end
    
    local mod = _twaf.modfactory[u[2]]
    
    if type(mod) ~= "table" then
        log.success = 0
        log.reason  = "No Module '"..u[2].."'"
        return
    end
    
    log.result = mod._VERSION
end

-- get version, e.g: GET /api/luajit
_M.api.luajit.get = function(_twaf, _log, u)

    local jitv
    
    if jit then jitv = jit.version end
    
    _log.result = {
        lua = _VERSION,
        luajit = jitv
    }
    
    return
end

--get errlog, e.g: GET /api/errlog
--TODO: choose: time, level, count
--NOW: last 100 error logs which level > WARN
_M.api.errlog.get = function(_twaf, _log, u)

    local _max = 100
    
    if u[2] then
        _max = _tonumber(u[2])
    end
    
    local buffer   = new_tab(_max * 3, 0)
    local res, err = errlog.get_logs(_max, buffer)
    _log.result = res
    
    --[[
    if res then
        for i = 1, #res, 3 do
            local _level = res[i]
            if not _level then
                break
            end
            local _time = res[i + 1]
            local _msg  = res[i + 2]
            
            _log.result[num] = 
        end
    end
    ]]
end

_M.help.collectgarbage = {
    "GET /api/collectgarbage"
}

_M.help.engine_info = {
    "GET /api/engine_info"
}

_M.help.timer_count = {
    "GET /api/timer_count \
     功能: 打印当前运行和待运行的定时器个数 \
     注: pending_count 表示待运行的定时器个数 \
         running_count 表示正运行的定时器个数 \
         pending_count 上限为 lua_max_pending_timers (默认1024) \
         running_count 上限为 lua_max_running_timers (默认256)"
}

_M.help._G = {
    "GET /api/_G/{output_file_path} \
     功能: 打印 _G 至指定文件 \
     注: output_file_path 表示输出信息存储路径，默认路径 var/log/twaf_G.json"
}

_M.help.ctx = {
    "GET /api/ctx/{output_file_path} \
     功能: 打印 ctx 至指定文件 \
     注: output_file_path 表示输出信息存储路径，默认路径 var/log/twaf_ctx.json"
}

_M.help.shm = {
    "GET /api/shm/{shared_dict_name}/{key}"
}

_M.help.version = {
    "GET /api/version",
    "GET /api/version/{module_name}"
}

_M.help.luajit = {
    "GET /api/luajit"
}

_M.help.errlog = {
    "GET /api/errlog"
}

return _M