
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local balance = require "ngx.balancer"

local ngx_exit = ngx.exit
local ngx_ERR  = ngx.ERR
local ngx_log  = ngx.log

function _M.balancer(self, _twaf)
    
    local b = _twaf:ctx().balancer
    
    if not b or not b.addr then
        ngx_exit(502)
        return
    end
    
    local ok, err = balance.set_current_peer(b.addr, b.port or 80)
    if not ok then
        ngx_log(ngx_ERR, "failed to set the current peer: " , err)
        return ngx_exit(500)
    end
    
    -- set_timeouts(connect_timeout, send_timeout, read_timeout)
    local ok, err = balance.set_timeouts(b.timeout, b.timeout, b.timeout)
    if not ok then
        ngx_log(ngx_ERR, "failed to set balancer timeout: " , err)
        return ngx_exit(500)
    end
end

return _M
