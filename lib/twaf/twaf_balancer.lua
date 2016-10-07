-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

local balance = require "ngx.balancer"

function _M.balancer(self, _twaf)
    
    local b = _twaf:ctx().balancer
    
    if not b or not b.addr then
        ngx.exit(502)
        return
    end
    
    local ok, err = balance.set_current_peer(b.addr, b.port or 80)
    if not ok then
        ngx.log(ngx.ERR, "failed to set the current peer: " , err)
        return ngx.exit(500)
    end
end

return _M
