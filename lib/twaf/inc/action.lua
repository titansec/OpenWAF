
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

_M.error_page = 
"<html> \
<head><title>{{status}}</title></head> \
<body bgcolor=\"white\"> \
<center><h1>{{status}}</h1></center> \
<hr><center>webapng {{ngx_ver}}</center> \
</body> \
</html>"

_M.status_lines = {
    [200] = "200 OK",
    [201] = "201 Created",
    [202] = "202 Accepted",
    [204] = "204 No Content",
    [206] = "206 Partial Content",
    [301] = "301 Moved Permanently",
    [302] = "302 Moved Temporarily",
    [303] = "303 See Other",
    [304] = "304 Not Modified",
    [400] = "400 Bad Request",
    [401] = "401 Unauthorized",
    [402] = "402 Payment Required",
    [403] = "403 Forbidden",
    [404] = "404 Not Found",
    [405] = "405 Not Allowed",
    [406] = "406 Not Acceptable",
    [408] = "408 Request Time-out",
    [409] = "409 Conflict",
    [410] = "410 Gone",
    [411] = "411 Length Required",
    [412] = "412 Precondition Failed",
    [413] = "413 Request Entity Too Large",
    [415] = "415 Unsupported Media Type",
    [416] = "416 Requested Range Not Satisfiable",
    [500] = "500 Internal Server Error",
    [501] = "501 Method Not Implemented",
    [502] = "502 Bad Gateway",
    [503] = "503 Service Temporarily Unavailable",
    [504] = "504 Gateway Time-out",
    [507] = "507 Insufficient Storage"
}

function _M.do_action(self, _twaf, action, meta)

    local simulation = _twaf:get_modules_config_param("twaf_global", "simulation")
    if simulation == true or not action then
        action = "PASS"
    end
    
    local actions = {
        PASS = function (_twaf)
            -- not match, countinue other rules or modules
            return false
        end,
        AUDIT = function (_twaf)
            -- not match, countinue other rules or modules
            return false
        end,
        WARN = function (_twaf)
            -- not match, countinue other rules or modules
            return false
        end,
        ALLOW = function(_twaf, meta)
            -- stopping processing of the current phase but also skipping over all other phases
            _twaf:ctx().trust = true
            return true
        end,
        ALLOW_PHASE = function(_twaf, meta)
            -- stopping processing of the current phase
            return true
        end,
        CHAIN = function(_twaf, meta)
            return ngx.OK
        end,
        DENY = function(_twaf, meta)
            meta = tonumber(meta) or 403
            
            local phase = ngx.get_phase()
            
            if phase ~= "body_filter" then
                ngx.exit(meta)
                return true
            end
            
            ngx.status = meta
            local output = _M.error_page
            output = output:gsub("{{status}}", _M.status_lines[meta])
            output = output:gsub("{{ngx_ver}}", ngx.var.nginx_version)
                
            ngx.header['Content-Length'] = #output
            ngx.arg[1] = output
            
            return true
        end,
        REDIRECT = function(_twaf, meta)
            meta = tostring(meta)
            local phase = ngx.get_phase()
            if phase == "access" then
                ngx.redirect(meta)
            elseif phase == "header_filter" then
                ngx.header['Location'] = meta
                ngx.status = 302
            end
            
            return true
        end,
        ROBOT = function(_twaf)
            ngx.var.twaf_attack_info = ""
            _twaf.modfactory.twaf_anti_robot:handler(_twaf)
        end,
        RESET_CONNECTION = function()
            ngx.ctx.reset_connection = true
            return ngx.DONE
        end
    }
    
    return actions[action:upper()](_twaf, meta)
end

return _M
