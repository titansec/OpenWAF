
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local ngx_re_find   = ngx.re.find
local ngx_re_gsub   = ngx.re.gsub
local ngx_OK        = ngx.OK
local ngx_DONE      = ngx.DONE
local ngx_exit      = ngx.exit
local ngx_var       = ngx.var
local ngx_header    = ngx.header
local ngx_redirect  = ngx.redirect
local ngx_get_phase = ngx.get_phase
local string_upper  = string.upper
local string_gsub   = string.gsub
local _type         = type
local _tonumber     = tonumber
local _tostring     = tostring
local ngx_resp_get_headers  = ngx.resp.get_headers

local actions_mapping = {
    ALLOW = 1,
    ALLOW_PHASE = 2,
    AUDIT = 3,
    CHAIN = 4,
    DENY = 5,
    GEETEST = 6,
    OPAGE = 7,
    PASS = 8,
    REDIRECT = 9,
    RESET_CONNECTION = 10,
    ROBOT = 11,
    WARN = 12
}

local function _parse_dynamic_value(self, key, req)
    local lookup = function(m)
        local val      = twaf:get_vars(string_upper(m[1]), req)
        local specific = m[2]
        
        if (not val) then
            --logger.fatal_fail("Bad dynamic parse, no collection key " .. m[1])
            return "-"
        end
        
        if (_type(val) == "table") then
            if (specific) then
                return val[specific]
            else
                return val
                --return tostring(m[1])
            end
        elseif (_type(val) == "function") then
            return val(twaf)
        else
            return val
        end
    end
    
    -- grab something that looks like
    -- %{VAL} or %{VAL.foo}
    -- and find it in the lookup table
    local str = ngx_re_gsub(key, [[%{([^\.]+?)(?:\.([^}]+))?}]], lookup, "oij")
    
    if str == "nil" then str = nil end
    
    --logger.log(_twaf, "Parsed dynamic value is " .. str)
    
    if (ngx_re_find(str, [=[^\d+$]=], "oij")) then
        return _tonumber(str)
    else
        return str
    end
end

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

function _M.is_action(action, meta)

    action = string_upper(action)
    local num = actions_mapping[action]
    if not num then
        return false, "wrong action config!"
    end

    if action == "DENY" then
        meta = meta or 403
        meta = _tonumber(meta) or 0
        if meta < 100 and meta > 1000 then
            return false, "wrong action meta config!"
        end
    elseif action == "REDIRECT" then
        if _type(meta) ~= "string" then
            return false, "action meta: expect string type!"
        end
    end

    return true, action, meta -- return true, num, meta
end

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
        ALLOW = function(_twaf)
            -- stopping processing of the current phase but also skipping over all other phases
            _twaf:ctx().trust = true
            return true
        end,
        ALLOW_PHASE = function(_twaf)
            -- stopping processing of the current phase
            return true
        end,
        CHAIN = function(_twaf)
            return ngx_OK
        end,
        DENY = function(_twaf, meta)
        
            local ctx    = _twaf:ctx()
            local output = _M.error_page
            local phase  =  ngx_get_phase()
            
            meta = tonumber(meta) or 403
            
            if phase ~= "body_filter" then
                ngx_exit(meta)
                return true
            end
            
            output = string_gsub(output, "{{status}}", _M.status_lines[meta])
            output = string_gsub(output, "{{ngx_ver}}", ngx_var.nginx_version)
            
            if ngx_resp_get_headers()['Content-Length'] then
                ngx.status = meta
                ngx_header['Content-Length'] = #output
            end
            
            ngx.arg[1] = output
            ngx.arg[2] = true
            
            ctx.interrupt = true
            
            return true
        end,
        REDIRECT = function(_twaf, meta)
        
            local ctx   = _twaf:ctx()
            local phase =  ngx_get_phase()
            
            meta = _parse_dynamic_value(nil, meta, ctx.req)
            
            if phase == "access" then
            
                ngx_redirect(_tostring(meta))
            elseif phase == "header_filter" then
            
                ngx.status = 302
                ngx_header['Location'] = _tostring(meta)
            elseif phase == "body_filter" then
            
                -- TODO
            end
            
            ctx.interrupt = true
            
            return true
        end,
        ROBOT = function(_twaf)
            ngx_var.twaf_attack_info = ""
            _twaf.modfactory.twaf_anti_robot:handler(_twaf, true)
        end,
        GEETEST = function(_twaf)
            ngx_var.twaf_attack_info = ""
            return _twaf.modfactory.twaf_geetest:handler(_twaf, true)
        end,
        RESET_CONNECTION = function(_twaf)
            _twaf:ctx().reset_connection = true
            return ngx_DONE
        end,
        OPAGE = function(_twaf, meta)
            return false
        end
    }
    
    return actions[string_upper(action)](_twaf, meta)
end

return _M
