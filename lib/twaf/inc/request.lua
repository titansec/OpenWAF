
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.0"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local redis_m   = require "resty.redis"

local ngx_var               = ngx.var
local ngx_now               = ngx.now
local ngx_log               = ngx.log
local ngx_ERR               = ngx.ERR
local ngx_exit              = ngx.exit
local ngx_time              = ngx.time
local ngx_re_find           = ngx.re.find
local ngx_re_match          = ngx.re.match
local ngx_req_read_body     = ngx.req.read_body
local ngx_req_start_time    = ngx.req.start_time
local ngx_req_get_headers   = ngx.req.get_headers
local ngx_req_get_uri_args  = ngx.req.get_uri_args
local ngx_req_get_method    = ngx.req.get_method
local ngx_req_get_body_file = ngx.req.get_body_file
local ngx_req_get_post_args = ngx.req.get_post_args
local ngx_req_get_body_data = ngx.req.get_body_data
local ngx_HTTP_FORBIDDEN    = ngx.HTTP_FORBIDDEN
local ngx_req_http_version  = ngx.req.http_version
local ngx_req_raw_header    = ngx.req.raw_header
local ngx_resp_get_headers  = ngx.resp.get_headers
local table_insert          = table.insert
local table_remove          = table.remove
local string_match          = string.match
local string_find           = string.find
local _type                 = type
local _tonumber             = tonumber
local _tostring             = tostring
local _os_date              = os.date

_M.phase = {
    init = 1,
    init_worker = 2,
    ssl_cert = 3,
    ssl_session_fetch = 4,
    ssl_session_store = 5,
    set = 6,
    rewrite = 7,
    balancer = 8,
    access = 9,
    content = 10,
    header_filter = 11,
    body_filter = 12,
    log = 13,
    timer = 14
}

local function _get_vars(req, var)
    return req[var] or _M.vars[var](req)
end

local function _ip_version(self)
    local addr_len = #(ngx_var.binary_remote_addr or "-")
    
    if addr_len == 4 then
        return "IPv4"
    elseif addr_len == 16 then
        return "IPv6"
    else
        ngx_log(ngx_ERR, "expected 4 or 16, but got binary_remote_addr length "..addr_len)
        return "-"
    end
end

local function _basename(uri)
    local m = ngx_re_match(uri, [=[(/[^/]*+)+]=], "oij")
    return m[1]
end

local function _vars_op(op, ...)
    
    local func = {
        get_post_args = function(request_headers)
            
            request_headers = request_headers[1]
            local content_type = request_headers["content-type"]
            if not content_type then
                return nil
            end
            
            if ngx_re_find(content_type, [=[^application/x-www-form-urlencoded]=], "oij") then
                --ngx_req_read_body()
                
                if ngx_req_get_body_file() == nil then
                    return ngx_req_get_post_args(0)
                else
                    return nil
                end
            end
            
            return nil
        end,
        args = function (parms)
            local t = {}
            
            for _, parm in ipairs(parms) do
                if parm then
                    for k, v in pairs(parm) do
                        t[k] = v
                    end
                end
            end
            
            return t
        end,
        args_combined_size = function(args)
            local length = 0
            args = args[1]
            
            for key, val in pairs(args) do
                if _type(val) == "table" then
                    local t = twaf_func:table_values(val)
                    for _, v in pairs(t) do
                        length = length + #key
                        length = length + #_tostring(v)
                    end
                else
                    length = length + #key
                    length = length + #_tostring(val)
                end
            end
            
            return length
        end,
        get_args_names = function(args)
            args = args[1]
            
            if not args then
                return nil
            end
            
            return twaf_func:table_keys(args)
        end,
        get_cookies_names = function(cookies)
            cookies = cookies[1]
            
            if not cookies then
                return nil
            end
            
            return twaf_func:table_keys(cookies)
        end
    }
    
    return func[op]({...})
end

local function _get_boundary(ct)

    if not ct then
        return nil
    end
    
    if _type(ct) == "table" then
        ct = ct[1]
    end
    
    local m = string_match(ct, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    
    return string_match(ct, ";%s*boundary=([^\",;]+)")
end

local function __get_real_ip(req)
    local XFF = _get_vars(req, "XFF")
    
    if not XFF then
        return _get_vars(req, "REMOTE_ADDR")
    end
    
    local tb = twaf_func:string_ssplit(XFF, ",")
    if _type(tb) ~= "table" then
        return _get_vars(req, "REMOTE_ADDR")
    end
    
    return tb[1]
end

-- nil string table arr
local function _parse_request_body()

    local _twaf =  twaf
    local  ctx  = _twaf:ctx()
    local  req  =  ctx.req
    
    local gcf = _twaf.get_config_param(_twaf, "twaf_global")
    
    local content_type_header = _twaf:get_vars("REQUEST_HEADERS", req)["Content-Type"]
    if _type(content_type_header) == "table" then
        ngx_log(ngx[gcf.debug_log_level], "Request contained multiple content-type headers, bailing!")
        ngx_exit(400)
    end
    
    if (not content_type_header) then
        ngx_log(ngx[gcf.debug_log_level], "Request has no content type, ignoring the body")
        return nil
	end
    
    if ngx_re_find(content_type_header, [=[^multipart/form-data; boundary=]=], "oij") then
        if (not gcf.process_multipart_body) then
            return
        end
        
        --ngx_req_read_body()
        
        if ngx_req_get_body_file() then
            ngx_log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
            return
        end
        
        local body = ngx_req_get_body_data()
        if not body then
            return
        end
        
        ctx.req_body = body
        
        local boundary = _get_boundary(content_type_header)
        if not boundary then
            return
        end
        
        local t            =  {}
        local body_table   =  twaf_func:string_split_re(body, "--"..boundary)
        local first_string =  table_remove(body_table,1)
        local last_string  =  table_remove(body_table)
        
        for _, v in ipairs(body_table) do
        
            local from, to, name, filename = string_find(v, 'Content%-Disposition: form%-data; name="(.+)"; filename="(.-)"\r\n')
            if not from then
                -- other args
                ngx_log(ngx[gcf.debug_log_level], "post other args not file, ignore - ", _tostring(v))
                local from, to, data = string_find(v, ".-\r\n\r\n(.*)")
                if from then
                    table_insert(t, data)
                end
            else
                -- get file info
                local f = ctx.file or {}
                
                local files = req.FILES or {}
                table_insert(files, filename)
                req.FILES = files
                
                local fn = req.FILES_NAMES or {}
                table_insert(fn, name)
                req.FILES_NAMES = fn
                
                local from, to ,ct, data = string_find(v, 'Content%-Type: (.-)\r\n\r\n(.*)')
                if from then
                    f[filename] = {}
                    f[filename]["content-type"] = ct
                    f[filename]["data"] = data
                    table_insert(t, data)
                end
                
                ctx.file = f
            end
        end
        
        return t
        
    elseif ngx_re_find(content_type_header, [=[^application/x-www-form-urlencoded]=], "oij") then
    
        --ngx_req_read_body()
        
        if ngx_req_get_body_file() == nil then
            return ngx_req_get_body_data()
        else
            ngx_log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
            return nil
        end
        
    else
    
        --content type whitelist
        for k, _ in pairs(gcf.allowed_content_types) do
            if ngx_re_find(content_type_header, k, "oij") then
                --ngx_req_read_body()
                
                if not ngx_req_get_body_file() then
                    return ngx_req_get_body_data()
                else
                    ngx_log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
                    return nil
                end
            end
        end
        
        --unknown content type
        if gcf.allow_unknown_content_types then
            ngx_log(ngx[gcf.debug_log_level], "Allowing request with content type " .. _tostring(content_type_header))
            return nil
        else
            ngx_log(ngx[gcf.debug_log_level], _tostring(content_type_header) .. " not a valid content type!")
            ngx_exit(ngx_HTTP_FORBIDDEN)
        end
    end
end

local function _geo_look_up(_twaf, ip_version, addr)

    local geodb = nil
    
    if ip_version == "IPv4" then
        geodb = _twaf.config.geodb_country_ipv4
        if geodb then
            return geodb:query_by_addr(addr)
        end
        
    elseif ip_version == "IPv6" then
        geodb = _twaf.config.geodb_country_ipv6
        if geodb then
            return geodb:query_by_addr_v6(addr)
        end
    end
    
    return {}
end

local function _get_vars(req, var)
    return req[var] or _M.vars[var](req)
end

_M.vars = {
    ARGS_GET = function(req) req.ARGS_GET = ngx_req_get_uri_args(0) return req.ARGS_GET end,
    ARGS_POST = function(req) --[[ngx_req_read_body()]] req.ARGS_POST = ngx_req_get_post_args(0) return req.ARGS_POST end,
    REMOTE_ADDR = function(req) req.REMOTE_ADDR = ngx_var.remote_addr return req.REMOTE_ADDR end,
    EXTEN = function(req) req.EXTEN = ngx_var.exten return req.EXTEN end,
    SCHEME = function(req) req.SCHEME = ngx_var.scheme return req.SCHEME end,
    REMOTE_HOST = function(req) req.REMOTE_HOST = ngx_var.host return req.REMOTE_HOST end,
    HTTP_HOST = function(req) req.HTTP_HOST = ngx_var.http_host return req.HTTP_HOST end,
    REMOTE_PORT = function(req) req.REMOTE_PORT = _tonumber(ngx_var.remote_port) or 0 return req.REMOTE_PORT end,
    REMOTE_USER = function(req) req.REMOTE_USER = ngx_var.remote_user return req.REMOTE_USER end,
    SERVER_ADDR = function(req) req.SERVER_ADDR = ngx_var.server_addr return req.SERVER_ADDR end,
    SERVER_NAME = function(req) req.SERVER_NAME = ngx_var.server_name return req.SERVER_NAME end,
    SERVER_PORT = function(req) req.SERVER_PORT = _tonumber(ngx_var.server_port) or 0 return req.SERVER_PORT end,
  --HTTP_VERSION = function(req) req.HTTP_VERSION = ngx_req_http_version() return req.HTTP_VERSION end,
    REQUEST_METHOD = function(req) req.REQUEST_METHOD = ngx_req_get_method() return req.REQUEST_METHOD end,
    URI = function(req) req.URI = ngx_var.uri return req.URI end,
    QUERY_STRING = function(req) req.QUERY_STRING = ngx_var.query_string return req.QUERY_STRING end,
    REQUEST_URI = function(req) req.REQUEST_URI = ngx_var.request_uri return req.REQUEST_URI end,
    REQUEST_FILENAME = function(req) req.REQUEST_FILENAME = ngx_var.request_filename return req.REQUEST_FILENAME end,
    REQUEST_LINE = function(req) req.REQUEST_LINE = ngx_var.request return req.REQUEST_LINE end,
    REQUEST_LINE_ARGS = function(req) req.REQUEST_LINE_ARGS = ngx_var.args return req.REQUEST_LINE_ARGS end,
    REQUEST_PROTOCOL = function(req) req.REQUEST_PROTOCOL = ngx_var.server_protocol return req.REQUEST_PROTOCOL end,
    UNIQUE_ID = function(req) req.UNIQUE_ID = ngx_var.request_id return req.UNIQUE_ID end,
    REQUEST_TIME = function(req) req.REQUEST_TIME = ngx_var.request_time return req.REQUEST_TIME end,
    BYTES_IN = function(req) req.BYTES_IN = _tonumber(ngx_var.bytes_in) or 0 return req.BYTES_IN end,
    CONNECTION_REQUESTS = function(req) req.CONNECTION_REQUESTS = _tonumber(ngx_var.connection_requests) or 0 return req.CONNECTION_REQUESTS end,
    HTTP_USER_AGENT = function(req) req.HTTP_USER_AGENT = ngx_var.http_user_agent return req.HTTP_USER_AGENT end,
    HTTP_COOKIE = function(req) req.HTTP_COOKIE = ngx_var.http_cookie return req.HTTP_COOKIE end,
    TIME_LOCAL = function(req) req.TIME_LOCAL = ngx_var.time_local return req.TIME_LOCAL end,
    ORIGINAL_DST_ADDR = function(req) req.ORIGINAL_DST_ADDR = ngx_var.original_dst_addr return req.ORIGINAL_DST_ADDR end,
    ORIGINAL_DST_PORT = function(req) req.ORIGINAL_DST_PORT = _tonumber(ngx_var.original_dst_port) or 0 return req.ORIGINAL_DST_PORT end,
    HTTP_REFERER = function(req) req.HTTP_REFERER = ngx_var.http_referer or "-" return req.HTTP_REFERER end,
    GZIP_RATIO = function(req) req.GZIP_RATIO = ngx_var.gzip_ratio or "-" return req.GZIP_RATIO end,
    MSEC = function(req) req.MSEC = _tonumber(ngx_var.msec) or 0.00 return req.MSEC end,
    REQUEST_HEADERS = function(req) req.REQUEST_HEADERS = ngx_req_get_headers(0) return req.REQUEST_HEADERS end,
    REQUEST_COOKIES = function(req) req.REQUEST_COOKIES = twaf_func:get_cookie_table() return req.REQUEST_COOKIES end,
    TIME_EPOCH = function(req) req.TIME_EPOCH = ngx_time() return req.TIME_EPOCH end, -- seconds since 1970, integer
    TIME_NOW = function(req) req.TIME_NOW = ngx_now() return req.TIME_NOW end, -- like TIME_EPOCH, but a float number
    IP_VERSION = function(req) req.IP_VERSION = _ip_version() return req.IP_VERSION end,
    RESPONSE_HEADERS = function(req) return ngx_resp_get_headers(0) end,
    UPSTREAM_CACHE_STATUS = function(req) req.UPSTREAM_CACHE_STATUS = ngx_var.upstream_cache_status return req.UPSTREAM_CACHE_STATUS end,
  --RAW_HEADER = function(req) req.RAW_HEADER = ngx_req_raw_header() return req.RAW_HEADER end,
  --RAW_HEADER_TRUE = function(req) req.RAW_HEADER_TRUE  =  ngx_req_raw_header(true) return req.RAW_HEADER_TRUE end,
    UPSTREAM_STATUS = function(req) req.UPSTREAM_STATUS = _tonumber(ngx_var.upstream_status) or 0 return req.UPSTREAM_STATUS end,
    UPSTREAM_BYTES_SENT = function(req) return _tonumber(ngx_var.upstream_bytes_sent) or 0 end, -- 未缓存此值，防止header_filter前phase缓存此值为0
    UPSTREAM_BYTES_RECEIVED = function(req) return _tonumber(ngx_var.upstream_bytes_received) or 0 end, -- 未缓存此值，防止header_filter前phase缓存此值为0
    HTTP_VERSION = function(req)
        if req.phase_n == 7 or req.phase_n == 9 or req.phase_n == 10 or req.phase_n == 11 then -- rewrite access content header_filter
            req.HTTP_VERSION = ngx_req_http_version()
            return req.HTTP_VERSION
        end
    end,
    RAW_HEADER = function(req)
        if _get_vars(req, "HTTP_VERSION") == 2 then -- don't support HTTP 2.0
            req.RAW_HEADER = "-"
            return req.RAW_HEADER
        end

        if req.phase_n == 7 or req.phase_n == 9 or req.phase_n == 10 or req.phase_n == 11 then -- rewrite access content header_filter
            req.RAW_HEADER = ngx_req_raw_header()
            return req.RAW_HEADER
        end
    end,
    RAW_HEADER_TRUE = function(req)
        if _get_vars(req, "HTTP_VERSION") == 2 then -- don't support HTTP 2.0
            req.RAW_HEADER_TRUE = "-"
            return req.RAW_HEADER_TRUE
        end

        if req.phase_n == 7 or req.phase_n == 9 or req.phase_n == 10 or req.phase_n == 11 then -- rewrite access content header_filter
            req.RAW_HEADER_TRUE = ngx_req_raw_header(true) 
            return req.RAW_HEADER_TRUE
        end
    end,
    
    RESPONSE_STATUS = function() return ngx.status end,
    BYTES_SENT = function() return _tonumber(ngx_var.bytes_sent) or 0 end,
    DURATION = function() return (ngx_re_match(_tostring((ngx_now() - ngx_req_start_time()) * 1000000), "([0-9]+)", "oij"))[1] end,
    
    -- 下面三项均在ctx()中初始化，因此可删除
    -- POLICYID = function(req) req.POLICYID = twaf.config.global_conf_uuid return req.POLICYID end,
    -- MATCHED_VARS = function(req) req.MATCHED_VARS = {} return req.MATCHED_VARS end,
    -- MATCHED_VAR_NAMES = function(req) req.MATCHED_VAR_NAMES = {} return req.MATCHED_VAR_NAMES end,
    
    FILES = function(req)
        _get_vars(req, "REQUEST_BODY")
        return req.FILES
    end,
    FILES_NAMES = function(req)
        _get_vars(req, "REQUEST_BODY")
        return req.FILES_NAMES
    end,
    REAL_IP = function(req)
        req.REAL_IP = __get_real_ip(req)
        return req.REAL_IP
    end,
    REQUEST_BODY = function(req)
        if req.phase_n == 7 or req.phase_n == 9 or req.phase_n == 10 then -- rewrite access content
            req.REQUEST_BODY = _parse_request_body()
            return req.REQUEST_BODY
        end
    end,
    ARGS = function(req) 
        req.ARGS = _vars_op("args", _get_vars(req, "ARGS_GET"), _get_vars(req, "ARGS_POST"))
        return req.ARGS 
    end,
    ARGS_COMBINED_SIZE = function(req) 
        req.ARGS_COMBINED_SIZE = _vars_op("args_combined_size", _get_vars(req, "ARGS"))
        return req.ARGS_COMBINED_SIZE 
    end,
    ARGS_NAMES = function(req) 
        req.ARGS_NAMES = twaf_func:table_keys(_get_vars(req, "ARGS"))
        return req.ARGS_NAMES 
    end,
    ARGS_GET_NAMES = function(req) 
        req.ARGS_GET_NAMES = twaf_func:table_keys(_get_vars(req, "ARGS_GET"))
        return req.ARGS_GET_NAMES 
    end,
    ARGS_POST_NAMES = function(req) 
        req.ARGS_POST_NAMES = twaf_func:table_keys(_get_vars(req, "ARGS_POST"))
        return req.ARGS_POST_NAMES 
    end,
    REQUEST_HEADERS_NAMES = function(req) 
        req.REQUEST_HEADERS_NAMES = twaf_func:table_keys(_get_vars(req, "REQUEST_HEADERS")) 
        return req.REQUEST_HEADERS_NAMES 
    end,
    XFF = function(req) 
        req.XFF = _get_vars(req, "REQUEST_HEADERS")["X-Forwarded-For"]
        return req.XFF
    end,
    REQUEST_BASENAME = function(req) 
        req.REQUEST_BASENAME = _basename(_get_vars(req, "URI"))
        return req.REQUEST_BASENAME
    end,
    REQUEST_COOKIES_NAMES = function(req) 
        req.REQUEST_COOKIES_NAMES = twaf_func:table_keys(_get_vars(req, "REQUEST_COOKIES"))
        return req.REQUEST_COOKIES_NAMES
    end,
    TIME = function(req) -- hour:minute:second  --PS:the system time zone
        req.TIME = _os_date("%X", _get_vars(req, "TIME_EPOCH"))
        return req.TIME
    end,
    TIME_DAY = function(req) -- 1-31
        req.TIME_DAY = _os_date("%d", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_DAY
    end,
    TIME_HOUR = function(req) -- 0-23, %I 12-hour clock
        req.TIME_HOUR = _os_date("%H", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_HOUR
    end,
    TIME_MIN = function(req) -- 0-59
        req.TIME_MIN = _os_date("%M", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_MIN
    end,
    TIME_MON = function(req) -- 1-12
        req.TIME_MON = _os_date("%m", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_MON
    end,
    TIME_SEC = function(req) -- 0-59
        req.TIME_SEC = _os_date("%S", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_SEC
    end,
    TIME_WDAY = function(req) -- 0-6 Sunday-Saturday
        req.TIME_WDAY = _os_date("%w", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_WDAY
    end,
    TIME_YEAR = function(req) -- four-digit ex: 1997
        req.TIME_YEAR = _os_date("%Y", _get_vars(req, "TIME_EPOCH"))
        return req.TIME_YEAR
    end,
    URL = function(req)
        req.URL = _get_vars(req, "SCHEME") .. "://" .. 
                  _get_vars(req, "HTTP_HOST") .. _get_vars(req, "URI")
        return req.URL
    end,
    GEO = function(req)
        req.GEO = _geo_look_up(twaf, _get_vars(req, "IP_VERSION"), _get_vars(req, "REMOTE_ADDR"))
        return req.GEO
    end,
    GEO_CODE3 = function(req)
        req.GEO_CODE3 = (_get_vars(req, "GEO") or {})["code3"]
        return req.GEO_CODE3
    end,
    GEO_CODE = function(req)
        req.GEO_CODE = (_get_vars(req, "GEO") or {})["code"]
        return req.GEO_CODE
    end,
    GEO_ID = function(req)
        req.GEO_ID = (_get_vars(req, "GEO") or {})["id"]
        return req.GEO_ID
    end,
    GEO_CONTINENT = function(req)
        req.GEO_CONTINENT = (_get_vars(req, "GEO") or {})["continent"]
        return req.GEO_CONTINENT
    end,
    GEO_NAME = function(req)
        req.GEO_NAME = (_get_vars(req, "GEO") or {})["name"]
        return req.GEO_NAME
    end
}

_M.parse_var = {

    specific = function(_twaf, gcf, var, value)
    
        local _var = {}
        
        if _type(value) == "table" then
            for _, v in pairs(value) do
                ngx_log(ngx[gcf.debug_log_level], "Parse var is getting a specific value -- " .. v)
                table_insert(_var, var[v])
            end
        else
            ngx_log(ngx[gcf.debug_log_level], "Parse var is getting a specific value -- " .. value)
            return var[value]
        end
        
        return _var
    end,
    ignore = function(_twaf, gcf, var, value)
        local _var = twaf_func:copy_table(var)
        
        if _type(value) == "table" then
            for _, v in ipairs(value) do
                 ngx_log(ngx[gcf.debug_log_level], "Parse var is ignoring a value -- " .. _tostring(v))
                _var[v] = nil
            end
        else
            ngx_log(ngx[gcf.debug_log_level], "Parse var is ignoring a value -- " .. _tostring(value))
            _var[value] = nil
        end
        
        return _var
    end,
    keys = function(_twaf, gcf, var)
        ngx_log(ngx[gcf.debug_log_level], "Parse var is is getting the keys")
        return twaf_func:table_keys(var)
    end,
    values = function(_twaf, gcf, var)
        ngx_log(ngx[gcf.debug_log_level], "Parse var is getting the values")
        return twaf_func:table_values(var)
    end,
    all = function(_twaf, gcf, var)
        local _var = {}
        ngx_log(ngx[gcf.debug_log_level], "Parse var is ggetting all keys and values")
        _var = twaf_func:table_keys(var)
        
        for _, v in ipairs(twaf_func:table_values(var)) do
            table_insert(_var, v)
        end
        
        return _var
    end
}

return _M
