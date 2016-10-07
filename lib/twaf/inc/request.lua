
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

local twaf_func = require "lib.twaf.inc.twaf_func"
local redis_m   = require "resty.redis"
local iputils   = require "resty.iputils"

local function _ip_version(self)
    local addr_len = #(ngx.var.binary_remote_addr or "-")
    
    if addr_len == 4 then
        return "IPv4"
    elseif addr_len == 16 then
        return "IPv6"
    else
        ngx.log(ngx.ERR, "expected 4 or 16, but got binary_remote_addr length "..addr_len)
        return "-"
    end
end

local function _basename(uri)
	local m = ngx.re.match(uri, [=[(/[^/]*+)+]=], "oij")
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
            
            if ngx.re.find(content_type, [=[^application/x-www-form-urlencoded]=], "oij") then
                ngx.req.read_body()
                
                if ngx.req.get_body_file() == nil then
                    return ngx.req.get_post_args(0)
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
            
            --TODO:若k重复如何处理？
            --建议：若重复，则组成数组
            return t
        end,
        args_combined_size = function(args)
            local length = 0
            args = args[1]
            
            for key, val in pairs(args) do
                if type(val) == "table" then
                    local t = twaf_func:table_values(val)
                    for _, v in pairs(t) do
                        length = length + #key
                        length = length + #tostring(v)
                    end
                else
                    length = length + #key
                    length = length + #tostring(val)
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
    
    if type(ct) == "table" then
        ct = ct[1]
    end
    
    local m = ct:match(";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    
    return ct:match(";%s*boundary=([^\",;]+)")
end

-- nil string table arr
local function _parse_request_body(_twaf, request, ctx, request_headers)

    local gcf = _twaf.get_config_param(_twaf, "twaf_global")
    
    local content_type_header = request_headers["Content-Type"]
    if type(content_type_header) == "table" then
        ngx.log(ngx[gcf.debug_log_level], "Request contained multiple content-type headers, bailing!")
		ngx.exit(400)
	end
    
    if (not content_type_header) then
        ngx.log(ngx[gcf.debug_log_level], "Request has no content type, ignoring the body")
		return nil
	end
    
    if ngx.re.find(content_type_header, [=[^multipart/form-data; boundary=]=], "oij") then
		if (not gcf.process_multipart_body) then
			return
		end
        
        ngx.req.read_body()
        
		if ngx.req.get_body_file() then
            ngx.log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
			return
		end
        
        local body = ngx.req.get_body_data()
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
        local first_string =  table.remove(body_table,1)
        local last_string  =  table.remove(body_table)
        
        for _, v in ipairs(body_table) do
            
            local from, to, name, filename = v:find('Content%-Disposition: form%-data; name="(.+)"; filename="(.-)"\r\n')
            if not from then
                -- other args
                ngx.log(ngx[gcf.debug_log_level], "post other args not file, ignore - ", tostring(v))
                local from, to, data = v:find(".-\r\n\r\n(.*)")
                if from then
                    table.insert(t, data)
                end
            else
                -- get file info
                local f = ctx.file or {}
                
                local files = request.FILES or {}
                table.insert(files, filename)
                request.FILES = files
                
                local from, to, name = filename:find("(.+)%.")
                if from then
                    local fn = request.FILES_NAMES or {}
                    table.insert(fn, name)
                    request.FILES_NAMES = fn
                end
                
                local from, to ,ct, data = v:find('Content%-Type: (.-)\r\n\r\n(.*)')
                if from then
                    f[filename] = {}
                    f[filename]["content-type"] = ct
                    f[filename]["data"] = data
                    table.insert(t, data)
                end
                
                ctx.file = f
            end
        end
        
        return t
        
	elseif ngx.re.find(content_type_header, [=[^application/x-www-form-urlencoded]=], "oij") then
    
		ngx.req.read_body()

		if ngx.req.get_body_file() == nil then
            return ngx.req.get_body_data()
		else
            ngx.log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
			return nil
		end
    elseif gcf.allowed_content_types[content_type_header] then
		--white list
		ngx.req.read_body()

		if not ngx.req.get_body_file() then
			return ngx.req.get_body_data()
		else
            ngx.log(ngx[gcf.debug_log_level], "Request body size larger than client_body_buffer_size, ignoring request body")
			return nil
		end
	else
		if gcf.allow_unknown_content_types then
            ngx.log(ngx[gcf.debug_log_level], "Allowing request with content type " .. tostring(content_type_header))
			return nil
		else
            ngx.log(ngx[gcf.debug_log_level], tostring(content_type_header) .. " not a valid content type!")
			ngx.exit(ngx.HTTP_FORBIDDEN)
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

_M.request = {
    access = function(_twaf, request, ctx)
    
        if ctx.nodup then return end
        
        local cf                             = _twaf:get_config_param("twaf_global")
        local request_headers                =  ngx.req.get_headers(0)
        local request_uri_args               =  ngx.req.get_uri_args(0)
        local request_post_args              = _vars_op("get_post_args", request_headers)
        local request_method                 =  ngx.req.get_method()
        local args                           = _vars_op("args", request_uri_args, request_post_args)
        local request_body                   = _parse_request_body(_twaf, request, ctx, request_headers)
        local request_basename               = _basename(ngx.var.uri)
        local request_cookies                =  twaf_func:get_cookie_table()
        local unique_id                      =  twaf_func:random_id(cf.unique_id_len)
        
        ctx.TX      = {}
        ctx.storage = {}
        ctx.nodup   = 1
        
        request.ARGS                         =  args
        request.ARGS_COMBINED_SIZE           = _vars_op("args_combined_size", args)
        request.ARGS_GET                     =  request_uri_args
        request.ARGS_GET_NAMES               = _vars_op("get_args_names", request_uri_args)
        request.ARGS_NAMES                   = _vars_op("get_args_names", args)
        request.ARGS_POST                    =  request_post_args
        request.ARGS_POST_NAMES              = _vars_op("get_args_names", request_post_args)
        request.DURATION                     =  function() return (ngx.re.match(tostring((ngx.now() - ngx.req.start_time()) * 1000000), "([0-9]+)", "oij"))[1] end
        
        request.SESSION                      =  require "resty.session".start()
        request.SESSION_DATA                 =  request.SESSION.data
        
        request.REMOTE_ADDR                  =  ngx.var.remote_addr
        request.SCHEME                       =  ngx.var.scheme
        request.REMOTE_HOST                  =  ngx.var.host
        request.HTTP_HOST                    =  ngx.var.http_host
        request.REMOTE_PORT                  =  tonumber(ngx.var.remote_port) or 0
        request.REMOTE_USER                  =  ngx.var.remote_user
        request.SERVER_ADDR                  =  ngx.var.server_addr
        request.SERVER_NAME                  =  ngx.var.server_name
        request.SERVER_PORT                  =  tonumber(ngx.var.server_port) or 0
        request.HTTP_VERSION                 =  ngx.req.http_version()
        request.REQUEST_METHOD               =  request_method
        request.URI                          =  ngx.var.uri
        request.QUERY_STRING                 =  ngx.var.query_string
        request.REQUEST_URI                  =  ngx.var.request_uri
        request.REQUEST_BASENAME             =  request_basename
        request.REQUEST_FILENAME             =  ngx.var.request_filename
        request.REQUEST_HEADERS              =  request_headers
        request.REQUEST_HEADERS_NAMES        =  twaf_func:table_keys(request_headers)
        request.REQUEST_BODY                 =  request_body
        request.REQUEST_COOKIES              =  request_cookies
        request.REQUEST_COOKIES_NAMES        = _vars_op("get_cookies_names", request_cookies)
        request.REQUEST_LINE                 =  ngx.var.request
        request.REQUEST_PROTOCOL             =  ngx.var.server_protocol
        request.UNIQUE_ID                    =  unique_id
        request.TX                           =  ctx.TX
        request.TIME_EPOCH                   =  ngx.time()                         -- seconds since 1970, integer
        request.TIME                         =  os.date("%X", request.TIME_EPOCH)  -- hour:minute:second  --PS:当心系统时区
        request.TIME_DAY                     =  os.date("%d", request.TIME_EPOCH)  -- 1–31
        request.TIME_HOUR                    =  os.date("%H", request.TIME_EPOCH)  -- 0-23, %I 12-hour clock
        request.TIME_MIN                     =  os.date("%M", request.TIME_EPOCH)  -- 0–59
        request.TIME_MON                     =  os.date("%m", request.TIME_EPOCH)  -- 1-12
        request.TIME_SEC                     =  os.date("%S", request.TIME_EPOCH)  -- 0–59
        request.TIME_WDAY                    =  os.date("%w", request.TIME_EPOCH)  -- 0-6 Sunday-Saturday
        request.TIME_YEAR                    =  os.date("%Y", request.TIME_EPOCH)  -- four-digit ex: 1997
        request.TIME_NOW                     =  ngx.now()                          -- like TIME_EPOCH, but a float number
        request.BYTES_IN                     =  tonumber(ngx.var.bytes_in) or 0
        request.CONNECTION_REQUESTS          =  tonumber(ngx.var.connection_requests) or 0 -- CONN_REQ
        request.NGX_VAR                      =  ngx.var
        request.MATCHED_VARS                 =  {}
        request.MATCHED_VAR_NAMES            =  {}
        
        request.HTTP_USER_AGENT              =  ngx.var.http_user_agent
        request.RAW_HEADER                   =  ngx.req.raw_header()
        request.RAW_HEADER_TRUE              =  ngx.req.raw_header(true)
        request.TIME_LOCAL                   =  ngx.var.time_local
        request.ORIGINAL_DST_ADDR            =  ngx.var.original_dst_addr
        request.ORIGINAL_DST_PORT            =  tonumber(ngx.var.original_dst_port) or 0
        request.USERID                       =  ctx.user or "-"
        request.POLICYID                     =  ctx.policy_uuid or "-"
        request.HTTP_REFERER                 =  ngx.var.http_referer or "-"
        request.GZIP_RATIO                   =  ngx.var.gzip_ratio or "-"
        request.MSEC                         =  tonumber(ngx.var.msec) or 0.00
        request.URL                          =  (request.SCHEME or "-").."://"..(request.HTTP_HOST or "-")..(request.URI or "-")
        request.IP_VERSION                   = _ip_version()
        
        request.GEO                          = _geo_look_up(_twaf, request.IP_VERSION, request.REMOTE_ADDR)
        request.GEO_CODE3                    =  (request.GEO or {})["code3"]
        request.GEO_CODE                     =  (request.GEO or {})["code"]
        request.GEO_ID                       =  (request.GEO or {})["id"]
        request.GEO_CONTINENT                =  (request.GEO or {})["continent"]
        request.GEO_NAME                     =  (request.GEO or {})["name"]
        
    end,
    header_filter = function(_twaf, request)
        request.RESPONSE_HEADERS             = ngx.resp.get_headers(0)
        request.RESPONSE_STATUS              = function() return ngx.status end
        request.BYTES_SENT                   = function() return tonumber(ngx.var.bytes_sent) or 0 end
    end,
    body_filter = function(_twaf, request, ctx)
        if ctx.buffers == nil then
            ctx.buffers  = {}
        end
        
        local data  = ngx.arg[1]
        local eof   = ngx.arg[2]
        
        if data then
            table.insert(ctx.buffers, data)
        end
        
        if not eof then
            -- Send nothing to the client yet.
            ngx.arg[1] = nil
            
            -- no need to process further at this point
            ctx.short_circuit = true
            return
        else
            ctx.short_circuit = false
            request.RESPONSE_BODY = table.concat(ctx.buffers, '')
            ngx.arg[1] = request.RESPONSE_BODY
        end
    end
}

_M.parse_var = {

    specific = function(_twaf, gcf, var, value)
    
        local _var = {}
        
        if type(value) == "table" then
            for _, v in pairs(value) do
                ngx.log(ngx[gcf.debug_log_level], "Parse var is getting a specific value -- " .. v)
                table.insert(_var, var[v])
            end
        else
            ngx.log(ngx[gcf.debug_log_level], "Parse var is getting a specific value -- " .. value)
            return var[value]
        end
        
        return _var
    end,
    ignore = function(_twaf, gcf, var, value)
        local _var = twaf_func:copy_table(var)
        
        if type(value) == "table" then
            for _, v in ipairs(value) do
                 ngx.log(ngx[gcf.debug_log_level], "Parse var is ignoring a value -- " .. tostring(v))
                _var[v] = nil
            end
        else
            ngx.log(ngx[gcf.debug_log_level], "Parse var is ignoring a value -- " .. tostring(value))
            _var[value] = nil
        end
        
        return _var
    end,
    keys = function(_twaf, gcf, var)
        ngx.log(ngx[gcf.debug_log_level], "Parse var is is getting the keys")
        return twaf_func:table_keys(var)
    end,
    values = function(_twaf, gcf, var)
        ngx.log(ngx[gcf.debug_log_level], "Parse var is getting the values")
        return twaf_func:table_values(var)
    end,
    all = function(_twaf, gcf, var)
        local _var = {}
        ngx.log(ngx[gcf.debug_log_level], "Parse var is ggetting all keys and values")
        _var = twaf_func:table_keys(var)
        
        for _, v in ipairs(twaf_func:table_values(var)) do
            table.insert(_var, v)
        end
        
        return _var
    end
}


return _M
