
--Copyright (C) Miracle
--Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local twaf_func             = require "lib.twaf.inc.twaf_func"

local event_id              = "710001"
local event_severity        = "high"
local modules_name          = "twaf_anti_mal_crawler"
local rule_name             = "auto.crawler.general.mal"
local ngx_HTTP_OK           = ngx.HTTP_OK
local ngx_var               = ngx.var
local ngx_log               = ngx.log
local ngx_WARN              = ngx.WARN
local ngx_ERR               = ngx.ERR
local ngx_shared            = ngx.shared
local ngx_header            = ngx.header
local ngx_timer_at          = ngx.timer.at
local ngx_resp_get_headers  = ngx.resp.get_headers
local _tonumber             = tonumber
local table_insert          = table.insert
local string_format         = string.format

local entry_no_robots_response = 
     '<a href="{{trap_uri}}" style="display:none">robots</a>'
     
local exclude_content_encoding = {
    "gzip", "deflate"
}

local no_robots_txt = "User-agent: *\n"

local function _log_action(_twaf, cf)

    local cctx          =  {}
    
    cctx.id             =  event_id
    cctx.severity       =  event_severity
    cctx.rule_name      =  rule_name
    cctx.action         =  cf.action
    cctx.action_meta    =  cf.action_meta
    cctx.version        = _M._VERSION
    cctx.log_state      =  cf.log_state
    
    return twaf_func:rule_log(_twaf, cctx)
end

function _M.handler(self, _twaf)

    local tctx = _twaf:ctx()
    local gcf  = _twaf:get_config_param("twaf_global")
    local cf   = _twaf:get_config_param(modules_name)
    
    if twaf_func:state(cf.state) == false or tctx.trust == true then
        return false
    end
    
    if not tctx[modules_name] then
        tctx[modules_name] = {}
    end
    
    local ctx      = tctx[modules_name]
    local req      = tctx.req
    local uri      = (_twaf:get_vars("URI", req) or "-"):lower()
    local uri_len  = #uri
    
    if uri_len == 12 and uri == "/favicon.ico" then
        tctx[modules_name] = nil
        return false
    end
    
    local value
    local mal_flag        =  false
    local timeout         =  cf.timeout
    local delay           =  cf.timer_flush_expired or gcf.timer_flush_expired
    local request_cookies = _twaf:get_vars("REQUEST_COOKIES", req)
    local mal_cookie      =  request_cookies[cf.mal_cookie_name]
    local crawler_cookie  =  request_cookies[cf.crawler_cookie_name]
    local cookie_state    =  twaf_func:state(cf.cookie_state)
    local dict_state      =  twaf_func:state(cf.dict_state)
    local dict_name       =  cf.shared_dict_name or gcf.dict_name
    local dict            =  ngx_shared[dict_name]
    local policy          = _twaf:get_vars("POLICYID", req)
    local key             =  twaf_func:key(cf.shared_dict_key)
    
    if type(key) ~= "string" then
        ngx_log(ngx_WARN, string_format("%s module : shared_dict_key can't be table", modules_name))
        tctx[modules_name] = nil
        return false
    end
    
    key      = string_format("%s%s%s", modules_name, policy, key)
    ctx.dict = dict
    ctx.cf   = cf
    ctx.force_scan_key = string_format("%s_force_scan", key)
    
    twaf_func:dict_flush_expired(_twaf, dict, delay)
    
    local mal_key     = string_format("%s_mal", key)
    local crawler_key = string_format("%s_crawler", key)
    
    repeat
    
    if dict_state and dict:get(mal_key) then
        value    = 1
        mal_flag = "mal crawler dict"
        break
    end
    
    --check if there is mal cookie
    if cookie_state and mal_cookie then
        value    = mal_cookie
        mal_flag = "mal crawler cookie"
        break
    end
    
    --check mal trap uri
    if cf.trap_uri == uri and cf.trap_args ~= _twaf:get_vars("QUERY_STRING", req) then
        value    = uri
        mal_flag = "trap uri"
        break
    end
    
    --check if there is crawler cookie
    if (cookie_state and crawler_cookie) or (dict_state and dict:get(crawler_key)) then
        local method = _twaf:get_vars("REQUEST_METHOD", req)
        if method ~= "GET" and method ~= "HEAD" then
            value    = method
            mal_flag = "crawler only GET or HEAD method"
            break
        end
    end
    
    until true
    
    if mal_flag ~= false then
        if cookie_state == true and not mal_cookie then
            --crc32(time ip agent mal_cookie_name time)
            local mal_cookie_value = twaf_func:set_cookie_value(req, cf.mal_cookie_name)
            local cookie = string_format("%s=%s", cf.mal_cookie_name, mal_cookie_value)
            twaf_func:set_cookie(cookie)
        end
        
        twaf_func.matched_var(req, mal_flag, value)
        
        tctx[modules_name] = nil
        if dict_state then dict:set(mal_key, 1, timeout) end
        
        return _log_action(_twaf, cf)
    end
    
    if uri_len == 11 and uri == "/robots.txt"  then
        if cookie_state == true and not crawler_cookie then
            --crc32(time ip agent crawler_cookie_name time)
            local crawler_cookie_value = twaf_func:set_cookie_value(req, cf.crawler_cookie_name)
            local crawler_cookie       = string_format("%s=%s", cf.crawler_cookie_name, crawler_cookie_value)
            twaf_func:set_cookie(crawler_cookie)
        end
        
        if dict_state then dict:set(crawler_key, 1, timeout) end
        return false
    end
    
    return false
end

function _M.header_filter(self, _twaf)
    
    local tctx = _twaf:ctx()
    local ctx  =  tctx[modules_name]
    
    if not ctx then
        return true
    end
    
    local cf       = ctx.cf
    local req      = tctx.req
    local uri      = (_twaf:get_vars("URI", req) or "-"):lower()
    local status   = _twaf:get_vars("RESPONSE_STATUS", req)
    local headers  = _twaf:get_vars("RESPONSE_HEADERS", req)
    local uri_len  = #uri
    
    if status == 404 and uri_len == 11 and uri == "/robots.txt" then
        ngx_header.content_type = "text/plain"
        ngx.status              = ngx_HTTP_OK
        status                  = ngx_HTTP_OK
        ctx.no_robots_txt       = true
    end
    
    if status ~= ngx_HTTP_OK then
        return true
    end
    
    if uri_len ~= 11 or uri ~= "/robots.txt" then
    
        if twaf_func:state(cf.force_scan_robots_state) == true then
        
            local count = ctx.dict:get(ctx.force_scan_key) or 0
            if count >= cf.force_scan_times then
                return
            end
            
            local content_length = _tonumber(headers['Content-Length'])
            if not content_length or content_length < 28 then
                return
            end
            
            local content_type = headers['Content-Type']
            if content_type then
                local from = content_type:find("text/html")
                if from == nil then
                    return
                end
            else
                return
            end
            
            local content_encoding = headers['Content-Encoding']
            if content_encoding then
                for _, v in pairs(exclude_content_encoding) do
                    local from = content_encoding:find(v)
                    if from then
                        return
                    end
                end
            end
            
            local append_response = entry_no_robots_response:gsub("{{trap_uri}}", cf.trap_uri)
            ctx.force_scan_state  = true
            ctx.append_response   = append_response
            ngx_header['Content-Length'] = nil
            return
        end
        
        return true
    end
    
    if not ctx.no_robots_txt then
        local content_type = headers['Content-Type'] or ""
        local from = content_type:find("text/")
        if from == nil then
            return true
        end
    end
    
    local robots_footer = string_format("\nDisallow: %s\n", cf.trap_uri)
    ctx.mal_crawler_robots_footer = robots_footer
    
    if ctx.no_robots_txt == true then
        ngx_header['Content-Length'] = #no_robots_txt + #robots_footer
        return ngx.DONE
    end
    
    local content_length = headers['Content-Length']
    if content_length then
        ngx_header['Content-Length'] = content_length + #robots_footer
    end
    
    return ngx.DONE
end

function _M.body_filter(self, _twaf)

    local tctx     = _twaf:ctx()
    local ctx      =  tctx[modules_name]
    local req      =  tctx.req
    local uri      =  (_twaf:get_vars("URI", req) or "-"):lower()
    local uri_len  =  #uri
    
    if not ctx then return true end
    
    if ctx.force_scan_state == true then
    
        if not ctx.append_response_state then
            if ngx.arg[1]:find("</html>") then ctx.append_response_state = true end
        end
        
        if not ngx.arg[2] or not ctx.append_response_state then return true end
        
        ngx.arg[1] = ngx.arg[1] .. ctx.append_response
        
        local count = ctx.dict:get(ctx.force_scan_key) or 0
        ctx.dict:set(ctx.force_scan_key, count + 1, ctx.cf.timeout)
        
        return true
    end
    
    if uri_len ~= 11 or uri ~= "/robots.txt" then
        return true
    end
    
    local robots_footer = ctx.mal_crawler_robots_footer
    if robots_footer == nil then
        return true
    end
    
    if ngx.arg[2] ~= true then
        if ctx.no_robots_txt == true then
            ngx.arg[1] = nil
        end
        
        return ngx.DONE
    end
    
    if ctx.no_robots_txt == true then
        ngx.arg[1] = no_robots_txt
    end
    
    ngx.arg[1] = ngx.arg[1] .. robots_footer
    
    return ngx.DONE
end

return _M
