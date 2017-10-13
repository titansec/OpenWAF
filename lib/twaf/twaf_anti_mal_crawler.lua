
--Copyright (C) Miracle
--Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
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
    local request  = tctx.request
    local uri      = (request.URI or "-"):lower()
    local uri_len  = #uri
    
    if uri_len == 12 and uri == "/favicon.ico" then
        tctx[modules_name] = nil
        return false
    end
    
    local value
    local mal_flag        =  false
    local timeout         =  cf.timeout
    local delay           =  cf.timer_flush_expired or gcf.timer_flush_expired
  --local ip_bl_path      =  cf.ip_blacklist_path or gcf.ip_blacklist_path
    local request_cookies =  request.REQUEST_COOKIES
    local mal_cookie      =  request_cookies[cf.mal_cookie_name]
    local crawler_cookie  =  request_cookies[cf.crawler_cookie_name]
    local cookie_state    =  twaf_func:state(cf.cookie_state)
    local dict_state      =  twaf_func:state(cf.dict_state)
    local dict_name       =  cf.shared_dict_name or gcf.dict_name
    local dict            =  ngx_shared[dict_name]
    local policy          =  request.POLICYID
    local key             =  twaf_func:key(cf.shared_dict_key)
    
    if type(key) ~= "string" then
        ngx_log(ngx_WARN, modules_name .. "module shared_dict_key can't be table")
        tctx[modules_name] = nil
        return false
    end
    
    key      = modules_name.."_"..policy.."_"..key
    ctx.key  = key
    ctx.dict = dict
    ctx.cf   = cf
    
    twaf_func:dict_flush_expired(_twaf, dict, delay)
    
    repeat
    
    if dict_state and dict:get(key.."_mal") then
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
    if cf.trap_uri == uri and cf.trap_args ~= request.QUERY_STRING then
        value    = uri
        mal_flag = "trap uri"
        break
    end
    
    --check if there is crawler cookie
    if (cookie_state and crawler_cookie) or (dict_state and dict:get(key.."_crawler")) then
        local method = request.REQUEST_METHOD
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
            local mal_cookie_value = twaf_func:set_cookie_value(request, cf.mal_cookie_name)
            local cookie = cf.mal_cookie_name.."="..mal_cookie_value
            twaf_func:set_cookie(cookie)
        end
        
        --[[local ip_bl = _twaf.config.ip_blacklist
        if ip_bl and not ip_bl[request.REMOTE_ADDR] then
            ip_bl[request.REMOTE_ADDR] = 1
            twaf_func:record(ip_bl_path, 1, request.REMOTE_ADDR)
        end]]
        
        request.MATCHED_VAR      = value
        request.MATCHED_VAR_NAME = mal_flag
        table.insert(request.MATCHED_VARS, value)
        table.insert(request.MATCHED_VAR_NAMES, mal_flag)
        
        tctx[modules_name] = nil
        if dict_state then dict:set(key.."_mal", 1, timeout) end
        
        return _log_action(_twaf, cf)
    end
    
    if uri_len == 11 and uri == "/robots.txt"  then
        if cookie_state == true and not crawler_cookie then
            --crc32(time ip agent crawler_cookie_name time)
            local crawler_cookie_value = twaf_func:set_cookie_value(request, cf.crawler_cookie_name)
            local crawler_cookie       = cf.crawler_cookie_name.."="..crawler_cookie_value
            twaf_func:set_cookie(crawler_cookie)
        end
        
        if dict_state then dict:set(key.."_crawler", 1, timeout) end
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
    local request  = tctx.request
    local uri      = (request.URI or "-"):lower()
    local _status  = request.RESPONSE_STATUS
    local headers  = request.RESPONSE_HEADERS
    local uri_len  = #uri
    
    if _status() == 404 and uri_len == 11 and uri == "/robots.txt" then
        ngx_header.content_type = "text/plain"
        ngx.status              = ngx_HTTP_OK
        ctx.no_robots_txt       = true
    end
    
    if _status() ~= ngx_HTTP_OK then
        return true
    end
    
    if uri_len ~= 11 or uri ~= "/robots.txt" then
    
        if twaf_func:state(cf.force_scan_robots_state) == true then
        
            local count = ctx.dict:get(ctx.key.."_force_scan") or 0
            if count >= cf.force_scan_times then
                return
            end
            
            local content_length = tonumber(headers['Content-Length'])
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
            twaf_func:content_length_operation(#append_response, "add")
            return
        end
        
        return true
    end
    
    local robots_footer = "\nDisallow: "..cf.trap_uri.."\n"
    ctx.mal_crawler_robots_footer = robots_footer
    
    if ctx.no_robots_txt == true then
        ngx_header['Content-Length'] = #no_robots_txt + #robots_footer
        headers['Content-Length'] = ngx_header['Content-Length']
    else
        local content_length = ngx_header['Content-Length']
        if content_length then
            ngx_header['Content-Length'] = content_length + #robots_footer
            headers['Content-Length'] = ngx_header['Content-Length']
        end
    end
    
    return ngx.DONE
end

function _M.body_filter(self, _twaf)

    local tctx     = _twaf:ctx()
    local ctx      =  tctx[modules_name]
    local request  =  tctx.request
    local uri      =  (request.URI or "-"):lower()
    local headers  =  request.RESPONSE_HEADERS
    local uri_len  =  #uri
    
    if not ctx then
        return true
    end
    
    if ctx.force_scan_state == true and not ctx.append_response_state then
    
        local new_response
        local from, to = ngx.arg[1]:find("<body.->")
        
        if to ~= nil then
        
            local tmp1                = ngx.arg[1]:sub(1, to)
            local tmp2                = ngx.arg[1]:sub(to + 1)
            new_response              = tmp1..ctx.append_response
            ngx.arg[1]                = new_response..tmp2
            ctx.append_response_state = true
            
        elseif ngx.arg[2] == true then
            
            ctx.append_response_state = true
            ngx.arg[1]                = ngx.arg[1]..ctx.append_response
        end
        
        if ctx.append_response_state then
            local count = ctx.dict:get(ctx.key.."_force_scan") or 0
            ctx.dict:set(ctx.key.."_force_scan", count + 1, ctx.cf.timeout)
        end
        
        return true
    end
    
    if uri_len ~= 11 or uri ~= "/robots.txt" then
        return true
    end
    
    local robots_footer = ctx.mal_crawler_robots_footer
    if robots_footer == nil then
        return true
    end
    
    local content_type = request.RESPONSE_HEADERS['Content-Type']
    local from = content_type:find("text/")
    if from == nil then
        return true
    end
    
    if ngx.arg[2] ~= true then
        if ctx.no_robots_txt == true then
            ngx.arg[1] = nil
        end
        
        return ngx.DONE
    end
    
    if ctx.no_robots_txt == true then
        ngx.arg[1] = no_robots_txt .. robots_footer
    else 
        ngx.arg[1] = ngx.arg[1] .. robots_footer
    end
    
    return ngx.DONE
end

return _M
