
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local ffi                   =  require "ffi"
local cjson                 =  require "cjson.safe"
local twaf_action           =  require "lib.twaf.inc.action"

local ngx_ERR               =  ngx.ERR
local ngx_log               =  ngx.log
local ngx_exit              =  ngx.exit
local ngx_header            =  ngx.header
local timer                 =  ngx.timer.at
local ngx_re_find           =  ngx.re.find
local ngx_var               =  ngx.var
local ngx_get_phase         =  ngx.get_phase
local ngx_socket_tcp        =  ngx.socket.tcp
local ngx_req_get_uri_args  =  ngx.req.get_uri_args

ffi.cdef[[
int js_decode(unsigned char *input, long int input_len);
int css_decode(unsigned char *input, long int input_len);
int decode_base64_ext(char *plain_text, const unsigned char *input, int input_len);
int escape_seq_decode(unsigned char *input, int input_len);
int utf8_to_unicode(char *output, unsigned char *input, long int input_len, unsigned char *changed);
]]

function _M.ffi_copy(value, len)
    local buf = ffi.new(ffi.typeof("char[?]"), len + 1)
    ffi.copy(buf, value)
    return buf
end

function _M.ffi_str(value, len)
    return ffi.string(value, len)
end

function _M.load_lib(cpath, lib_name)

    for k, v in (cpath or ""):gmatch("[^;]+") do
        local lib_path = k:match("(.*/)")
        if lib_path then
            -- "lib_path" could be nil. e.g, the dir path component is "."
            lib_path = lib_path .. (lib_name or "")
            
            local f = io.open(lib_path)
            if f ~= nil then
                f:close()
                return ffi.load(lib_path)
            end
        end
    end
    
    ngx.log(ngx.WARN, "load lib failed - ", lib_name)
end

_M.decode_lib = _M.load_lib(package.cpath, 'decode.so')

function _M.string_trim(self, str)
    return (str:gsub("^%s*(.-)%s*$", "%1"))
end

--Only the first character to take effect in separator.
function _M.string_split(self, str, sep)
    local fields = {}
    local pattern = string.format("([^%s]+)", sep)
    str:gsub(pattern, function(c) fields[#fields + 1] = c end)
    return fields
end

-- If the separator with '-', '*', '+', '?', '%', '.', '[', ']', '^', it should add escape character
function _M.string_ssplit(self, str, sep)

    if not str or not sep then
        return str
    end
    
    local result = {}
    for m in (str..sep):gmatch("(.-)"..sep) do
        table.insert(result, m)
    end
    
    return result
end

-- When processing the request message, it is recommended to use this function
-- no object request pahse，this function does't work
function _M.string_split_re(self, str, sep)

    if not str or not sep then
        return str
    end
    
    local result = {}
    
    repeat 
    
    local len = #str
    if len <= 0 then
        break
    end
    
    local from, to, err = ngx.re.find(str, sep, "oij")
    if not from then
        table.insert(result, str)
        break
    else
        table.insert(result, str:sub(1, from - 1))
        str = str:sub(to + 1)
    end
    
    until false
    
    return result
end

function _M.get_cookie_table(self, text_cookie)

    local text_cookie = ngx_var.http_cookie
    if not text_cookie then
        return {}
    end
    
    local cookie_table = {}
    local cookie_string = _M:string_split(text_cookie, ";")
    for _, value in ipairs(cookie_string) do
        value = _M:string_trim(value)
        local result = _M:string_split(value, "=")
        if result[1] then
            cookie_table[result[1]] = result[2]
        end
    end
    
    return cookie_table
end

function _M.get_cookie(self, _twaf, key)
    local cookie = ngx_var.http_cookie
    if cookie == nil then
        return nil, "no any cookie found in the current request"
    end
    
    local cookie_table = _twaf:ctx().cookie_table
    
    if cookie_table == nil then
        cookie_table  = _M:get_cookie_table(cookie)
        _twaf:ctx().cookie_table = cookie_table
    end
    
    return cookie_table[key]
end

local function _bake_cookie(cookie)
    if not cookie.name or not cookie.value then
        return nil, 'missing cookie field "name" or "value"'
    end
    
    if cookie["max-age"] then
        cookie.max_age = cookie["max-age"]
    end
    local str = cookie.name .. "=" .. cookie.value
        .. (cookie.expires and "; Expires=" .. cookie.expires or "")
        .. (cookie.max_age and "; Max-Age=" .. cookie.max_age or "")
        .. (cookie.domain and "; Domain=" .. cookie.domain or "")
        .. (cookie.path and "; Path=" .. cookie.path or "")
        .. (cookie.secure and "; Secure" or "")
        .. (cookie.httponly and "; HttpOnly" or "")
        .. (cookie.extension and "; " .. cookie.extension or "")
    return str
end

function _M.set_cookie(self, cookie)
    local cookie_str, err
    
    if type(cookie) == "table" then
        cookie_str, err = _bake_cookie(cookie)
    else
        cookie_str = cookie
    end
    
    if cookie_str == nil then
        ngx_log(ngx_ERR, err)
        return
    end
    
    local Set_Cookie = ngx_header['Set-Cookie']
    local set_cookie_type = type(Set_Cookie)
    local t = {}
    
    if set_cookie_type == "string" then
        -- only one cookie has been setted
        if Set_Cookie ~= cookie_str then
            t[1] = Set_Cookie
            t[2] = cookie_str
            ngx_header['Set-Cookie'] = t
        end
    elseif set_cookie_type == "table" then
        -- more than one cookies has been setted
        local size = #Set_Cookie
        
        -- we can not set cookie like ngx.header['Set-Cookie'][3] = val
        -- so create a new table, copy all the values, and then set it back
        for i=1, size do
            t[i] = ngx_header['Set-Cookie'][i]
            if t[i] == cookie_str then
                -- new cookie is duplicated
                return true
            end
        end
        t[size + 1] = cookie_str
        ngx_header['Set-Cookie'] = t
    else
        -- no cookie has been setted
        ngx_header['Set-Cookie'] = cookie_str
    end
end

--time ip agent key time
function _M.set_cookie_value(self, request, key)
    
    if type(key) ~= "string" then
        ngx.log(ngx.WARN, "the cookie key not string in set_cookie_value")
        return ""
    end
    
    local time  = request.TIME_EPOCH      or ngx.time()
    local addr  = request.REMOTE_ADDR     or ngx.var.remote_addr
    local agent = request.http_user_agent or ngx.var.http_user_agent or ""
    
    local crc32_buf =  time..addr..agent..key..time
    local crc32     =  ngx.crc32_long(crc32_buf)
    
    return time..":"..crc32.."; path=/"
end

function _M.check_cookie_value(self, cookie, request, key, timeout)

    if not cookie or type(key) ~= "string" then
        ngx.log(ngx.WARN, "not cookie or key not a string in check_cookie_value")
        return false
    end
    
    local from = cookie:find(":")
    if not from or from == 1 or from == #cookie then
        return false
    end
    
    local time      = tonumber(cookie:sub(1, from - 1)) or 0
    local crc       = tonumber(cookie:sub(from + 1)) or 0
    local now       = request.TIME_EPOCH      or ngx.time()
    local addr      = request.REMOTE_ADDR     or ngx.var.remote_addr
    local agent     = request.http_user_agent or ngx.var.http_user_agent or ""
    local crc32_buf = time..addr..agent..key..time
    local crc32     = ngx.crc32_long(crc32_buf)
    
    if crc == crc32 then
        if timeout and (now - time) > timeout then
            return ngx.AGAIN
        end
        
        return true
    end
    
    return false
end

function _M.flush_expired(premature, _twaf, dict, delay)

    dict:flush_expired()
    
    if not dict:get("add_timer") then
        return nil, "twaf_func:flush_expired - don't have key \"add_timer\""
    end
    
    local ok, err = timer(delay, _M.flush_expired, _twaf, dict, delay)
    if not ok then
        dict:set("add_timer", nil)
    end
    
    return ok, err
end

function _M.dict_flush_expired(self, _twaf, dict, delay)
    local add_timer = dict:get("add_timer")
    if not add_timer then
        dict:add("add_timer", 1)
        local ok, err = timer(delay, _M.flush_expired, _twaf, dict, delay)
        if not ok then
            ngx_log(ngx_ERR, "twaf_func:dict_flush_expired - failed to create timer: ", err)
            dict:set("add_timer", nil)
            return
        end
    end
end

function _M.match(self, subject, complex, options)

    if complex == nil then
        return false
    end
    
    local res
    
    if type(complex) == "string" then
        res = ngx.re.find(subject, complex, options)
        if res then
            return true
        end
        
    elseif type(complex) == "table" then
        for _, v in pairs(complex) do
            res = ngx.re.find(subject, v, options)
            if res then
                return true
            end
        end
    end
    
    return false
end

function _M.state(self, state)

    if state == nil then
        return false
    end
    
    -- dynamic state
    if type(state) == "string" then
        state = state:sub(2)
        local ds_state = ngx_var[state]
        
        if ds_state == "1" then
            return true
        elseif ds_state == "0" then
            return false
        end
        
        return false
    end
    
    if  type(state) == "boolean" then
        return state
    end
    
    return false
end

function _M.get_variable(self, name)
    return ngx_var[name] or "-"
end

function _M.key(self, key_var)
    local key
    
    if type(key_var) == "string" then
        key = self:get_variable(key_var)
        
    elseif type(key_var) == "table" then
    
        if type(key_var[1]) == "string" then
            key = self:get_variable(key_var[1])
            for i = 2, #key_var do
                key = key .. self:get_variable(key_var[i])
            end
            
        elseif type(key_var[1]) == "table" then
            for _, key_m in ipairs(key_var) do
                local key_n = self:get_variable(key_m[1])
                for i = 2, #key_m do
                    key_n = key_n .. self:get_variable(key_m[i])
                end
                
                key[#key+1] = key_n
            end
        end
    end
    
    return key
end

function _M.get_dict_info(self, dict, key)
    return dict:get(key) or 0
end

function _M.content_length_operation(self, num, operator)

    local phase = ngx_get_phase()
    if phase ~= "header_filter" then
        return nil
    end
    
    local content_length = ngx_header['Content-Length']
    if content_length ~= nil then
        if operator == "add" then
            ngx_header['Content-Length'] = content_length + num
        elseif operator == "sub" then
            ngx_header['Content-Length'] = content_length - num
        end
    end
    
    return nil 
end

function _M.tcp_connect(self, host, port, timeout)

    local sock, err = ngx_socket_tcp()
    if not sock then
        ngx_log(ngx_ERR, err)
        return nil
    end
    
    if timeout then
        sock:settimeout(timeout)
    end
    
    local ok, err = sock:connect(host, port)
    if not ok then
        ngx_log(ngx_ERR, err)
        return nil
    end
    
    return sock
    
end

function _M.random_id(self, max_len)
    local s0 = "1234567890"
    local s1 = "abcdefghijklmnopqrstuvwxyz"
    local s2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    local seed = tostring(os.time())..tostring(ngx.var.stat_requests)
    
    math.randomseed(tonumber(seed))
    
    local srt = ""
    local str = s0 .. s1 .. s2
    for i = 1, max_len, 1 do
        local index = math.random(1, #str)
        srt = srt .. str:sub(index, index)
    end
    
    return srt
end

function _M.copy_table(self, st)
    local new_tab = {}
    for k, v in pairs(st or {}) do
        if k == "lua" then
            new_tab[k] = tostring(v)
        else
            if type(v) ~= "table" then
                new_tab[k] = v
            else
                new_tab[k] = _M:copy_table(v)
            end
        end
    end
    
    return new_tab
end

function _M.copy_value(self, val)
    if type(val) == "table" then
        return _M:copy_table(val)
    end
    
    return val
end

function _M.table_has_value(self, tb, value)
    if type(tb) ~= "table" or type(value) == "table" then
        --logger
        return false
    end
    
    for i, v in pairs(tb) do
        if type(v) == "table" then
            return _M:table_has_value(v, value)
        else
            if type(v) == type(value) and v == value then
                return true, i
            else
                return false
            end
        end
    end
    
    return false
end

function _M.table_keys(self, tb)
    if type(tb) ~= "table" then
        ngx.log(ngx.WARN, type(tb) .. " was given to table_keys")
        return tb
    end
    
    local t = {}
    
    for key, _ in pairs(tb) do
        table.insert(t, key)
    end
    
    return t
end

function _M.table_values(self, tb)
    if type(tb) ~= "table" then
        ngx.log(ngx.WARN, type(tb) .. " was given to table_values")
        return tb
    end
    
    local t = {}
    
    for _, value in pairs(tb) do
        if type(value) == "table" then
            local tab = _M:table_values(value)
            for _, v in pairs(tab) do
                table.insert(t, v)
            end
        else
            table.insert(t, value)
        end
    end
    
    return t
end

function _M.multi_table_values(self, ...)
    
    local t = {}
    
    for _, tb in ipairs({...}) do
        local t1 = _M:table_values(tb)
        for _, v in ipairs(t1) do
            table.insert(t, v)
        end
    end
    
    return t
end

function _M.check_rules(self, conf, rule)

    local log = {}

    -- id 
    if type(rule.id) ~= "string" then
        table.insert(log, "ID("..tostring(rule.id).."): string expected, got "..type(rule.id))
        rule.id = tostring(rule.id)
    end
    
    if conf.rules_id[rule.id] then
        table.insert(log, "ID: "..rule.id.." is duplicate")
    end
    
    -- phase
    local phase_arr = {access = 1, header_filter = 1, body_filter = 1}
    local p_func = function(phase)
        local t = type(phase)
        
        if t == "string" then
            if not phase_arr[phase] then
                table.insert(log, "phase: 'access', 'header_filter' or "..
                                  "'body_filter' expected, got "..
                                  phase.." in rule ID: "..rule.id)
            end
        else
            table.insert(log, "phase: 'string' or 'table' expected, got "..
                              t.." in rule ID: "..rule.id)
        end
    end
    
    if type(rule.phase) ~= "table" then
        p_func(rule.phase)
    else
        for _, v in ipairs(rule.phase) do
            p_func(v)
        end
    end
    
    if #log > 0 then
        ngx.log(ngx.WARN, cjson.encode(log))
        return false, log
    end
    
    return true
end

local function sanitise_request_line(ctx, request)

    local s
    
    local func = function(m)
        local str = ""
        for i = 1, #m - 1 do
            str = str.."*"
        end
                    
        str = s.."="..str..m:sub(-1, -1)
        return str
    end
    
    local r_line = request.REQUEST_LINE
    
    if r_line and ctx.sanitise_uri_args then
        for _, arg in pairs(ctx.sanitise_uri_args) do
            s = arg
            r_line = string.gsub(r_line, arg.."=(.-[& ])", func)
        end
    end
    
    ctx.sanitise_uri_args = nil
    return r_line or ""
end

local function table_value_to_string(tb)
    if type(tb) ~= "table" then return tb end
    
    for k, v in pairs(tb) do
        if type(v) == "table" then
            tb[k] = table_value_to_string(v)
        elseif type(v) =="function" then
            tb[k] = string.dump(v)
        elseif type(v) == "userdata" then
            tb[k] = 1
        end
    end
    
    return tb
end

function _M.table_to_string(self, tb)
    if type(tb) ~= "table" then return tb end
    
    local tbl = _M:copy_table(tb)
    
    local t = table_value_to_string(tbl)
    
    return cjson.encode(t)
end

function _M.syn_config_process(self, _twaf, worker_config)

    if type(worker_config) ~= "table" then
        return nil
    end
    
    local phase = {"access", "header_filter", "body_filter"}
    
    -- system rules
    if worker_config.rules then
        for phase, rules in pairs(worker_config.rules) do
            for _, rule in ipairs(rules) do
                if not rule.match then
                    for _, p in ipairs(phase) do
                        if rule[p] then
                            rule[p] = load(rule[p])
                        end
                    end
                end
            end
        end
    end
        
    -- user defined rules
    if worker_config.twaf_policy and worker_config.twaf_policy.policy_uuids then
        for uuid, _ in pairs(worker_config.twaf_policy.policy_uuids) do
            local policy = worker_config.twaf_policy[uuid]
            if policy and policy.twaf_secrules then
                local rules = policy.twaf_secrules.user_defined_rules
                for _, rule in ipairs(rules or {}) do
                    if not rule.match then
                        for _, p in ipairs(phase) do
                            if rule[p] then
                                rule[p] = load(rule[p])
                            end
                        end
                    end
                end
            end
        end
    end
        
    for k, v in pairs(worker_config) do
        if type(_twaf.config[k]) == "userdata" then
            worker_config[k] = _twaf.config[k]
        end
    end
    
    return worker_config
end

function _M.syn_config(self, _twaf)
    local gcf   = _twaf:get_config_param("twaf_global")
    local dict  =  ngx.shared[gcf.dict_name]
    local wid   =  ngx.worker.id()
    local wpid  =  ngx.worker.pid()
    
    local res = dict:get("worker_process_"..wid)
    
    if res and res ~= true and res ~= wpid then
        res = true
    end
    
    if res == true then
        ngx.log(ngx.ERR, "config synchronization ing..")
        local worker_config = dict:get("worker_config")
        worker_config = cjson.decode(worker_config)
        
        _twaf.config = _M:syn_config_process(_twaf, worker_config) or _twaf.config
        
        dict:set("worker_process_"..wid, wpid)
    end
end

function _M.parse_dynamic_value(self, key, request)
	local lookup = function(m)
		local val      = request[m[1]:upper()]
		local specific = m[2]
        
		if (not val) then
			--logger.fatal_fail("Bad dynamic parse, no collection key " .. m[1])
            return "-"
		end
        
		if (type(val) == "table") then
			if (specific) then
				return tostring(val[specific])
			else
                return _M:table_to_string(val)
				--return tostring(m[1])
			end
		elseif (type(val) == "function") then
			return tostring(val(twaf))
		else
			return tostring(val)
		end
	end
    
	-- grab something that looks like
	-- %{VAL} or %{VAL.foo}
	-- and find it in the lookup table
	local str = ngx.re.gsub(key, [[%{([^\.]+?)(?:\.([^}]+))?}]], lookup, "oij")
    
	--logger.log(_twaf, "Parsed dynamic value is " .. str)
    
	if (ngx.re.find(str, [=[^\d+$]=], "oij")) then
		return tonumber(str)
	else
		return str
	end
end

function _M.conf_log(self, _twaf, request, ctx)

    local log =  {}
    local lcf = _twaf:get_config_param("twaf_log") or {}
    local sef =  lcf.safe_event_format
    
    if not sef then
        return false
    end
    
    for _, v in pairs(sef.ctx or {}) do
        log[v] = _M:table_to_string(ctx[v]) or "-"
    end
    
    for _, v in pairs(sef.vars or {}) do
        local value = request[v:upper()]
        if type(value) == "function" then
            value = _M:table_to_string(value())
        else
            value = _M:table_to_string(value)
        end
        
        log[v] = value or "-"
    end
    
    return log
end

function _M.rule_category(self, _twaf, rule_name)
    for k, v in pairs(_twaf.config.category_map or {}) do
        if ngx.re.find(rule_name, v.rule_name) then
            return k
        end
    end
    
    return "UNKNOWN"
end

function _M.rule_log(self, _twaf, info)

    local ctx     = _twaf:ctx()
    local request =  ctx.request
    info.category = _M:rule_category(_twaf, info.rule_name)
    
    -- reqstat
    ctx.events.stat[info.category] = 1
    
    -- attack response
    if info.action ~= "PASS" and info.action ~= "ALLOW" and info.action ~= "CHAIN" then
	    ngx_var.twaf_attack_info = ngx_var.twaf_attack_info .. info.rule_name .. ";"
	end
    
    -- log
    if info.log_state == true then
        ctx.events.log[info.rule_name] = _M:conf_log(_twaf, ctx.request, info)
    end
    
    request.MATCHED_VARS      = {}
    request.MATCHED_VAR_NAMES = {}
    
    -- action
    return twaf_action:do_action(_twaf, info.action, info.action_meta)
end

return _M
