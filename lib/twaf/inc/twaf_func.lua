
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.3"
}

local ffi                   =  require "ffi"
local cjson                 =  require "cjson.safe"
local twaf_action           =  require "lib.twaf.inc.action"

local _type                 =  type
local _next                 =  next
local _tonumber             =  tonumber
local _tostring             =  tostring
local io_open               =  io.open
local os_time               =  os.time
local string_format         =  string.format
local string_upper          =  string.upper
local string_lower          =  string.lower
local string_find           =  string.find
local string_sub            =  string.sub
local string_gsub           =  string.gsub
local string_dump           =  string.dump
local string_match          =  string.match
local string_gmatch         =  string.gmatch
local table_insert          =  table.insert
local math_random           =  math.random
local math_randomseed       =  math.randomseed
local timer                 =  ngx.timer.at
local ngx_ERR               =  ngx.ERR
local ngx_WARN              =  ngx.WARN
local ngx_INFO              =  ngx.INFO
local ngx_log               =  ngx.log
local ngx_exit              =  ngx.exit
local ngx_AGAIN             =  ngx.AGAIN
local ngx_header            =  ngx.header
local ngx_re_find           =  ngx.re.find
local ngx_re_gsub           =  ngx.re.gsub
local ngx_crc32_long        =  ngx.crc32_long
local ngx_var               =  ngx.var
local ngx_get_phase         =  ngx.get_phase
local ngx_socket_tcp        =  ngx.socket.tcp
local ngx_req_get_uri_args  =  ngx.req.get_uri_args
local ngx_req_read_body     =  ngx.req.read_body
local ngx_req_get_body_data =  ngx.req.get_body_data
local ngx_shared            =  ngx.shared
local ngx_worker_id         =  ngx.worker.id
local ngx_worker_pid        =  ngx.worker.pid

function _M.ffi_copy(value, len)
    local buf = ffi.new(ffi.typeof("char[?]"), len + 1)
    ffi.copy(buf, value)
    return buf
end

function _M.ffi_str(value, len)
    return ffi.string(value, len)
end

function _M.load_lib(cpath, lib_name)

    for k, v in string_gmatch(cpath or "", "[^;]+") do
        local lib_path = string_match(k, "(.*/)")
        if lib_path then
            -- "lib_path" could be nil. e.g, the dir path component is "."
            lib_path = lib_path .. (lib_name or "")
            
            local f = io_open(lib_path)
            if f ~= nil then
                f:close()
                return ffi.load(lib_path)
            end
        end
    end
    
    ngx_log(ngx_WARN, "load lib failed - ", lib_name)
end

function _M.string_trim(self, str)
    return (string_gsub(str, "^%s*(.-)%s*$", "%1"))
end

--Only the first character to take effect in separator.
function _M.string_split(self, str, sep)
    local fields = {}
    local pattern = string_format("([^%s]+)", sep)
    string_gsub(str, pattern, function(c) fields[#fields + 1] = c end)
    return fields
end

-- If the separator with '-', '*', '+', '?', '%', '.', '[', ']', '^', it should add escape character
function _M.string_ssplit(self, str, sep)

    if not str or not sep then
        return str
    end
    
    local result = {}
    for m in string_gmatch(str..sep, "(.-)"..sep) do
        table_insert(result, m)
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
    
    local from, to, err = ngx_re_find(str, sep, "oij")
    if not from then
        table_insert(result, str)
        break
    else
        table_insert(result, string_sub(str, 1, from - 1))
        str = string_sub(str, to + 1)
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
    
    if _type(cookie) == "table" then
        cookie_str, err = _bake_cookie(cookie)
    else
        cookie_str = cookie
    end
    
    if cookie_str == nil then
        ngx_log(ngx_ERR, err)
        return
    end
    
    local Set_Cookie = ngx_header['Set-Cookie']
    local set_cookie_type = _type(Set_Cookie)
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
        
        -- we can not set cookie like ngx_header['Set-Cookie'][3] = val
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
function _M.set_csrf_value(self, req, key)
    
    if _type(key) ~= "string" then
        ngx_log(ngx_WARN, "the cookie key not string in set_cookie_value")
        return ""
    end
    
    local _time = twaf:get_vars("TIME_EPOCH", req)
    local addr  = twaf:get_vars("REMOTE_ADDR", req)
    local agent = twaf:get_vars("HTTP_USER_AGENT", req) or ""
    
    local crc32_buf =  string_format("%d%s%s%s%d", _time, addr, agent, key, _time)
    local crc32     =  ngx_crc32_long(crc32_buf)
    
    return string_format("%d:%s", _time, crc32)
end

--time ip agent key time
function _M.set_cookie_value(self, req, key, httponly)
    
    if _type(key) ~= "string" then
        ngx_log(ngx_WARN, "the cookie key not string in set_cookie_value")
        return ""
    end
    
    local _time = twaf:get_vars("TIME_EPOCH", req)
    local addr  = twaf:get_vars("REMOTE_ADDR", req)
    local agent = twaf:get_vars("HTTP_USER_AGENT", req) or ""
    
    local crc32_buf =  string_format("%d%s%s%s%d", _time, addr, agent, key, _time)
    local crc32     =  ngx_crc32_long(crc32_buf)
    
    local tail = "; path=/"
    if httponly == nil or httponly == true then 
        tail = string_format("%s; HttpOnly", tail)
    end
    
    return string_format("%d:%s%s", _time, crc32, tail)
end

function _M.check_cookie_value(self, cookie, req, key, timeout)

    if not cookie or _type(key) ~= "string" then
        ngx_log(ngx_WARN, "not cookie or key not a string in check_cookie_value")
        return false
    end
    
    local from = string_find(cookie, ":")
    if not from or from == 1 or from == #cookie then
        return false
    end
    
    local _time     = _tonumber(string_sub(cookie, 1, from - 1)) or 0
    local crc       = _tonumber(string_sub(cookie, from + 1)) or 0
    local now       = twaf:get_vars("TIME_EPOCH", req)
    local addr      = twaf:get_vars("REMOTE_ADDR", req)
    local agent     = twaf:get_vars("HTTP_USER_AGENT", req) or ""
    local crc32_buf = string_format("%d%s%s%s%d", _time, addr, agent, key, _time)
    local crc32     = ngx_crc32_long(crc32_buf)
    
    if crc == crc32 then
        if timeout and (now - _time) > timeout then
            return ngx_AGAIN
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
    
    if _type(complex) == "string" then
        res = ngx_re_find(subject, complex, options)
        if res then
            return true
        end
        
    elseif _type(complex) == "table" then
        for _, v in pairs(complex) do
            res = ngx_re_find(subject, v, options)
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
    if _type(state) == "string" then
        state = string_sub(state, 2)
        local ds_state = ngx_var[state]
        
        if ds_state == "1" then
            return true
        elseif ds_state == "0" then
            return false
        end
        
        return false
    end
    
    if  _type(state) == "boolean" then
        return state
    end
    
    return false
end

function _M.get_variable(self, key)
    local str = nil
    local req = twaf:ctx().req
    
    if string_sub(key, 1, 1) == "%" then
        str = _M:parse_dynamic_value(key ,req)
    else
        str = _M:table_to_string(twaf:get_vars(string_upper(key), req))
    end
    
    if str == nil then
        return "-"
    end
    
    return str
end

function _M.key(self, key_var)
    local key
    
    if _type(key_var) == "string" then
        key = self:get_variable(key_var)
        
    elseif _type(key_var) == "table" then
    
        if _type(key_var[1]) == "string" then
            key = self:get_variable(key_var[1])
            for i = 2, #key_var do
                key = key .. self:get_variable(key_var[i])
            end
            
        elseif _type(key_var[1]) == "table" then
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

function _M.random_id(self, max_len, bool)
    
    local seed = _tostring(os_time())
    if not bool then
        seed = seed .. _tostring(ngx_var.stat_requests)
    end
    
    math_randomseed(_tonumber(seed))
    
    local srt = ""
    local str = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i = 1, max_len, 1 do
        local index = math_random(1, #str)
        srt = srt .. string_sub(str, index, index)
    end
    
    return srt
end

function _M.copy_table(self, st)
    local new_tab = {}
    for k, v in pairs(st or {}) do
        if k == "lua" then
            new_tab[k] = _tostring(v)
        else
            if _type(v) ~= "table" then
                new_tab[k] = v
            else
                new_tab[k] = _M:copy_table(v)
            end
        end
    end
    
    return new_tab
end

function _M.copy_value(self, val)
    if _type(val) == "table" then
        return _M:copy_table(val)
    end
    
    return val
end

function _M.table_has_value(self, tb, value)
    if _type(tb) ~= "table" or _type(value) == "table" then
        return false
    end
    
    for _, v in pairs(tb) do
        if _type(v) == "table" then
            return _M:table_has_value(v, value)
        else
            if _type(v) == _type(value) and v == value then
                return true
            end
        end
    end
    
    return false
end


function _M.table_keys(self, tb)
    if _type(tb) ~= "table" then
        ngx_log(ngx_WARN, _type(tb) .. " was given to table_keys")
        return tb
    end
    
    local t = {}
    
    for key, _ in pairs(tb) do
        table_insert(t, key)
    end
    
    return t
end

function _M.table_values(self, tb)
    if _type(tb) ~= "table" then
        ngx_log(ngx_WARN, _type(tb) .. " was given to table_values")
        return tb
    end
    
    local t = {}
    
    for _, value in pairs(tb) do
        if _type(value) == "table" then
            local tab = _M:table_values(value)
            for _, v in pairs(tab) do
                table_insert(t, v)
            end
        else
            table_insert(t, value)
        end
    end
    
    return t
end

function _M.multi_table_values(self, ...)
    
    local t = {}
    
    for _, tb in ipairs({...}) do
        local t1 = _M:table_values(tb)
        for _, v in ipairs(t1) do
            table_insert(t, v)
        end
    end
    
    return t
end

local function check_rules_opts(r, str, err)
    local o = r.opts
    
    o.nolog = o.nolog or false
    _M.type_check(o.nolog, str.."opts.nolog", "boolean", err)
    
    r.log_state = (not o.nolog or o.log) and true or false
end

local function check_rules_var(m, v, str, err)

    v.var_type = _type(v.var)
    if v.var_type == "string" then
        v.var = string_upper(v.var)
    elseif v.var_type == "function" then
        -- nothing to do
    else
        table_insert(err, str .. "var: string or function expected")
    end

    v.storage = v.storage or false
    _M.type_check(v.storage, str.."storage", "boolean", err)

    if v.shm_key then
        _M.type_check(v.shm_key, str.."shm_key", "string", err)
    end

    if v["function"] then
        _M.type_check(v.var, str.."var", "string", err)
        v.var = string_lower(v.var)
    end

    -- phase

    if v.parse then
        _M.type_check(v.parse, str.."parse", "table", err)

        local is_parse = {specific = 1, ignore = 2, keys = 3, values = 4, all = 5}

        local parse = {}
        for pk, pv in pairs(v.parse) do
            if not parse[1] then
                parse = {pk, pv}
                if not is_parse[pk] then
                    table_insert(err, str .. "parse: specific, ignore, keys, values or all expected")
                end
            else
                table_insert(err, str .. "parse: just one parse expected")
                break
            end
        end

        if parse[1] == "specific" and parse[2] == "" then parse = nil end
        v.parse = parse
    end
    
    if not v.storage and not v.shm_key and not v.nocache then
        
        local parse = ""
        if v.parse then
            parse = _M:table_to_string(v.parse)
        end
        
        local tf = ""
        if _type(m.transform) == "string" then
            tf = m.transform
        elseif _type(m.transform) == "table" then
            for _, t in ipairs(m.transform) do
                tf = tf .. t
            end
        end
        
        v.cache_v  = v.var .. parse
        v.cache_vt = v.cache_v .. tf
    end
end

local function check_rules_match(mt, str, err)
    if not mt or not _M.type_check(mt, str.."match", "table", err) then 
        return true 
    end

    local s = ""
    local flag = false
    local is_type = {table = 1, string = 2}
    for i, m in ipairs(mt) do

        s = string_format("%s match[%d] - ", str, i)
        _M.type_check(m.vars, s.."vars", "table", err)

        if m.transform then
            m.transform_type = is_type[_type(m.transform)]
            if not m.transform_type then
                table_insert(err, s .. "transform: table or string expected")
            end
            
            if m.transform_type == 1 then
                if not m.transform[2] then
                    m.transform = m.transform[1]
                    if m.transform then
                        _M.type_check(m.transform, s.."transform", "string", err)
                    else
                        m.transform_type = nil
                    end
                end
            end
        end

        for j, v in ipairs(m.vars) do
            check_rules_var(m, v, string_format("%s vars[%d] - ", s, j), err)
        end

        _M.type_check(m.operator, s.."operator", "string", err)

        if m.pattern then flag = true end

        if m.pf then
            if flag == true then
                table_insert(err, "just need one of pattern, pf or pset")
            else
                flag = true
                _M.type_check(m.pf, s.."pf", "string", err)

                m.pattern = {}
                local f = io_open(m.pf)
                if not f then
                    table_insert(err, s.."pf: open failed ".._tostring(pf))
                else
                    repeat
                    local n = f:read()
                    if not n then break end
                    table_insert(m.pattern, n)
                    until false

                    f:close()
                end
            end
        end

        if m.pset then
            if flag == true then
                table_insert(err, "just need one of pattern, pf or pset")
            else
                flag = true
                m.pattern = twaf.config.pset[m.pset]
                if not m.pattern then
                    table_insert(err, "not found pset: "..m.pset)
                    m.pattern = {}
                end
            end
        end

        m.p_is_table = _type(m.pattern) == "table" and true or false
        m.parse_pattern = m.parse_pattern or false
        _M.type_check(m.parse_pattern, s.."parse_pattern", "boolean", err)

        m.op_negated = m.op_negated or false
        _M.type_check(m.op_negated, s.."op_negated", "boolean", err)

        flag = false
    end
    
    return true
end

function _M.check_rules(self, ids, r)

    local err = {}
    local str = string_format("ID %s - ", _tostring(r.id))

    -- id 
    _M.type_check(r.id, str.."id", "string", err)

    if ids[r.id] then
        table_insert(err, str .. "id is duplicated")
    end

  --_M.type_check(r.weight, str.."weight", "number", err)

    r.release_version = r.release_version or ""
    _M.type_check(r.release_version, str.."release_version", "string", err)

    r.charactor_version = r.charactor_version or ""
    _M.type_check(r.charactor_version, str.."charactor_version", "string", err)

    r.severity = r.severity or "high"
    _M.type_check(r.severity, str.."severity", "string", err)

    r.category = r.category or ""
    _M.type_check(r.category, str.."category", "string", err)

    _M.type_check(r.rule_name, str.."rule_name", "string", err)

    r.disable = r.disable or false
    _M.type_check(r.disable, str.."disable", "boolean", err)

    r.opts = r.opts or {}
    check_rules_opts(r, str, err)

    if _type(r.phase) == "table" then r.phase = r.phase[1] end

    local is_phase = {access = 1, header_filter = 1, body_filter = 1}
    if not is_phase[r.phase] then
        table_insert(err, str .. "phase: access,header_filter or body_filter expected")
    end

    r.action = r.action or "PASS"
    local f, a, m = twaf_action.is_action(r.action, r.meta)
    if not f then table_insert(err, str .. a) end
    r.action = a
    r.meta = m

    -- desc
    -- tags

    r.recommend = _tonumber(r.recommend) or 9
    _M.type_check(r.recommend, str.."recommend", "number", err)

    check_rules_match(r.match, str, err)

    if #err > 0 then return false, err end

    return true
end

local function sanitise_request_line(ctx, req)

    local s
    
    local func = function(m)
        local str = ""
        for i = 1, #m - 1 do
            str = str.."*"
        end
                    
        str = string_format("%s=%s%s", s, str, string_sub(m, -1, -1))
        return str
    end
    
    local r_line = twaf:get_vars("REQUEST_LINE", req)
    
    if r_line and ctx.sanitise_uri_args then
        for _, arg in pairs(ctx.sanitise_uri_args) do
            s = arg
            r_line = string_gsub(r_line, arg.."=(.-[& ])", func)
        end
    end
    
    ctx.sanitise_uri_args = nil
    return r_line or ""
end

local function table_value_to_string(tb)
    if _type(tb) ~= "table" then return tb end
    
    for k, v in pairs(tb) do
        if _type(v) == "table" then
            tb[k] = table_value_to_string(v)
        elseif _type(v) =="function" then
            tb[k] = string_dump(v)
        elseif _type(v) == "userdata" then
            tb[k] = 1
        end
    end
    
    return tb
end

function _M.table_to_string(self, tb, is_all)
    if _type(tb) ~= "table" then return is_all == true and _tostring(tb) or tb end
    
    local tbl = _M:copy_table(tb)
    
    local t = table_value_to_string(tbl)
    
    return cjson.encode(t)
end

function _M.syn_config_process(self, _twaf, worker_config)

    if _type(worker_config) ~= "table" then
        return nil
    end
    
    local phase = {"access", "header_filter", "body_filter"}
    --[[
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
    ]]
    for k, v in pairs(worker_config) do
        if _type(_twaf.config[k]) == "userdata" then
            worker_config[k] = _twaf.config[k]
        end
    end
    
    return worker_config
end

function _M.syn_config(self, _twaf)
    local gcf   = _twaf:get_config_param("twaf_global")
    local dict  =  ngx_shared[gcf.dict_name]
    local wid   =  ngx_worker_id()
    local wpid  =  ngx_worker_pid()
    
    local res = dict:get("worker_process_"..wid)
    
    if res == nil or res == true or res ~= wpid then
        ngx_log(ngx_INFO, "config synchronization ing..")
        local worker_config = dict:get("worker_config")
        worker_config = cjson.decode(worker_config)
        
        _twaf.config = _M:syn_config_process(_twaf, worker_config) or _twaf.config
        
        dict:set("worker_process_"..wid, wpid)
    end
end

-- input：nil string number boolean table "nil" function
-- output: nil string, number
function _M.parse_dynamic_value(self, key, req)
    local lookup = function(m)
        local val      = twaf:get_vars(string_upper(m[1]), req)
        local specific = m[2]
        
        if (not val) then
            --logger.fatal_fail("Bad dynamic parse, no collection key " .. m[1])
            return ngx_var[m[1]] or "-"
        end
        
        if (_type(val) == "table") then
            if (specific) then
                return _M:table_to_string(val[specific], true)
            else
                return _M:table_to_string(val, true)
            end
        elseif (_type(val) == "function") then
            return _M:table_to_string(val(twaf), true)
        else
            return _M:table_to_string(val, true)
        end
    end
    
    -- grab something that looks like
    -- %{VAL} or %{VAL.foo}
    -- and find it in the lookup table
    local str = ngx_re_gsub(key, [[%{([^\.]+?)(?:\.([^}]+))?}]], lookup, "oij")
    
    if str == "nil" then return nil end
    
    --logger.log(_twaf, "Parsed dynamic value is " .. str)
    
    if (ngx_re_find(str, [=[^\d+$]=], "oij")) then
        return _tonumber(str)
    else
        return str
    end
end

function _M.conf_log(self, _twaf, req, ctx)

    local _log =  {}
    local  lcf = _twaf:get_config_param("twaf_log") or {}
    local  sef =  lcf.safe_event_format
    
    if not sef then
        return false
    end
    
    for _, v in pairs(sef.ctx or {}) do
        _log[v] = _M:table_to_string(ctx[v]) or "-"
    end
    
    for _, v in pairs(sef.vars or {}) do
        _log[v] = _M:table_to_string(_twaf:get_vars(string_upper(v), req)) or "-"
    end
    
    return _log
end

function _M.rule_category(self, _twaf, rule_name)
    for k, v in pairs(_twaf.config.category_map or {}) do
        if ngx_re_find(rule_name, v.rule_name) then
            return k
        end
    end
    
    return "UNKNOWN"
end

function _M.rule_log(self, _twaf, info)

    local ctx     = _twaf:ctx()
    local req     =  ctx.req
    info.action   =  string_upper(info.action or "PASS")
    info.category = _M:rule_category(_twaf, info.rule_name)
    
    -- reqstat
    ctx.events.stat[info.category] = info.action
    
    -- attack response
    if info.action == "DENY" then
        ngx_var.twaf_attack_info = ngx_var.twaf_attack_info .. info.rule_name .. ";"
    end
    
    -- log
    if info.log_state == true then
        ctx.events.log[info.rule_name] = _M:conf_log(_twaf, ctx.req, info)
    end
    
    req.MATCHED_VARS      = {}
    req.MATCHED_VAR_NAMES = {}
    
    -- action
    return twaf_action:do_action(_twaf, info.action, info.action_meta)
end

function _M:print_G(_twaf)

    local gcf = _twaf:get_config_param("twaf_global")
    local shm =  gcf.dict_name
    
    if not shm then return end
    local dict = ngx_shared[shm]
    if not dict then return end
    
    local path = dict:get("twaf_print_G")
    if not path then return end
    
    dict:delete("twaf_print_G")
    
    local data = {}
    local tablePrinted = {}
    
    local printTableItem = function(tb, k, v, printTableItem)
        k = _tostring(k)
        if _type(v) == "table" then
            if not tablePrinted[v] then
                tb[k] = {}
                tablePrinted[v] = true
                for m, n in pairs(v) do
                    printTableItem(tb[k], m, n, printTableItem)
                end
            else
                tb[k] = "'"..k.."' have existed"
            end
        else
            tb[k] = _tostring(v)
        end
    end
    
    printTableItem(data, "_G", _G, printTableItem)
    
    local f = io_open(path, "a+")
    f:write(cjson.encode(data))
    f:close()
    
    return
end

function _M:print_ctx(_twaf)

    local gcf = _twaf:get_config_param("twaf_global")
    local shm =  gcf.dict_name
    
    if not shm then return end
    local dict = ngx_shared[shm]
    if not dict then return end
    
    local path = dict:get("twaf_print_ctx")
    if not path then return end
    
    dict:delete("twaf_print_ctx")
    
    local func = function(tb, func, data, tablePrinted)
    
        data = data or {}
        tablePrinted = tablePrinted or {}
    
        if _type(tb) ~= "table" then
            return _tostring(tb) 
        end
        
        for k, v in pairs(tb) do
            if _type(v) == "table" then
                if not tablePrinted[v] then
                    tablePrinted[v] = true
                    data[k] = func(v, func, data[k], tablePrinted)
                else
                    data[k] = "'"..k.."' have existed"
                end
            else
                data[k] = _tostring(v)
            end
        end
        
        return data
    end
    
    local data = func(_twaf:ctx(), func)
    
    local f = io_open(path, "a+")
    f:write(cjson.encode(data))
    f:close()
end

function _M.table_merge(tb1, tb2)

    if _type(tb1) ~= "table" or _type(tb2) ~= "table" then return tb1 end
    
    for k, v in pairs(tb2) do
        tb1[k] = v
    end
    
    return tb1
end

-- check json body
function _M.api_check_json_body(log)
    ngx_req_read_body()
    local body = ngx_req_get_body_data()
    
    local res, data = pcall(cjson.decode, body)
    if not res or _type(data) ~= "table" then
        log.success = 0
        log.reason  = "request body: json expected, got " .. (body or "nil")
        return nil
    end
    
    return data
end

function _M.flush_cache_timer(premature, delay, dict, dict_key, timer_key)

    local timer_delay = dict:get(timer_key)
    if not timer_delay or timer_delay ~= delay then
        return nil
    end
    
    if dict:get(dict_key.."_change") then

        local f, err = io_open(dict_key, "w+")
        if err then 
            ngx_log(ngx_ERR, "open failed: ", err)
        else
            f:write(dict:get(dict_key) or "")
            f:close()
        end
        
        dict:set(dict_key.."_change", nil)
        
    end
    
    local ok, err = timer(delay, _M.flush_cache_timer, delay, dict, dict_key, timer_key)
    if err then
        ngx_log(ngx_ERR, "failed set timer when flush info to file: ", err)
        dict:set(timer_key, nil)
    end
    
    return ok, err
end

function _M.type_check(arg, key, typ, tb)
    local ty = _type(arg)
    if ty ~= typ then
        local err = string_format("%s: %s expected, got %s", key, typ, ty)
        if tb then
            table_insert(tb, err)
        end
        return false, err
    end
    return true
end

function _M.matched_var(req, name, var)
    req.MATCHED_VAR      = var
    req.MATCHED_VAR_NAME = name
    table_insert(req.MATCHED_VARS, var)
    table_insert(req.MATCHED_VAR_NAMES, name)
end

return _M
