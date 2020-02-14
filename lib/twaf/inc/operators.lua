
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local cidr         = require "lib.twaf.inc.cidr"
local iputils      = require "resty.iputils"
local libinjection = require "resty.libinjection"

local ngx_re_find  = ngx.re.find
local ngx_re_match = ngx.re.match
local ngx_log      = ngx.log
local ngx_WARN     = ngx.WARN
local _type        = type
local _tostring    = tostring
local _tonumber    = tonumber
local string_sub   = string.sub
local string_find  = string.find

function _M.operators(self, operator, subject, pattern, ctx)

    ctx = ctx or {}
    
    local func = {
        equal = function(a, b)
            a = _tostring(a)
            b = _tostring(b)
                        
            if a == b then
                return true, a
            else
                return false, a
            end
            
        end,
        greater = function(a, b)
            a = _tonumber(a)
            b = _tonumber(b)
            if not a or not b then
                return false, a
            end
            
            if a > b then
                return true, a
            else
                return false, a
            end
            
        end,
        less = function(a, b)
            a = _tonumber(a)
            b = _tonumber(b)
            if not a or not b then
                return false, a
            end
            
            if a < b then
                return true, a
            else
                return false, a
            end
            
        end,
        greater_eq = function(a, b)
            a = _tonumber(a)
            b = _tonumber(b)
            if not a or not b then
                return false, a
            end
            
            if a >= b then
                return true, a
            else
                return false, a
            end
            
        end,
        less_eq = function(a, b)
            a = _tonumber(a)
            b = _tonumber(b)
            if not a or not b then
                return false, a
            end
            
            if a <= b then
                return true, a
            else
                return false, a
            end
            
        end,
        begins_with = function(subject, pattern)
            
            local from, to = ngx_re_find(_tostring(subject), pattern)
            if from == 1 then
                return true, subject
            else
                return false, subject
            end
            
        end,
        contains = function(subject, pattern)
            
            local from, to = ngx_re_find(_tostring(subject), pattern)
            if from then
                return true, subject
            else
                return false, subject
            end
            
        end,
        contains_word = function(subject, pattern)
            
            local pa = "\b"..pattern.."\b"
            local from, to = ngx_re_find(_tostring(subject), pa)
            if from then
                return true, subject
            else
                return false, subject
            end
            
        end,
        ends_with = function(subject, pattern)
            
            local from, to = ngx_re_find(_tostring(subject), pattern)
            if to == #subject then
                return true, subject
            else
                return false, subject
            end
            
        end,
        str_match = function(subject, pattern)
            
            local from, to = ngx_re_find(_tostring(subject), pattern)
            if from then
                return true, subject
            else
                return false, subject
            end
            
        end,
        detect_sqli = function(data)
        
            if _type(data) ~= "string" then
                return false, data
            end
            
            local  issqli, fingerprint = libinjection.sqli(data)
            if issqli then
                return true, data
            else
                return false, data
            end
            
        end,
        detect_xss = function(data)
            if _type(data) ~= "string" then
                return false, data
            end
            
            local isxss = libinjection.xss(data)
            if isxss then
                return true, data
            else
                return false, data
            end
            
        end,
        regex = function(subject, pattern)
        
            local captures, err = ngx_re_match(_tostring(subject), _tostring(pattern), "oij")
            if not captures then
                return false, subject
            end
            
            if #pattern > 252 then
                pattern = string_sub(pattern, 1, 252)
            end
            
            return true, captures
            
        end,
        ip_utils = function(subject, pattern)
        
            -- subject: real ip
            -- pattern: configuration
            
            local ip_v6 = false
            local cf_v6 = false
            if string_find(subject, ":") then ip_v6 = true end
            if string_find(pattern, ":") then cf_v6 = true end
            
            if ip_v6 ~= cf_v6 then
                return false, subject
            end
            
            local from = string_find(pattern, "-")
            if not from then
            
                local bool = cidr.contains(cidr.from_str(pattern), cidr.from_str(subject))
                if bool == true then
                    return true, subject
                end
                
                return false, subject
            end
            
            if ip_v6 == true then
            
                local bool = cidr.ipv6_compare(string_sub(pattern, 1, from - 1), subject)
                if bool > 0 then
                    return false, subject
                end
                
                bool = cidr.ipv6_compare(string_sub(pattern, from + 1), subject)
                if bool < 0 then
                    return false, subject
                end
                
                return true, subject
            end
            
            -- ipv4
            local low, up
            
            low = iputils.ip2bin(string_sub(pattern, 1, from - 1))
            up  = iputils.ip2bin(string_sub(pattern, from + 1))
            
            if not low or not up then
                return false, subject
            end
            
            local bin_ip = iputils.ip2bin(subject)
            
            if bin_ip >= low and bin_ip <= up then
                return true, subject
            end
            
            return false, subject
        end,
        num_range = function(subject, pattern)
        
            subject = _tonumber(subject)
            if not subject then
                return false, subject
            end
            
            --  before '-' need '%'
            local from =  string_find(pattern, "-")
            if not from then
                pattern = _tonumber(pattern)
                if not pattern then
                    -- TODO: if check rule, then such 'if' don't need
                    ngx_log(ngx_WARN, "pattern format wrong: ", pattern)
                    return false, "pattern format wrong"
                end
                
                return subject == pattern, subject
            end
            
            local left  = _tonumber(string_sub(pattern, 1, from - 1))
            local right = _tonumber(string_sub(pattern, from + 1))
            
            if not left or not right then
                ngx_log(ngx_WARN, "pattern format wrong: ", pattern)
                return false, "pattern format wrong"
            end
            
            if subject >= left and subject <= right then
                return true, subject
            end
            
            return false, subject
        end,
        str_range = function(subject, pattern)
        
            subject = _tostring(subject)
            if not subject then
                return false, "subject is nil"
            end
            
            --  before '-' need '%'
            local from =  string_find(pattern, "-")
            if not from then
                pattern = pattern
                if not pattern then
                    ngx_log(ngx_WARN, "pattern format wrong: ", pattern)
                    return false, "pattern format wrong"
                end
                
                return subject == pattern, subject
            end
            
            local left  = string_sub(pattern, 1, from - 1)
            local right = string_sub(pattern, from + 1)
            
            if not left or not right then
                ngx_log(ngx_WARN, "pattern format wrong: ", pattern)
                return false, "pattern format wrong"
            end
            
            if subject >= left and subject <= right then
                return true, subject
            end
            
            return false, subject
        end,
        validate_url_encoding = function(data)
        
            if not data then
                return false
            end
            
            local i   = 1
            local len = #data
            
            repeat
            
                if i > len then
                    break
                end
                
                local c = string_sub(data, i, i)
                if c == "%" then
                    if (i + 2) > len then
                        -- Not enough bytes.
                        return true, data
                    else
                        local c1 = string_sub(data, i+1, i+1)
                        local c2 = string_sub(data, i+2, i+2)
                        
                        if ((c1 >= '0' and c1 <= '9')  or 
                            (c1 >= 'a' and c1 <= 'f')  or 
                            (c1 >= 'A' and c1 <= 'F')) and
                           ((c2 >= '0' and c2 <= '9')  or
                            (c2 >= 'a' and c2 <= 'f')  or 
                            (c2 >= 'A' and c2 <= 'F'))
                        then
                            i = i + 3
                        else
                            return true, data
                        end
                    end
                else
                    i = i + 1
                end
            
            until false
            
            return false
        end,
        sso = function(num)
        
            num = _tonumber(num) or 0
            
            if num == 0 then
                ngx.ctx.sso_opts = false
            elseif num > 0 then
                ngx.ctx.sso_opts = true
            end
            
        end
    }
    
    if not func[operator] then
        ngx_log(ngx_WARN, "Not support operator: ", operator)
        return false
    end
    
    -- return true or false, not others, like nil and so on
    return func[operator](subject, pattern)
end

return _M
