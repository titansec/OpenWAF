
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

local iputils      = require "resty.iputils"
local libinjection = require "resty.libinjection"

function _M.operators(self, operator, subject, pattern, ctx)

    ctx = ctx or {}
    
    local func = {
        equal = function(a, b)
            a = tostring(a)
            b = tostring(b)
                        
            if a == b then
                ctx.mp = "Operator equal matched "..a
                return true, a
            else
                ctx.mp = "Operator equal matched "..a.." (negated)"
                return false, a
            end
            
        end,
        greater = function(a, b)
            a = tonumber(a)
            b = tonumber(b)
            if not a or not b then
                ctx.mp = "expected number, but got data: '"..a.."'".." ,pattern: '"..b.."'"
                return false, a
            end
            
            if a > b then
                ctx.mp = "Operator greater matched "..a
                return true, a
            else
                ctx.mp = "Operator greater matched "..a.." (negated)"
                return false, a
            end
            
        end,
        less = function(a, b)
            a = tonumber(a)
            b = tonumber(b)
            if not a or not b then
                ctx.mp = "expected number, but got data: '"..a.."'".." ,pattern: '"..b.."'"
                return false, a
            end
            
            if a < b then
                ctx.mp = "Operator less matched "..a
                return true, a
            else
                ctx.mp = "Operator less matched "..a.." (negated)"
                return false, a
            end
            
        end,
        greater_eq = function(a, b)
            a = tonumber(a)
            b = tonumber(b)
            if not a or not b then
                ctx.mp = "expected number, but got data: '"..a.."'".." ,pattern: '"..b.."'"
                return false, a
            end
            
            if a >= b then
                ctx.mp = "Operator greater_eq matched "..a
                return true, a
            else
                ctx.mp = "Operator greater_eq matched "..a.." (negated)"
                return false, a
            end
            
        end,
        less_eq = function(a, b)
            a = tonumber(a)
            b = tonumber(b)
            if not a or not b then
                ctx.mp = "expected number, but got data: '"..a.."'".." ,pattern: '"..b.."'"
                return false, a
            end
            
            if a <= b then
                ctx.mp = "Operator less_eq matched "..a
                return true, a
            else
                ctx.mp = "Operator less_eq matched "..a.." (negated)"
                return false, a
            end
            
        end,
        begins_with = function(subject, pattern)
            
            local from, to = tostring(subject):find(pattern)
            if from == 1 then
                ctx.mp = "String match "..pattern
                return true, subject
            else
                ctx.mp = "String match "..pattern.." (negated)"
                return false, subject
            end
            
        end,
        contains = function(subject, pattern)
            
            local from, to = tostring(subject):find(pattern)
            if from then
                ctx.mp = "String match "..pattern
                return true, subject
            else
                ctx.mp = "String match "..pattern.." (negated)"
                return false, subject
            end
            
        end,
        contains_word = function(subject, pattern)
            
            local pa = "\b"..pattern.."\b"
            local from, to = tostring(subject):find(pa)
            if from then
                ctx.mp = "String match "..pattern
                return true, subject
            else
                ctx.mp = "String match "..pattern.." (negated)"
                return false, subject
            end
            
        end,
        ends_with = function(subject, pattern)
            local from, to = tostring(subject):find(pattern)
            if to == #subject then
                ctx.mp = "String match "..pattern
                return true, subject
            else
                ctx.mp = "String match "..pattern.." (negated)"
                return false, subject
            end
            
        end,
        str_match = function(subject, pattern)
            
            local from, to = tostring(subject):find(pattern, 1, true)
            if from then
                ctx.mp = "Pattern match "..pattern
                return true, subject
            else
                ctx.mp = "Pattern match "..pattern.. " (negated)"
                return false, subject
            end
            
        end,
        detect_sqli = function(data)
        
            if type(data) ~= "string" then
                ctx.mp = "detected SQLi using libinjection, but not sqli (negated)"
                return false, data
            end
            
            local  issqli, fingerprint = libinjection.sqli(data)
            if issqli then
                ctx.mp = "detected SQLi using libinjection with fingerprint "..fingerprint
                return true, data
            else
                ctx.mp = "detected SQLi using libinjection, but not sqli (negated)"
                return false, data
            end
            
        end,
        detect_xss = function(data)
            if type(data) ~= "string" then
                ctx.mp = "detected XSS using libinjection (negated)"
                return false, data
            end
            
            local isxss = libinjection.xss(data)
            if isxss then
                ctx.mp = "detected XSS using libinjection"
                return true, data
            else
                ctx.mp = "detected XSS using libinjection (negated)"
                return false, data
            end
            
        end,
        regex = function(subject, pattern)
        
            local captures, err = ngx.re.match(tostring(subject), pattern, "oij")
            if not captures then
                ctx.mp = "Pattern match "..pattern.." (negated)"
                return false, subject
            end
            
            if #pattern > 252 then
                pattern = pattern:sub(1, 252)
            end
                
            ctx.mp = "Pattern match "..pattern
            return true, captures
            
        end,
        ip_utils = function(subject, pattern)
        
            local lower, upper, err
            
            local from = pattern:find("-")
            if from then
                lower = iputils.ip2bin(pattern:sub(1, from - 1))
                upper = iputils.ip2bin(pattern:sub(from + 1))
                
                if not lower or not upper then
                    ctx.mp = "Iputils ip2bin failed, pattern: "..pattern
                    return false, subject
                end
                
            elseif pattern:find("/") then
                lower, upper = iputils.parse_cidr(pattern)
                if not lower then
                    ctx.mp = "Iputils parse cidr failed: "..pattern
                    return false, subject
                end
                
            else
                lower = iputils.ip2bin(pattern)
                upper = lower
                
                if not lower then
                    ctx.mp = "Iputils ip2bin failed, pattern: "..pattern
                    return false, subject
                end
            end
            
            local bin_ip = iputils.ip2bin(subject)
            
            if bin_ip >= lower and bin_ip <= upper then
                ctx.mp = "Iputils match "..pattern
                return true, subject
            end
            
            ctx.mp = "Iputils match "..pattern.." (negated)"
            return false, subject
        end,
        num_range = function(subject, pattern)
        
            subject = tonumber(subject)
            if not subject then
                ctx.mp = "expected number, but got data: '"..pattern.."'"
                return false, subject
            end
            
            --  before '-' need '%'
            local from =  pattern:find("-")
            if not from then
                pattern = tonumber(pattern)
                if not pattern then
                    -- TODO: if check rule, then such 'if' don't need
                    ngx.log(ngx.WARN, "pattern format wrong: ", pattern)
                    return false, "pattern format wrong"
                end
                
                return subject == pattern, subject
            end
            
            local left  = tonumber(pattern:sub(1, from - 1))
            local right = tonumber(pattern:sub(from + 1))
            
            if not left or not right then
                ngx.log(ngx.WARN, "pattern format wrong: ", pattern)
                return false, "pattern format wrong"
            end
            
            if subject >= left and subject <= right then
                ctx.mp = "Operator num_range matched: "..subject
                return true, subject
            end
            
            ctx.mp = "Operator num_range matched: "..subject.." (negated)"
            return false, subject
        end,
        str_range = function(subject, pattern)
        
            subject = tostring(subject)
            if not subject then
                return false, "subject is nil"
            end
            
            --  before '-' need '%'
            local from =  pattern:find("-")
            if not from then
                pattern = pattern
                if not pattern then
                    ngx.log(ngx.WARN, "pattern format wrong: ", pattern)
                    return false, "pattern format wrong"
                end
                
                return subject == pattern, subject
            end
            
            local left  = pattern:sub(1, from - 1)
            local right = pattern:sub(from + 1)
            
            if not left or not right then
                ngx.log(ngx.WARN, "pattern format wrong: ", pattern)
                return false, "pattern format wrong"
            end
            
            if subject >= left and subject <= right then
                ctx.mp = "Operator str_range matched: "..subject
                return true, subject
            end
            
            ctx.mp = "Operator str_range matched: "..subject.." (negated)"
            return false, subject
        end,
        validate_url_encoding = function(data)
        
            -- 检验url，%xx中xx是16进制
            if not data then
                return false
            end
            
            local i   = 1
            local len = #data
            
            repeat
            
                if i > len then
                    break
                end
                
                local c = data:sub(i,i)
                if c == "%" then
                    if (i + 2) > len then
                        -- Not enough bytes.
                        ctx.mp = "Invalid URL Encoding: Not enough characters at the end of '"..data.."'"
                        return true, data
                    else
                        local c1 = data:sub(i+1, i+1)
                        local c2 = data:sub(i+2, i+2)
                        
                        if ((c1 >= '0' and c1 <= '9')  or 
                            (c1 >= 'a' and c1 <= 'f')  or 
                            (c1 >= 'A' and c1 <= 'F')) and
                           ((c2 >= '0' and c2 <= '9')  or
                            (c2 >= 'a' and c2 <= 'f')  or 
                            (c2 >= 'A' and c2 <= 'F'))
                        then
                            i = i + 3
                        else
                            ctx.mp = "Invalid URL Encoding: Non-hexadecimal digits of '"..data.."'"
                            return true, data
                        end
                    end
                else
                    i = i + 1
                end
            
            until false
            
            return false
        end
    }
    
    if not func[operator] then
        ngx.log(ngx.WARN, "Not support operator: ", operator)
        return false
    end
    
    -- return true or false, not others, like nil and so on
    return func[operator](subject, pattern)
end

return _M
