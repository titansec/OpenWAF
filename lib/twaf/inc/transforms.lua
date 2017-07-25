
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local ffi        = require "ffi"
local twaf_func  = require "lib.twaf.inc.twaf_func"

function _M.transforms(self, options, values)
    local func = {
        base64_decode = function(value)
            if not value then return nil end
            
            local t_val = ngx.decode_base64(tostring(value))
            if (t_val) then
                return t_val
            else
                return value
            end
        end,
        base64_decode_ext = function(value)
            if not value then return nil end
            if type(twaf_func.decode_lib) ~= "userdate" then return nil end
            
            local val = tostring(value)
            local len = #val
            local buf = ffi.new(ffi.typeof("char[?]"), len)
            local n = twaf_func.decode_lib.decode_base64_ext(buf, val, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        base64_encode = function(value)
            if not value then return nil end
            
            return ngx.encode_base64(value)
        end,
        css_decode = function(waf, value)
            if not value then return nil end
            if type(twaf_func.decode_lib) ~= "userdate" then return nil end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = twaf_func.decode_lib.css_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        compress_whitespace = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\s+]=], ' ', "oij")
        end,
        counter = function(value)
            if not value then return 0 end
            
            if type(value) == "table" then
                return #value
            end
            
            return 1
        end,
        escape_seq_decode = function(value)
            if not value then return nil end
            if type(twaf_func.decode_lib) ~= "userdate" then return nil end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = twaf_func.decode_lib.escape_seq_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        hex_decode = function(value)
            if type(value) ~= "string" then return value end
            
            local str

            if (pcall(function()
                str = value:gsub('..', function (cc)
                    return string.char(tonumber(cc, 16))
                end)
            end)) then
                return str
            else
                return value
            end
        end,
        hex_encode = function(value)
            if type(value) ~= "string" then return value end
            
            return (value:gsub('.', function (c)
                return string.format('%02x', string.byte(c))
            end))
        end,
        html_decode = function(value)
            if type(value) ~= "string" then return value end
            
            local str = ngx.re.gsub(value, [=[&lt;]=], '<', "oij")
            str = ngx.re.gsub(str, [=[&gt;]=], '>', "oij")
            str = ngx.re.gsub(str, [=[&quot;]=], '"', "oij")
            str = ngx.re.gsub(str, [=[&apos;]=], "'", "oij")
            pcall(function() str = ngx.re.gsub(str, [=[&#(\d+);]=], function(n) return string.char(n[1]) end, "oij") end)
            pcall(function() str = ngx.re.gsub(str, [=[&#x(\d+);]=], function(n) return string.char(tonumber(n[1],16)) end, "oij") end)
            str = ngx.re.gsub(str, [=[&amp;]=], '&', "oij")
            return str
        end,
        js_decode = function(waf, value)
            if not value then return nil end
            if type(twaf_func.decode_lib) ~= "userdate" then return nil end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = twaf_func.decode_lib.js_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        length = function(value)
            if not value then
                return 0
            end
            
            if type(value) == "table" then
                local length = 0
                for k, v in pairs(value) do
                    length = length + #tostring(k) + #tostring(v)
                end
                
                return length
            end
            
            return #tostring(value)
        end,
        lowercase = function(value)
            if type(value) ~= "string" then return value end
            
            return string.lower(value)
        end,
        md5 = function(value)
            if not value then return nil end
            
            return ngx.md5_bin(value)
        end,
        none = function(value)
            return value
        end,
        normalise_path = function(value)
            if type(value) ~= "string" then return value end
            
            while (ngx.re.match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], "oij")) do
                value = ngx.re.gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', "oij")
            end
            return value
        end,
        remove_comments = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', "oij")
        end,
        remove_comments_char = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\/\*|\*\/|--|#]=], '', "oij")
        end,
        remove_nulls = function(value)
            return ngx.re.gsub(value, [=[\0+]=], '', "oij")
        end,
        remove_whitespace = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\s+]=], '', "oij")
        end,
        replace_comments = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], ' ', "oij")
        end,
        replace_nulls = function(waf, value)
            return ngx.re.gsub(value, [[\0]], ' ', "oij")
        end,
        sha1 = function(value)
            if not value then return nil end
            
            return ngx.sha1_bin(value)
        end,
        sql_hex_decode = function(value)
            if type(value) ~= "string" then return value end
            
            if (string.find(value, '0x', 1, true)) then
                value = string.sub(value, 3)
                local str
                if (pcall(function()
                    str = value:gsub('..', 
                        function (cc) 
                           return string.char(tonumber(cc, 16)) 
                        end)
                    end)) 
                then
                    return str
                end
                
                return value
            end
            
            return value
        end,
        trim = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[^\s*|\s+$]=], '')
        end,
        trim_left = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.sub(value, [=[^\s+]=], '')
        end,
        trim_right = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.sub(value, [=[\s+$]=], '')
        end,
        uri_decode = function(value)
            if type(value) ~= "string" then return value end
            
            --Unescape str as an escaped URI component.
            return ngx.unescape_uri(value)
        end,
        uri_decode_uni = function(value)
            if type(value) ~= "string" then return value end
            
            --Unescape str as an escaped URI component.
            return ngx.unescape_uri(value)
        end,
        uri_encode = function(value)
            if type(value) ~= "string" then return value end
            
            --Escape str as a URI component
            return ngx.escape_uri(value)
        end,
        utf8_to_unicode = function(value)
            if type(value) ~= "string" then return value end
            if type(twaf_func.decode_lib) ~= "userdate" then return nil end
            
            local inp_len = #value
            local inp     = twaf_func.ffi_copy(value, inp_len)
            local outp    = ffi.new(ffi.typeof("char[?]"), inp_len * 7 + 1)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local outp_len = twaf_func.decode_lib.utf8_to_unicode(outp, inp, inp_len, changed)
            
            return twaf_func.ffi_str(outp, outp_len)
        end
    }
    
    if not func[options] then
        ngx.log(ngx.WARN, "Not support transform: ", options)
        return nil
    end
    
    return func[options](values)
end

return _M
