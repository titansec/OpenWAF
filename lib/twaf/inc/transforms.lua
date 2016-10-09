
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.

local _M = {
    _VERSION = "0.01"
}

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
        base64_encode = function(value)
            if not value then return nil end
            
            return ngx.encode_base64(value)
        end,
        compress_whitespace = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\s+]=], ' ', "oij")
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
            str = ngx.re.gsub(str, [=[&#(\d+);]=], function(n) return string.char(n[1]) end, "oij")
            str = ngx.re.gsub(str, [=[&#x(\d+);]=], function(n) return string.char(tonumber(n[1],16)) end, "oij")
            str = ngx.re.gsub(str, [=[&amp;]=], '&', "oij")
            return str
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
        normalise_path = function(value)
            if type(value) ~= "string" then return value end
            
            while (ngx.re.match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], "oij")) do
                value = ngx.re.gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', "oij")
            end
            return value
        end,
        remove_comments = function(value)
            if type(value) ~= "string" then return value end
            
            -- modsec支持去掉/*...*/,--,#，而这里目前只支持去掉/*...*/
            return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', "oij")
        end,
        remove_comments_char = function(value)
            if type(value) ~= "string" then return value end
            
            --同modsec,去掉/*,*/,--,#
            return ngx.re.gsub(value, [=[\/\*|\*\/|--|#]=], '', "oij")
        end,
        remove_whitespace = function(value)
            if type(value) ~= "string" then return value end
            
            return ngx.re.gsub(value, [=[\s+]=], '', "oij")
        end,
        remove_nulls = function(value)
            return ngx.re.gsub(value, [=[\0+]=], '', "oij")
        end,
        replace_comments = function(value)
            if type(value) ~= "string" then return value end
            
            --用一个空格代替/*...*/
            return ngx.re.gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], ' ', "oij")
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
                    str = value:gsub('..', function (cc)
                        return string.char(tonumber(cc, 16))
                    end)
                end)) then
                    return str
                else
                    return value
                end
            else
                return value
            end
        end,
        trim = function(value)
            if type(value) ~= "string" then return value end
            
            --去除左右两侧空格
            return ngx.re.gsub(value, [=[^\s*|\s+$]=], '')
        end,
        trim_left = function(value)
            if type(value) ~= "string" then return value end
            
            --去除左侧空格
            return ngx.re.sub(value, [=[^\s+]=], '')
        end,
        trim_right = function(value)
            if type(value) ~= "string" then return value end
            
            --去除左侧空格
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
        counter = function(value)
            if not value then return 0 end
            
            if type(value) == "table" then
                return #value
            end
            
            return 1
        end,
    }
    
    if not func[options] then
        ngx.log(ngx.WARN, "Not support transform: ", options)
        return false
    end
    
    return func[options](values)
end

return _M
