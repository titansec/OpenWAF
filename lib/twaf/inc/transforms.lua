
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.2"
}

local ffi        = require "ffi"
local twaf_func  = require "lib.twaf.inc.twaf_func"

local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64
local ngx_md5_bin = ngx.md5_bin
local ngx_sha1_bin = ngx.sha1_bin
local ngx_unescape_uri = ngx.unescape_uri
local ngx_escape_uri = ngx.escape_uri
local ngx_log = ngx.log
local ngx_WARN = ngx.WARN
local _tostring = tostring
local _type     = type

ffi.cdef[[
int js_decode(unsigned char *input, long int input_len);
int css_decode(unsigned char *input, long int input_len);
int decode_base64_ext(char *plain_text, const unsigned char *input, int input_len);
int escape_seq_decode(unsigned char *input, int input_len);
int utf8_to_unicode(char *output, unsigned char *input, long int input_len, unsigned char *changed);
int cmdline_execute(unsigned char *input, long int input_len);
int compressWhitespace_execute(unsigned char *input, long int input_len);
int hexDecode_execute(unsigned char *data, int len);
int bytes2hex(char *output, unsigned char *data, int len);
int html_entities_decode_inplace(unsigned char *input, int input_len);
int normalize_path(unsigned char *input, int input_len, int win, unsigned char *changed);
int removeComments_execute(unsigned char *input, long int input_len, unsigned char *changed);
int removeCommentsChar_execute(unsigned char *input, long int input_len, unsigned char *changed);
int removeNulls_execute(unsigned char *input, long int input_len, unsigned char *changed);
int removeWhitespace_execute(unsigned char *input, long int input_len, unsigned char *changed);
int replaceComments_execute(unsigned char *input, long int input_len, unsigned char *changed);
int replaceNulls_execute(unsigned char *input, long int input_len);
int trimLeft_execute(unsigned char *input, long int input_len);
int trimRight_execute(unsigned char *input, long int input_len);
int trim_execute(unsigned char *input, long int input_len);
int sql_hex2bytes(unsigned char *data, int len);
]]

_M.transforms_lib = twaf_func.load_lib(package.cpath, 'transforms.so')

function _M.transforms(self, options, values)
    local func = {
        base64_decode = function(value)
            if not value then return nil end
            
            local t_val = ngx_decode_base64(_tostring(value))
            if (t_val) then
                return t_val
            else
                return value
            end
        end,
        base64_decode_ext = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local val = _tostring(value)
            local len = #val
            local buf = ffi.new(ffi.typeof("char[?]"), len)
            local n = _M.transforms_lib.decode_base64_ext(buf, val, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        base64_encode = function(value)
            if not value then return nil end
            
            return ngx_encode_base64(value)
        end,
        css_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.css_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        cmd_line = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.cmdline_execute(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        compress_whitespace = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.compressWhitespace_execute(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        counter = function(value)
            if not value then return 0 end
            
            if _type(value) == "table" then
            
                local count = 0
                
                for _, v in pairs(value) do
                    count = count + 1
                end
                
                return count
            end
            
            return 1
        end,
        escape_seq_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.escape_seq_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        hex_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.hexDecode_execute(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        hex_encode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local outp = ffi.new(ffi.typeof("char[?]"), len * 2 + 1)
            
            local n = _M.transforms_lib.bytes2hex(outp, buf, len)
            
            return twaf_func.ffi_str(outp, n)
        end,
        html_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.html_entities_decode_inplace(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        js_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.js_decode(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        length = function(value)
            if not value then
                return 0
            end
            
            if _type(value) == "table" then
                local length = 0
                for k, v in pairs(value) do
                    length = length + #_tostring(k) + #_tostring(v)
                end
                
                return length
            end
            
            return #_tostring(value)
        end,
        lowercase = function(value)
            if _type(value) ~= "string" then return value end
            
            return string.lower(value)
        end,
        md5 = function(value)
            if not value then return nil end
            
            return ngx_md5_bin(value)
        end,
        none = function(value)
            return value
        end,
        normalise_path = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.normalize_path(buf, len, 0, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        normalise_path_win = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.normalize_path(buf, len, 1, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        remove_comments = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.removeComments_execute(buf, len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        remove_comments_char = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.removeCommentsChar_execute(buf, len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        remove_nulls = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.removeNulls_execute(buf, len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        remove_whitespace = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.removeWhitespace_execute(buf, len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        replace_comments = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.replaceComments_execute(buf, len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(buf, n)
        end,
        replace_nulls = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local changed = _M.transforms_lib.replaceNulls_execute(buf, len)
            
            if changed == 0 then return value end
            
            return twaf_func.ffi_str(buf, len)
        end,
        sha1 = function(value)
            if not value then return nil end
            
            return ngx_sha1_bin(value)
        end,
        sql_hex_decode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.sql_hex2bytes(buf, len)
            
            return twaf_func.ffi_str(buf, n)
        end,
        trim = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.trim_execute(buf, len)
            
            if (n == 0) then return value end
            
            return twaf_func.ffi_str(buf + n, len - n)
          --local str = _M:transforms("trim_left", value)
          --return _M:transforms("trim_right", str)
        end,
        trim_left = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            
            local n = _M.transforms_lib.trimLeft_execute(buf, len)
            
            if (n == 0) then return value end
            
          --return value:sub(len-n+1)
            return twaf_func.ffi_str(buf + n, len - n)
        end,
        trim_right = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local len = #value
            local buf = twaf_func.ffi_copy(value, len)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local n = _M.transforms_lib.trimRight_execute(buf, len)
            
            if (n == len) then return value end
            
            return twaf_func.ffi_str(buf, n)
        end,
        uri_decode = function(value)
            if _type(value) ~= "string" then return value end
            
            --modsec: Decodes a URL-encoded input string.
            --twaf:   Unescape str as an escaped URI component.
            return ngx_unescape_uri(value)
        end,
        uri_decode_uni = function(value)
            if _type(value) ~= "string" then return value end
            
            --modsec: Decodes a URL-encoded input string.
            --twaf:   Unescape str as an escaped URI component.
            return ngx_unescape_uri(value)
        end,
        uri_encode = function(value)
            if _type(value) ~= "string" then return value end
            
            --modsec: Encodes input string using URL encoding.
            --twaf:   Escape str as a URI component
            return ngx_escape_uri(value)
        end,
        utf8_to_unicode = function(value)
            if _type(value) ~= "string" then return value end
            if _type(_M.transforms_lib) ~= "userdata" then return value end
            
            local inp_len = #value
            local inp     = twaf_func.ffi_copy(value, inp_len)
            local outp    = ffi.new(ffi.typeof("char[?]"), inp_len * 7 + 1)
            local changed = ffi.new(ffi.typeof("char[?]"), 1)
            
            local outp_len = _M.transforms_lib.utf8_to_unicode(outp, inp, inp_len, changed)
            
            if (twaf_func.ffi_str(changed, 1) == "0") then
                return value
            end
            
            return twaf_func.ffi_str(outp, outp_len)
        end
    }
    
    if not func[options] then
        ngx_log(ngx_WARN, "Not support transform: ", options)
        return nil
    end
    
    return func[options](values)
end

return _M
