
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local http_cache = require "http_cache"

function _M.parse_dynamic_value(self, key, request)
	local lookup = function(m)
		local val      = request[m[1]:upper()]
		local specific = m[2]

		if (not val) then
            return "-"
		end

		if (type(val) == "table") then
			if (specific) then
				return tostring(val[specific])
			else
				return tostring(m[1])
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
    
	if (ngx.re.find(str, [=[^\d+$]=], "oij")) then
		return tonumber(str)
	else
		return str
	end
end

local function _set_var(ctx, element, value)

    local col     = string.upper(element.column)
	local key     = element.key
	local incr    = element.incr
	local storage = ctx.storage
    
    if col == "TX" then
        storage = ctx
    end
    
    if not storage[col] then
        storage[col] = {}
    end

	if (incr) then
		local existing = storage[col][key]
        
		if (existing and type(existing) ~= "number") then
		elseif (not existing) then
			existing = 0
		end
        
		if (type(value) == "number") then
			value = value + existing
		else
			value = existing
		end
	end
    
	storage[col][key] = value
end

function _M.opts(self, _twaf, ctx, request, options, values)
    local func = {
        nolog  = function(_twaf, values, ctx, request)
        end,
        setvar = function(_twaf, values, ctx, request)
            for k, v in ipairs(values) do
                local value = _M:parse_dynamic_value(v.value, request)
                _set_var(ctx, v, value)
            end
        end,
        expirevar = function(_twaf, values, ctx, request)
            for k, v in ipairs(values) do
                _set_var(ctx, v, v.time + ngx.time())
            end
        end,
        sanitise_arg = function(_twaf, values, ctx, request)
            local tb = {}
            local uri_args = request.ARGS_GET
            
            if type(values) == "table" then
                for _, v in pairs(values) do
                    if uri_args[v] then
                        table.insert(tb, v)
                    end
                end
            else
                if uri_args[values] then
                    table.insert(tb, values)
                end
            end
            
            ctx.sanitise_uri_args = tb
        end,
        add_resp_headers = function(_twaf, values, ctx, request)
        
            if type(values) ~= "table" then
                return
            end
        
            ctx.add_resp_headers = ctx.add_resp_headers or {}
            
            for k, v in pairs(values) do
                ctx.add_resp_headers[k] = v
            end
        end,
        proxy_cache = function(_twaf, values, ctx, request)
            
            if type(values) ~= "table" or ctx.cache_down then
                return
            end
            
            ctx.cache_down = true
            
            local cache_status = request.UPSTREAM_CACHE_STATUS or ""
            local cache_data   = http_cache.get_metadata()
            
            if not values.state then
                http_cache.purge()
                return
            end
            
            if cache_status == "MISS" or cache_status == "EXPIRED" then

                if cache_data and cache_data.valid_sec then
                    local new_expire = request.TIME_EPOCH + (values.expired or 600)
                    local cache_meta = {}
                    cache_data.fcn   = {}
                    
                    ngx.var.twaf_cache_flag  = 0
                    cache_meta.valid_sec     = new_expire
                    cache_data.fcn.valid_sec = new_expire
                    cache_data.fcn.expire    = new_expire
                    
                    http_cache.set_metadata(cache_meta)
                end
            end
        end
    }
    
    return func[options](_twaf, values, ctx, request)
end

return _M
