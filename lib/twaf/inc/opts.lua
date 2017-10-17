
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.2"
}

local http_cache = require "http_cache"
local twaf_func  = require "lib.twaf.inc.twaf_func"

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

function _M.opts(self, _twaf, ctx, sctx, request, options, values)
    local func = {
        nolog  = function(_twaf, values, ctx, request)
        end,
        setvar = function(_twaf, values, ctx, request)
            for k, v in ipairs(values) do
                local value = twaf_func:parse_dynamic_value(v.value, request)
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
        proxy_cache = function(_twaf, values, ctx, request, sctx)
            
            if sctx.cache_down == nil then sctx.cache_down = {} end
            
            if type(values) ~= "table" or sctx.cache_down[sctx.id or "-"] then return end
            
            sctx.cache_down[sctx.id or "-"] = true
            
            local cache_status = request.UPSTREAM_CACHE_STATUS or ""
            
            if cache_status == "MISS" or cache_status == "EXPIRED" then
                local cache_data = http_cache.get_metadata()

                if cache_data and cache_data.valid_sec then
                    local new_expire = request.TIME_EPOCH + (values.expired or 600)
                    local cache_meta = {}
                    cache_meta.fcn   = {}
                    
                    cache_meta.valid_sec     = new_expire
                    cache_meta.fcn.valid_sec = new_expire
                    cache_meta.fcn.expire    = new_expire
                    cache_meta.min_uses      = values.min_uses or 3
                    
                    http_cache.set_metadata(cache_meta)
                end
            end
        end
    }
    
    return func[options](_twaf, values, ctx, request, sctx)
end

return _M
