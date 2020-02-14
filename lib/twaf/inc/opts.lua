
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.5"
}

local http_cache   = require "http_cache"
local twaf_func    = require "lib.twaf.inc.twaf_func"

local ngx_log      = ngx.log
local ngx_WARN     = ngx.WARN
local string_upper = string.upper
local table_insert = table.insert
local _type        = type

local function _set_var(ctx, element, value, req)

    local  col     = string_upper(element.column)
    local  key     = element.key
    local  incr    = element.incr
    local _time    = element.time
    local  storage = ctx.storage
    local  dict    = req[col]
    
    if _time then
    
        if not dict then return end
        
        key = (element.shm_key or dict:get("default_key") or "")..key
        key = twaf_func:parse_dynamic_value(key, req)
        
        dict:add(key, 0, _time)
        
        if incr then
            dict:incr(key, value)
        else
            dict:set(key, value)
        end
        
        return
    end
    
    if col == "TX" then
        storage = req
    end
    
    if not storage[col] then
        storage[col] = {}
    end

	if (incr) then
		local existing = storage[col][key]
        
		if (existing and _type(existing) ~= "number") then
		elseif (not existing) then
			existing = 0
		end
        
		if (_type(value) == "number") then
			value = value + existing
		else
			value = existing
		end
	end
    
	storage[col][key] = value
end

function _M.opts(self, _twaf, ctx, sctx, req, options, values)
    local func = {
        nolog  = function()
        end,
        setvar = function(_twaf, values, ctx, req)
            for k, v in ipairs(values) do
                local value = twaf_func:parse_dynamic_value(v.value, req)
                _set_var(ctx, v, value, req)
            end
        end,
        sanitise_arg = function(_twaf, values, ctx, req)
            local tb = {}
            local uri_args = _twaf:get_vars("ARGS_GET", req)
            
            if _type(values) == "table" then
                for _, v in pairs(values) do
                    if uri_args[v] then
                        table_insert(tb, v)
                    end
                end
            else
                if uri_args[values] then
                    table_insert(tb, values)
                end
            end
            
            ctx.sanitise_uri_args = tb
        end,
        add_resp_headers = function(_twaf, values, ctx)
        
            if _type(values) ~= "table" then
                return
            end
        
            ctx.add_resp_headers = ctx.add_resp_headers or {}
            
            for k, v in pairs(values) do
                ctx.add_resp_headers[k] = v
            end
        end,
        proxy_cache = function(_twaf, values, ctx, req, sctx)
            
            if sctx.cache_down == nil then sctx.cache_down = {} end
            
            if _type(values) ~= "table" or sctx.cache_down[sctx.id or "-"] then return end
            
            sctx.cache_down[sctx.id or "-"] = true
            
            local cache_status = _twaf:get_vars("UPSTREAM_CACHE_STATUS", req) or ""
            
            if cache_status == "MISS" or cache_status == "EXPIRED" then
                local cache_data = http_cache.get_metadata()

                if cache_data and cache_data.valid_sec then
                    local new_expire = _twaf:get_vars("TIME_EPOCH", req) + (values.expired or 600)
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
    
    if not func[options] then
        ngx_log(ngx_WARN, "Not support option: ", options)
        return nil
    end
    
    return func[options](_twaf, values, ctx, req, sctx)
end

return _M
