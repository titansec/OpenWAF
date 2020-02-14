
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.0.0"
}

local cjson                = require "cjson"
local twaf_func            = require "lib.twaf.inc.twaf_func"

local modules_name         = "twaf_attack_response"
local _type                = type
local io_open              = io.open
local string_format        = string.format
local ngx_log              = ngx.log
local ngx_ERR              = ngx.ERR
local ngx_var              = ngx.var
local ngx_re_find          = ngx.re.find
local ngx_header           = ngx.header

local response1 = 
   '<html> \
      <head> \
        <meta http-equiv="content-type" content="text/html;charset=utf-8"> \
      </head> \
      <body link="#0000cc" style="margin-top:80px;"> \
        <div class="norsSuggest" style="margin: 0px auto; width: 650px;"> \
	      <div style="float:left;height:200px;padding:45px 0;"> \
            <div style="border-radius:5em;width:120px;height:120px; \
			  background-color:#FF0000;border:2px solid #FF0000; \
			  text-align:center;line-height:120px;box-shadow:0 2px 10px #000000;"> \
              <span style="font-size:120px;color:#FFFFFF;">X</span> \
            </div> \
	      </div> \
	      <div style="float: left; padding: 0px 20px; height:200px;"> \
            <h3>非法的访问</h3> \
		    <span>您的访问已被识别为攻击并记录. </span> <br> \
		    <span>如有任何意见或建议，请及时与管理员联系</span> <br> \
			<p >温馨提示：</p> \
            <ol> \
			  <li>请勿非法请求</li> \
              <li>请检查您访问的URL是否正确</li> \
			  <li>您访问的URL地址可能不被允许</li> \
              <li>UNIQUE_ID: {{UNIQUE_ID}}</li> \
            </ol> \
          </div> \
	    </div> \
        <div style="clear:float;clear:both;"></div> \
        <div style="width:1000px;margin:0 auto;"> \
      </body> \
	</html>'

local response2 = 
   '<html> \
      <head> \
        <meta http-equiv="content-type" content="text/html;charset=utf-8"> \
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" /> \
      </head> \
      <body link="#0000cc" style="margin-top:80px;"> \
        <div class="norsSuggest" style="margin: 0px auto; width: 650px;"> \
	      <div style="float:left;height:200px;padding:45px 0;"> \
            <div style="border-radius:5em;width:120px;height:120px; \
			  background-color:#FF0000;border:2px solid #FF0000; \
			  text-align:center;line-height:120px;box-shadow:0 2px 10px #000000;"> \
              <span style="font-size:120px;color:#FFFFFF;font-family:verdana;">X</span> \
            </div> \
	      </div> \
	      <div style="float: left; padding: 0px 20px; height:200px;"> \
            <h3>非法的访问</h3> \
		    <span>您的访问已被识别为攻击并记录. </span> <br> \
		    <span>如有任何意见或建议，请及时与管理员联系</span> <br> <br> \
	        <span>客户端地址: {{REMOTE_ADDR}}</span> <br> \
		    <span>访问的URL: {{URL}}</span> <br> \
            <span>触发的事件类型: {{category}}</span> <br> \
            <span>UNIQUE_ID: {{UNIQUE_ID}}</span> <br> \
          </div> \
	    </div> \
        <div style="clear:float;clear:both;"></div> \
        <div style="width:1000px;margin:0 auto;"> \
      </body> \
	</html>'

local function _attack_category()
    local category     = ""
    local attack_info  = ngx_var.twaf_attack_info or ""
    
	if #attack_info ~= 0 then
        local tb = twaf_func:string_split(attack_info, ";")
        for _, v in pairs(tb) do
            if not category:find(v) then
                category = string_format("%s%s;", category, v)
            end
        end
        
        category = category:sub(1, -2)
	end
    
    return category
end

local function _pre_resp_body(tctx, cf)

	local buf         = cf.format
    local format_args = {}
    local req         = tctx.req
    
    local args = function(m)
        return twaf:get_vars(m, req) or format_args[m] or "-"
    end
	
	if buf ~= nil then
	    local f = io_open(buf)
        if f then
            buf = f:read("*a")
            f:close()
        else
            ngx_log(ngx_ERR, string_format("open '%s' failed in attack response module", buf))
            buf = nil
        end
	end
    
    if twaf_func:state(cf.detail_state) == false then
		if buf == nil then buf = response1 end
        buf = buf:gsub("{{(.-)}}", args)
        return buf
    end
    
	format_args["category"]  = _attack_category()
    
	if buf ~= nil then
	    if _type(cf.format_args_add) == "table" then
	        for k, v in pairs(cf.format_args_add) do
		        format_args[k] = v
            end
        end
    else
	    buf = response2
	end
    
    buf = buf:gsub("{{(.-)}}", args)
    
    return buf
end
    
function _M.header_filter(self, _twaf)

    local tctx = _twaf:ctx()
    if not tctx then return true end
    
    local cf  = _twaf:get_config_param(modules_name)
    local gcf = _twaf:get_config_param("twaf_global")
    if not cf or not gcf then return true end
    
    if twaf_func:state(cf.state)       == false or
       twaf_func:state(gcf.simulation) == true  then
        return true
    end
    
    local attack_info  = ngx_var.twaf_attack_info
    if not attack_info or #attack_info == 0 then
        return true
    end
    
    if not tctx[modules_name] then tctx[modules_name] = {} end
    local buf = _pre_resp_body(tctx, cf)
    
    ngx_header['Content-Type']   = "text/html"
    ngx_header['Content-Length'] = #buf
    tctx[modules_name]["buf"]    = buf
    tctx[modules_name]["cf"]     = cf
    
    return true
end

function _M.body_filter(self, _twaf)

    local tctx = _twaf:ctx() or {}
    
    if not tctx[modules_name] and ngx_var.header_filter_postpone == '1' then
        _M:header_filter(_twaf)
    end
    
    ctx = tctx[modules_name]
    
    if not ctx then return true end
    
    ngx.arg[1] = ctx.buf
    ngx.arg[2] = true
    return
end

return _M