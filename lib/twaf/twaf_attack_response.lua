
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "0.0.1"
}

local cjson                = require "cjson"
local twaf_func            = require "lib.twaf.inc.twaf_func"

local modules_name         = "twaf_attack_response"
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
    
function _M.header_filter(self, _twaf)

    local tctx = _twaf:ctx()
    if not tctx then
        return true
    end
    
    local cf  = _twaf:get_config_param(modules_name)
    local gcf = _twaf:get_config_param("twaf_global")
    if not cf or not gcf then
        return true
    end
    
    if twaf_func:state(cf.state)       == false or
       twaf_func:state(gcf.simulation) == true  then
        return true
    end
    
	local modsec_notes = ngx_var.modsec_notes
	local attack_info  = ngx_var.twaf_attack_info
    
	if not modsec_notes and (not attack_info or #attack_info == 0) then
		return true
	end
    
    if not tctx[modules_name] then
        tctx[modules_name] = {}
    end
    
    tctx[modules_name]["state"] = true
    tctx[modules_name]["gcf"]   = gcf
    tctx[modules_name]["cf"]    = cf
    
    local content_length = ngx_header['Content-Length']
    if content_length then
        ngx_header['Content-Length'] = nil
    end
    
    return true
end

function _M.body_filter(self, _twaf)

    local tctx = _twaf:ctx() or {}
    local ctx  =  tctx[modules_name]
    if not ctx or not ctx.state then
        return true
    end
    
	local attack_info  = ngx_var.twaf_attack_info
	if ngx.arg[2] ~= true then
        ngx.arg[1] = nil
        return
    end
    
    local cf  = ctx.cf
	local buf = cf.format
	
	if buf ~= nil then
	    local file = io.open(buf)
        buf = file:read("*a")
	    file:close()
	end
    
    local format_args      = {}
    local request          = tctx.request
    
    local func = function(m)
        return request[m] or format_args[m] or "-"
    end
    
    if twaf_func:state(cf.detail_state) == false then
		if buf == nil then
		    buf = response1
		end
        
        buf = buf:gsub("{{(.-)}}", func)
		ngx.arg[1] = buf
        return
    end
    
	format_args["category"]  = ""
    
	if #attack_info ~= 0 then
        local a = twaf_func:string_split(attack_info, ";")
        for _, v in pairs(a) do
            if not format_args["category"]:find(v) then
                format_args["category"] = format_args["category"] .. v .. ";"
            end
        end
	end
    
	format_args["category"] = format_args["category"]:sub(1, -2)
    
	if buf ~= nil then
	    if type(cf.format_args_add) == "table" then
	        for k, v in pairs(cf.format_args_add) do
		        format_args[k] = v
            end
        end
    else
	    buf = response2
	end
    
    buf = buf:gsub("{{(.-)}}", func)
    
    ngx.arg[1] = buf
end

return _M