
-- Copyright (C) Miracle
-- Copyright (C) Titan, Co.Ltd.


local _M = {
    _VERSION = "0.01"
}

local cjson         = require "cjson.safe"
local twaf_func     = require "lib.twaf.inc.twaf_func"
local geoip_country = require "geoip.country"

local mt       = { __index = _M, }
local ngx_log  = ngx.log
local ngx_WARN = ngx.WARN

function _M.new(self)

    return setmetatable ({
        rules             = {},
        rules_id          = {},
        disable_rules_id  = {},
        global_conf_uuid  = "twaf_default_conf",
        twaf_default_conf = {},
        twaf_policy       = {}
    }, mt)
    
end

function _M.set_main_policy(self, value)
    self.global_conf_uuid = value
end

function _M.load_default_config(self, path)
    if path == nil then
        ngx_log(ngx_WARN, "no default config path")
        return
    end
    
    local d_file = io.open(path)
    if not d_file then return false end
    
    local default_conf_json = d_file:read("*a")
    d_file:close()
    
    self.twaf_default_conf = cjson.decode(default_conf_json) or {}
    
    -- access rule
    self.twaf_access_rule = twaf_func:copy_table(self.twaf_default_conf.twaf_access_rule)
    self.twaf_default_conf.twaf_access_rule = nil
end

local function _merge_table(self, path, modules_name)

    local f = io.open(path.."/"..modules_name..".json")
    local conf_json = f:read("*a")
    f:close()
    local conf = cjson.decode(conf_json)
    
    if type(conf[modules_name]) ~= "table" then
        return
    end
    
    if self[modules_name] == nil then
        self[modules_name] = {}
    end
    
    for key, value in pairs(conf[modules_name]) do
        self[modules_name][key] = value
    end
end

function _M.load_access_rule(self, path)
    _merge_table(self, path, "twaf_access_rule")
end

local function _load_policy_config(self, path, policy)
    if path == nil then
        return
    end
      
    self.twaf_policy[policy] = twaf_func:copy_table(self.twaf_default_conf)
    
    local p_file = io.open(path.."/"..policy..".json")
    local policy_conf_json = p_file:read("*a")
    p_file:close()
    local policy_conf = cjson.decode(policy_conf_json) or {}
    
    for modules, v in pairs(policy_conf) do
        if type(v) == "table" and #v == 0 then
            for key, value in pairs(v) do
                if self.twaf_policy[policy][modules] == nil then
                    self.twaf_policy[policy][modules] = {}
                end
                
                self.twaf_policy[policy][modules][key] = value
            end
        else
            self.twaf_policy[policy][modules] = v
        end
    end
    
end

function _M.load_policy_config(self, path, policy_uuids)
    self.twaf_policy.policy_uuids = policy_uuids
    for policy_uuid, _ in pairs(policy_uuids) do
        _load_policy_config(self, path, policy_uuid)
    end
end

-- 各文件rules合并
local function _rule_combine(tb1, tb2, f)

    if type(tb2) == "table" then
        for _, v in ipairs(tb2) do
            table.insert(tb1, v)
        end
        
        return
    end
    
    table.insert(tb1, f.DetectorInfo)
    
end

function _M.rule_group_phase(self, tb, rules)

    if not tb then
        tb = {}
    end

    if type(tb) ~= "table" then
        return
    end
    
    tb.access        = tb.access        or {}
    tb.header_filter = tb.header_filter or {}
    tb.body_filter   = tb.body_filter   or {}
    
    -- i: index, r: rule
    for i, r in ipairs(rules) do
        if type(r.phase) ~= "table" then
            table.insert(tb[r.phase], r)
        else
            for _, phase in pairs(r.phase) do
                table.insert(tb[phase], r)
            end
        end
    end
    
    return tb
end

local function _load_rules_lua(secrules, pre_path, path)
    local file = io.popen("ls "..pre_path..path.."/*.lua")
    if not file then return end
    
    local paths = file:read("*a")
    file:close()
    
    if type(paths) == "string" and #paths == 0 then
        return
    end
    
    paths = twaf_func:string_trim(paths)
    paths = twaf_func:string_ssplit(paths,string.char(10))
    
    for _, p in pairs(paths) do
        p = p:sub(#pre_path + 1, -5)
        local f = require(p)
        _rule_combine(secrules, f.rules, f)
    end
end

local function _load_rules_json(secrules, pre_path, path)
    local file = io.popen("ls "..pre_path..path.."/*.json")
    if not file then return end
    
    local paths = file:read("*a")
    file:close()
    
    if type(paths) == "string" and #paths == 0 then
        return
    end
    
    paths = twaf_func:string_trim(paths)
    paths = twaf_func:string_ssplit(paths,string.char(10))
    
    for _, path in pairs(paths) do
        local d_file = io.open(path)
        local rules = d_file:read("*a")
        d_file:close()
        
        rules = cjson.decode(rules)
        _rule_combine(secrules, rules)
    end
end

function _M.load_rules(self)

    local pre_path = self.twaf_default_conf.twaf_secrules.pre_path
    local path     = self.twaf_default_conf.twaf_secrules.path
    
    if not pre_path or not path then
        ngx_log(ngx_WARN, "the path of twaf rules is nil")
        return
    end
    
    local secrules = {}
    
    --TODO: 支持多级目录解析
    --load rules to self.rules
    _load_rules_json(secrules, pre_path, path)
    _load_rules_lua(secrules, pre_path, path)
    
    --check rules 检测失败应该drop process
    for _, r in ipairs(secrules) do
        local res = twaf_func:check_rules(self, r)
        if res == true then
            self.rules_id[r.id] = 1
        else
            r.disable = 1
            self.disable_rules_id[r.id] = 1
        end
    end
    
    --将所有规则划分phase
    _M:rule_group_phase(self.rules, secrules)
    
end

function _M.load_geoip_country_ipv4(self, path)
    local geodb_country_ipv4, err = geoip_country.open(path)
    if not geodb_country_ipv4 then
        ngx.log(ngx.WARN, err)
        self.geodb_country_ipv4 = nil
        return false
    end
    
    --test baidu: 111.13.101.208
    self.geodb_country_ipv4 = geoip_country.open(path)
end

function _M.load_geoip_country_ipv6(self, path)
    local geodb_country_ipv6, err = geoip_country.open(path)
    if not geodb_country_ipv6 then
        ngx.log(ngx.WARN, err)
        self.geodb_country_ipv6 = nil
        return false
    end
    
    --test google: 2404:6800:4005:809::2004
    self.geodb_country_ipv6 = geoip_country.open(path)
end

return _M
