
-- Copyright (C) Miracle
-- Copyright (C) OpenWAF

local _M = {
    _VERSION = "1.1.1"
}

local cjson         = require "cjson"
local twaf_func     = require "lib.twaf.inc.twaf_func"
local geoip_country = require "geoip.country"

local mt            = { __index = _M, }
local ngx_log       = ngx.log
local ngx_WARN      = ngx.WARN
local io_open       = io.open
local io_popen      = io.popen
local table_insert  = table.insert
local string_char   = string.char
local string_format = string.format
local _type         = type

function _M.new(self)

    return setmetatable ({
        rules             = {},
        rules_id          = {},
        rule_sets         = {},
        disable_rules_id  = {},
        global_conf_uuid  = "twaf_default_conf",
        twaf_default_conf = {},
        twaf_policy       = {},
        pset              = {}
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
    
    local d_file = io_open(path)
    if not d_file then return false end
    
    local default_conf_json = d_file:read("*a")
    d_file:close()
    
    self.twaf_default_conf = cjson.decode(default_conf_json)
    
    -- access rule
    self.twaf_access_rule = twaf_func:copy_table(self.twaf_default_conf.twaf_access_rule)
    self.twaf_default_conf.twaf_access_rule = nil
    
    -- rules or modules category
    local twaf_global = self.twaf_default_conf.twaf_global
    local f = io_open(twaf_global.category_path)
    local category = f:read("*a")
    f:close()
    category = cjson.decode(category)
    self.category_map = category
end

local function _merge_table(self, path, modules_name)

    local f = io_open(path)
    local conf_json = f:read("*a")
    f:close()
    local conf = cjson.decode(conf_json)
    
    if _type(conf[modules_name]) ~= "table" then
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
    
    local p_file = io_open(string_format("%s/%s.json", path, policy))
    local policy_conf_json = p_file:read("*a")
    p_file:close()
    local policy_conf = cjson.decode(policy_conf_json) or {}
    
    for modules, v in pairs(policy_conf) do
        if _type(v) == "table" and #v == 0 then
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

-- merge lua rule file (only one rule in a file)
local function _rule_combine(tb1, tb2, f)

    if _type(tb2) == "table" then
        for _, v in ipairs(tb2) do
            table_insert(tb1, v)
        end
        
        return
    end
    
    table_insert(tb1, f.DetectorInfo)
    
end

function _M.rule_group_phase_by_list(self, tb, rules)

    if not tb then
        tb = {}
    end

    if _type(tb) ~= "table" then
        return
    end
    
    tb.access        = tb.access        or {}
    tb.header_filter = tb.header_filter or {}
    tb.body_filter   = tb.body_filter   or {}
    
    -- i: index, r: rule
    for i, r in ipairs(rules) do
        table_insert(tb[r.phase], r)
    end
    
    return tb
end

function _M.rule_group_phase(self, rules, rules_order)

    local tb = {}
    
    tb.access        = {}
    tb.header_filter = {}
    tb.body_filter   = {}
    
    for _, rid in ipairs(rules_order) do
        table_insert(tb[rules[rid].phase], rid)
    end
    
    return tb
end

local function _load_rules_lua(secrules, pre_path, path)
    local file = io_popen(string_format("ls %s%s/*.lua 2>/dev/null", pre_path, path))
    if not file then return end
    
    local paths = file:read("*a")
    file:close()
    
    if _type(paths) == "string" and #paths == 0 then
        return
    end
    
    paths = twaf_func:string_trim(paths)
    paths = twaf_func:string_ssplit(paths,string_char(10))
    
    for _, p in pairs(paths) do
        p = p:sub(#pre_path + 1, -5)
        local f = require(p)
        _rule_combine(secrules, f.rules, f)
    end
end

local function _load_rules_json(secrules, pre_path, path)
    local file = io_popen(string_format("ls %s%s/*.json 2>/dev/null", pre_path, path))
    if not file then return end
    
    local paths = file:read("*a")
    file:close()
    
    if _type(paths) == "string" and #paths == 0 then
        return
    end
    
    paths = twaf_func:string_trim(paths)
    paths = twaf_func:string_ssplit(paths,string_char(10))
    
    for _, path in pairs(paths) do
        local d_file = io_open(path)
        local rules = d_file:read("*a")
        d_file:close()
        
        rules = cjson.decode(rules)
        _rule_combine(secrules, rules)
    end
end

function _M.load_rules(self, flag)

    local pre_path = self.twaf_default_conf.twaf_secrules.pre_path
    local path     = self.twaf_default_conf.twaf_secrules.path
    
    if not pre_path or not path then
        ngx_log(ngx_WARN, "the path of twaf rules is nil")
        return false, "the path of twaf rules is nil"
    end
    
    local secrules = {}
    local rules = {}
    local rules_order = {}
    
    --TODO: Support multi-level directory parsing
    --load rules to self.rules
    _load_rules_json(secrules, pre_path, path)
    _load_rules_lua(secrules, pre_path, path)
    
    --check rules 
    --if check failed, drop process
    local reason = {}
    for _, r in ipairs(secrules) do
        local res, err = twaf_func:check_rules(self.rules_id, r)
        if res == true then
            self.rules_id[r.id] = r.phase
            rules[r.id] = r
            table_insert(rules_order, r.id)
        else
            table_insert(reason, err)
        end
    end
    
    if #reason > 0 then
        if not flag then
            error(twaf_func:table_to_string(reason))
        end
        return false, reason
    end
    
    self.rules = rules
    self.rule_sets.twaf_default_rule_set = _M:rule_group_phase(rules, rules_order)
    
    return true
end

function _M.load_geoip_country_ipv4(self, path)
    local geodb_country_ipv4, err = geoip_country.open(path)
    if not geodb_country_ipv4 then
        ngx_log(ngx_WARN, err)
        self.geodb_country_ipv4 = nil
        return false
    end
    
    --test baidu: 111.13.101.208
    self.geodb_country_ipv4 = geoip_country.open(path)
end

function _M.load_geoip_country_ipv6(self, path)
    local geodb_country_ipv6, err = geoip_country.open(path)
    if not geodb_country_ipv6 then
        ngx_log(ngx_WARN, err)
        self.geodb_country_ipv6 = nil
        return false
    end
    
    --test google: 2404:6800:4005:809::2004
    self.geodb_country_ipv6 = geoip_country.open(path)
end

return _M
