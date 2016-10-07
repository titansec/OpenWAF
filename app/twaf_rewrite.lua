local cjson = require "cjson.safe"
local gcf   = twaf:get_config_param("twaf_global")
local dict  = ngx.shared[gcf.dict_name]
local wid   = ngx.worker.id()
local wpid  = ngx.worker.pid()
--ngx.log(ngx.ERR, dict:get("worker_process_"..wid))

local res = dict:get("worker_process_"..wid)

if res and res ~= true and res ~= wpid then
    res = true
end

if res == true then
    ngx.log(ngx.ERR, "rewrite: config synchronization ing..")
    local worker_config = dict:get("worker_config")
    worker_config = cjson.decode(worker_config)
    local phase = {"access", "header_filter", "body_filter"}
    
    if worker_config and worker_config.rules then
        for _, rule in ipairs(worker_config.rules) do
            if not rule.match then
            
                local phase = {"access", "header_filter", "body_filter"}
                
                for _, p in ipairs(phase) do
                    if rule[p] then
                        rule[p] = load(rule[p])
                    end
                end
            end
        end
    end
    
    if worker_config then
    
        -- 系统规则
        if worker_config.rules then
            for phase, rules in pairs(worker_config.rules) do
                for _, rule in ipairs(rules) do
                    if not rule.match then
                        for _, p in ipairs(phase) do
                            if rule[p] then
                                rule[p] = load(rule[p])
                            end
                        end
                    end
                end
            end
        end
        
        -- 用户自定义规则
        if worker_config.twaf_policy and worker_config.twaf_policy.policy_uuids then
            for uuid, _ in pairs(worker_config.twaf_policy.policy_uuids) do
                local policy = worker_config.twaf_policy[uuid]
                if policy and policy.twaf_secrules then
                    local rules = policy.twaf_secrules.user_defined_rules
                    for _, rule in ipairs(rules or {}) do
                        if not rule.match then
                            for _, p in ipairs(phase) do
                                if rule[p] then
                                    rule[p] = load(rule[p])
                                end
                            end
                        end
                    end
                end
            end
        end
    
        for k, v in pairs(worker_config) do
            if type(twaf.config[k]) == "userdata" then
                worker_config[k] = twaf.config[k]
            end
        end
        
        twaf.config = worker_config
    end
    
    dict:set("worker_process_"..wid, wpid)
end

twaf.modfactory.twaf_access_rule:handler(twaf)
