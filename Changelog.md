Time: 2020/02/14  
Version: v1.0.0β  
功能变更：  
&emsp;&emsp;twaf_access_rule 接入规则模块：  
&emsp;&emsp;&emsp;&emsp;Add: 新增 [url_case_sensitive](https://github.com/titansec/OpenWAF#url_case_sensitive) 参数，用于判断路径 "path" 是否区分大小写(默认不区分大小写)  
&emsp;&emsp;&emsp;&emsp;Add: [host](https://github.com/titansec/OpenWAF#host) 参数与 [port](https://github.com/titansec/OpenWAF#port) 参数支持数组类型  
&emsp;&emsp;&emsp;&emsp;Add: [host](https://github.com/titansec/OpenWAF#host) 参数支持 IPv6  
&emsp;&emsp;&emsp;&emsp;Add: 接入规则 [POST](https://github.com/titansec/openwaf_api#access_rule_post) 和 [DELETE](https://github.com/titansec/openwaf_api#delete) 的 API 支持批量添加或批量删除接入规则  
&emsp;&emsp;&emsp;&emsp;Update: 接入规则 [PUT API](https://github.com/titansec/openwaf_api#put) <i><strong>功能从 修改部分配置 改为 全量(覆盖)修改配置</strong></i>  
&emsp;&emsp;&emsp;&emsp;Add: 新增接入规则的 [PATCH API](https://github.com/titansec/openwaf_api#access_rule_patch) 用于部分修改配置  

&emsp;&emsp;twaf_secrules 规则引擎模块：  
&emsp;&emsp;&emsp;&emsp;Add: 规则引擎中 opts 的 [ngx_var](https://github.com/titansec/OpenWAF#ngx_var) 支持动态变量  
&emsp;&emsp;&emsp;&emsp;Add: 规则引擎中 operators 的 [ip_utils](https://github.com/titansec/OpenWAF#ip_utils) 支持 IPv6  
&emsp;&emsp;&emsp;&emsp;Add: 添加规则集机制。可设置不同规则集，并在[策略中引用指定规则集](https://github.com/titansec/OpenWAF#ruleset_ids)。(策略未引用规则集，则默认加载所有规则生效，兼容了无规则集的旧版本)  
&emsp;&emsp;&emsp;&emsp;Add: 新增[规则集APIs](https://github.com/titansec/openwaf_api#rule_set)。包含增删改查。  

&emsp;&emsp;twaf_log 日志模块：  
&emsp;&emsp;&emsp;&emsp;Add: 日志支持[写入本地文件](https://github.com/titansec/OpenWAF#twaf_log)(同时支持原有tcp/udp外发)  

&emsp;&emsp;twaf_stat 统计模块：  
&emsp;&emsp;&emsp;&emsp;Update: 统计：支持[按关键字进行分类统计](https://github.com/titansec/OpenWAF#shared_dict_key-1)。  

&emsp;&emsp;twaf_api API模块：  
&emsp;&emsp;&emsp;&emsp;Add: 新增策略policy的[PATCH](https://github.com/titansec/openwaf_api#policy_patch)方法API，用于修改策略部分配置。  
&emsp;&emsp;&emsp;&emsp;Add: 新增 [errlog](https://github.com/titansec/openwaf_api#errlog) API，可通过调用API查询错误日志  
&emsp;&emsp;&emsp;&emsp;Add: 新增 [luajit](https://github.com/titansec/openwaf_api#luajit) API，便于判断环境是 lua 还是 luajit  
&emsp;&emsp;&emsp;&emsp;Add: 新增 [PSET(集合)](https://github.com/titansec/OpenWAF#pset)功能。可用于自定义"对象"  
&emsp;&emsp;&emsp;&emsp;Update: <i><strong>user_defined_rules 的 [POST](https://github.com/titansec/openwaf_api#user_defined_rules_post) API 不再支持 {index} 参数</strong></i>  

&emsp;&emsp;others：  
&emsp;&emsp;&emsp;&emsp;Update: 变量 UNIQUE_ID，默认34位自定义随机字符串 改为从 $request_id 变量获取的 16/32 位随机字符串  
&emsp;&emsp;&emsp;&emsp;Add: 默认添加了 X-Tt-Request-Id 响应头，其值等于 UNIQUE_ID 变量的值.  
&emsp;&emsp;&emsp;&emsp;Add: 可从X-Forwarded-For中获取真实来源IP。开启接入规则模块，此功能才生效。  
&emsp;&emsp;&emsp;&emsp;Fix: [warn] could not build optimal variables_hash。在nginx配置文件中放大variables_hash_max_size和variables_hash_bucket_size的值，解决此问题。  
&emsp;&emsp;&emsp;&emsp;Add: 新增响应体内容替换  
&emsp;&emsp;&emsp;&emsp;Add: OpenWAF 颁发的 cookie，默认追加 HttpOnly 属性。  
&emsp;&emsp;&emsp;&emsp;Add: 可用规则生成不同频率级别的 CC 防护  
&emsp;&emsp;&emsp;&emsp;Update: 自定义响应头支持配置动态变量  
&emsp;&emsp;&emsp;&emsp;Update: "redirect"重定向动作支持配置动态变量  

性能提升：  
&emsp;&emsp;Update: 变量，按需自动加载所需变量。不必每个请求都加载所有变量  
&emsp;&emsp;Add: 配置初始化。无需在请求过程中处理不必要的配置校验及转换。  
&emsp;&emsp;Add: 基于配置初始化，规则引擎设置二级缓存(变量缓存级transform结果缓存)  
&emsp;&emsp;Add: 基于配置初始化，接入规则设置二级缓存，实现快速匹配(由原来的顺序匹配O(N)，改为缓存定位O(1))  

PS: 从低版本升级至 v1.0.0β 版本：  
&emsp;&emsp;1. 所有 Add 新增，向下兼容，不影响原有配置功能。  
&emsp;&emsp;2. Update 更新基本做到向下兼容，不影响原有配置。可能会有影响的，字体已加粗且斜体  

Time: 2017/12/26  
Version: v0.0.6  
&emsp;&emsp;Access_rule module :  
&emsp;&emsp;&emsp;&emsp;fix : 'host' not ignore case  
    
&emsp;&emsp;Log module :  
&emsp;&emsp;&emsp;&emsp;add directive : 'size_limit'  
    
&emsp;&emsp;Api module :  
&emsp;&emsp;&emsp;&emsp;upload API module  
&emsp;&emsp;&emsp;&emsp;fix : failed to request api  
    
&emsp;&emsp;Anti_mal_crawler module :  
&emsp;&emsp;&emsp;&emsp;fix : mistakenly identified as crawler  
&emsp;&emsp;&emsp;&emsp;add directive : 'dict_state'  
    
&emsp;&emsp;Anti_cc module :  
&emsp;&emsp;&emsp;&emsp;fix : no log in CC protection period  
&emsp;&emsp;&emsp;&emsp;add directive : 'attacks'   
    
&emsp;&emsp;Secrules module :  
&emsp;&emsp;&emsp;&emsp;add action : 'WARN'  
&emsp;&emsp;&emsp;&emsp;add action : 'AUDIT'  
&emsp;&emsp;&emsp;&emsp;add action : 'ALLOW_PHASE'  
&emsp;&emsp;&emsp;&emsp;add directive : 'system_rules_state'  
&emsp;&emsp;&emsp;&emsp;add directive : 'recommend' in rules  
&emsp;&emsp;&emsp;&emsp;add directive : 'add_resp_headers' in rules  
&emsp;&emsp;&emsp;&emsp;fix : 'meta' not work when action is 'DENY'  
&emsp;&emsp;&emsp;&emsp;change the order of system_rule and user_defined_rules  
    
&emsp;&emsp;Others :  
&emsp;&emsp;&emsp;&emsp;upload doc : 轻松玩转OpenWAF之ELK  
&emsp;&emsp;&emsp;&emsp;upload doc : 深入研究OpenWAF之nginx配置  
&emsp;&emsp;&emsp;&emsp;upload doc : 轻松玩转OpenWAF之安装篇  
&emsp;&emsp;&emsp;&emsp;upload donation  
&emsp;&emsp;&emsp;&emsp;support waf bypass  
&emsp;&emsp;&emsp;&emsp;fix : return 500, ngx.req.raw_header() not support HTTP/2  
&emsp;&emsp;&emsp;&emsp;create CODE_OF_CONDUCT.md  
&emsp;&emsp;&emsp;&emsp;create CONTRIBUTING.md  
&emsp;&emsp;&emsp;&emsp;update docker version to 0.0.6  
    
&emsp;&emsp;New Release : 0.0.6  
    
Time: 2017/04/10  
Version: v0.0.5  
&emsp;&emsp;1. Rules  
&emsp;&emsp;&emsp;&emsp;Delete 30 rules which severity is "low".  
&emsp;&emsp;2. fix  
&emsp;&emsp;&emsp;&emsp;Failed to install on Ubuntu: undefined symbol GeoIP_continent_by_id  
&emsp;&emsp;3. Update docker version to 0.0.5  
&emsp;&emsp;4. New Release - 0.0.5  
    
Time: 2017/03/20  
Version: v0.0.4  
&emsp;&emsp;1. New Module - twaf_anti_cc  
&emsp;&emsp;&emsp;&emsp;Anti http flood  
&emsp;&emsp;2. Performance optimization  
&emsp;&emsp;&emsp;&emsp;optimaize RESPONSE_BODY variable to reduce memory  
&emsp;&emsp;3. add QQ group  
&emsp;&emsp;&emsp;&emsp;QQ group: 579790127  
&emsp;&emsp;4. fix  
&emsp;&emsp;&emsp;&emsp;4.1 loading error -- wrong comment  
&emsp;&emsp;&emsp;&emsp;4.2 return 500 response code -- string.char not support GBK  
&emsp;&emsp;5. Update docker version  
&emsp;&emsp;6. New Release - 0.0.4  
    
Time: 2017/01/03  
Version: v0.0.3.170103_beta  
&emsp;&emsp;1. New Module - twaf_anti_mal_crawler  
&emsp;&emsp;&emsp;&emsp;Distinguish malicious crawler and some scan tools  
    
Time: 2016/12/05  
Version: v0.0.2.161205_beta  
&emsp;&emsp;1. New Module - twaf_attack_response  
&emsp;&emsp;&emsp;&emsp;Return custom response page When the request is rejected by OpenWAF  
&emsp;&emsp;2. Api - api/stat[/policy_uuid]  
&emsp;&emsp;&emsp;&emsp;Show statistical infomation  
    
Time: 2016/12/05  
Version: v0.0.1.161130_beta  
&emsp;&emsp;1. Docker  
&emsp;&emsp;&emsp;&emsp;build OpenWAF with docker  
    
Time: 2016/12/05  
Version: v0.0.1.161012_beta  
&emsp;&emsp;1. log module  
&emsp;&emsp;&emsp;&emsp;Send tcp/udp log  
&emsp;&emsp;2. reqstat module  
&emsp;&emsp;&emsp;&emsp;Statistics of request infomation  
&emsp;&emsp;3. access rule  
&emsp;&emsp;&emsp;&emsp;Publish applications  
&emsp;&emsp;4. rule engine  
&emsp;&emsp;&emsp;&emsp;Access Control  
    