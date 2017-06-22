名称
====

此文档将详细描述 OpenWAF 的 nginx 配置文件 /etc/ngx_openwaf.conf 中每一项配置

以及接入规则（access_rule）与 nginx 配置的关联

Table of Contents
=================

* [twaf_main](#twaf_main)
    * [twaf_init](#twaf_init)
* [twaf_api](#twaf_api)
* [twaf_server](#twaf_server)
    * [twaf_access_rule](#twaf_access_rule)

nginx配置
=========

```nginx
http {
    include            /opt/OpenWAF/conf/twaf_main.conf;    # 加载策略配置，规则，功能模块
    include            /opt/OpenWAF/conf/twaf_api.conf;     # api，动态配置接入规则，动态配置规则，动态配置策略，查看统计信息等

    upstream test {
       server 0.0.0.1; #just an invalid address as a place holder
       balancer_by_lua_file /opt/OpenWAF/app/twaf_balancer.lua;
    }
    
    server {
        listen 443 ssl;
        server_name _;
        
        ssl_certificate /opt/OpenWAF/conf/ssl/nginx.crt;
        ssl_certificate_key /opt/OpenWAF/conf/ssl/nginx.key;
        ssl_protocols TLSv1.1 TLSv1.2;
        
        include                     /opt/OpenWAF/conf/twaf_server.conf;
        ssl_certificate_by_lua_file /opt/OpenWAF/app/twaf_ssl_cert.lua;
        
        location / {
            proxy_pass $twaf_upstream_server;
        }
    }
    
    server {
        listen       80;
        server_name  _;
        include      /opt/OpenWAF/conf/twaf_server.conf;

        location / {
            proxy_pass $twaf_upstream_server;
        }
    }
}
```

twaf_main
---------

```nginx
#twaf_main.conf 文件

#申请共享内存
lua_shared_dict twaf_shm                  50m;
lua_shared_dict twaf_limit_conn           5m;
lua_shared_dict twaf_reqstat              1m;

lua_package_path        "/opt/OpenWAF/?.lua;;";            #指定 OpenWAF 安装路径
init_by_lua_file         /opt/OpenWAF/app/twaf_init.lua;   #加载策略配置，加载特征规则，加载功能模块
```

若想添加新的共享内存，在 twaf_main.conf 中添加，如：lua_shared_dict  twaf_test  1m;  

### twaf_init

```lua
-- twaf_init.lua 文件

require "resty.core"

--加载静态配置
local twaf_config_m = require "lib.twaf.twaf_conf"
local twaf_config = twaf_config_m:new()
twaf_config:load_default_config("/opt/OpenWAF/conf/twaf_default_conf.json")  -- 加载缺省策略
twaf_config:load_access_rule("/opt/OpenWAF/conf/twaf_access_rule.json")      -- 加载接入规则
twaf_config:load_policy_config("/opt/OpenWAF/conf", {twaf_policy_conf = 1})  -- 加载策略，想扩展策略，可在此加载新的策略
twaf_config:load_rules()                                                     -- 加载规则

-- GeoIP ,想扩展城市级别GEOIP，可在此扩展
twaf_config:load_geoip_country_ipv4("/opt/OpenWAF/lib/twaf/inc/knowledge_db/geo_country/GeoIP.dat")    -- 加载国家级别 GeoIPv4
twaf_config:load_geoip_country_ipv6("/opt/OpenWAF/lib/twaf/inc/knowledge_db/geo_country/GeoIPv6.dat")  -- 加载国家级别 GEOIPv6

-- 加载 OpenWAF 自带的统计模块
local twaf_reqstat_m = require "lib.twaf.twaf_reqstat"
twaf_reqstat = twaf_reqstat_m:new(twaf_config.twaf_default_conf.twaf_reqstat, twaf_config.twaf_policy.policy_uuids)

local twaf_lib = require "lib.twaf.twaf_core"
twaf = twaf_lib:new(twaf_config)

--加载各功能模块
local default_init_register = twaf:get_default_config_param("init_register")
twaf:register_modules(default_init_register)
```

添加新的策略，在 twaf_init.lua 中加载  
```txt
    1. 添加 /opt/OpenWAF/conf 目录下，policy1.json 和 policy2.json 策略  
        twaf_config:load_policy_config("/opt/OpenWAF/conf", {policy1 = 1, policy2 = 1})  
        
    2. 添加 /etc/a/policy1.json 策略和 /etc/b/policy2.json 策略  
        twaf_config:load_policy_config("/etc/a", {policy1 = 1})  
        twaf_config:load_policy_config("/etc/b", {policy2 = 1})  
```
        
twaf_api
========

```nginx
server {
    listen 127.0.0.1:61111;    #监听地址
    server_name nosuchdomain;
    access_log off;

    location / {
        stub_status on;
        allow 127.0.0.0/8;
        deny all;
    }

    location /api {
        content_by_lua_file /opt/OpenWAF/app/twaf_api.lua;    #api，动态配置接入规则，动态配置规则，动态配置策略，查看统计信息等
        allow 127.0.0.0/8;
        deny all;
    }
}
```

如查看全局统计信息: 'curl http://127.0.0.1:61111/api/stat'

更多信息，请详看 [twaf_api](https://github.com/titansec/openwaf_api) 模块

twaf_server
===========

```nginx
#twaf_server.conf
rewrite_by_lua_file       /opt/OpenWAF/app/twaf_rewrite.lua;         # rewrite 阶段有接入规则模块
access_by_lua_file        /opt/OpenWAF/app/twaf_access.lua;          # 处理请求头，请求体阶段，主要的安全防护功能都在 access 阶段处理
header_filter_by_lua_file /opt/OpenWAF/app/twaf_header_filter.lua;   # 处理响应头阶段
body_filter_by_lua_file   /opt/OpenWAF/app/twaf_body_filter.lua;     # 处理响应体阶段
log_by_lua_file           /opt/OpenWAF/app/twaf_log.lua;             # log 阶段有日志模块和统计模块

set $twaf_upstream_server "";
set $twaf_attack_info     "";
set $twaf_cache_flag       1;
```

twaf_access_rule
----------------

twaf_access_rule 涉及 ssl_certificate_by_lua ， rewrite_by_lua 和 balancer_by_lua 三个阶段
    
```
{
    "twaf_access_rule": [
        "rules": [                                 -- 注意先后顺序
            {                                      
                "ngx_ssl": false,                  -- nginx 认证的开关
                "ngx_ssl_cert": "path",            -- nginx 认证所需 PEM 证书地址
                "ngx_ssl_key": "path",             -- nginx 认证所需 PEM 私钥地址
                "host": "www.baidu.com",           -- 域名，正则匹配
                "path": "/",                       -- 路径，正则匹配
                "port": 80,                        -- 端口，默认 80
                "server_ssl": false,               -- 后端服务器 ssl 开关
                "forward": "server_5",             -- 后端服务器 upstream 名称
                "forward_addr": "1.1.1.2",         -- 后端服务器ip地址
                "forward_port": "8080",            -- 后端服务器端口号（缺省80）
                "uuid": "access_567b067ff2060",    -- 用来标记此规则的 uuid，api 中会用到，要保证全局唯一
                "policy": "policy_uuid"            -- 安全策略 ID
            }
        ]
    }
}
```

### ssl_certificate_by_lua

ssl_certificate_by_lua 阶段用于 ssl 认证，涉及到 access_rule 配置的有 ngx_ssl，ngx_ssl_cert 和 ngx_ssl_key

这部分配置可以节省 nginx 中 ssl 配置的重复性，如：

```nginx
    server {
        listen 443 ssl;
        server_name www.abc.com;
        
        ssl_certificate /opt/OpenWAF/conf/ssl/abc.crt;
        ssl_certificate_key /opt/OpenWAF/conf/ssl/abc.key;
        ssl_protocols TLSv1.1 TLSv1.2;

        location / {
            ...
        }
    }
    
    server {
        listen 443 ssl;
        server_name www.xyz.com;
        
        ssl_certificate /opt/OpenWAF/conf/ssl/xyz.crt;
        ssl_certificate_key /opt/OpenWAF/conf/ssl/xyz.key;
        ssl_protocols TLSv1.1 TLSv1.2;

        location / {
            ...
        }
    }
    
    ...
```

原始 nginx 配置如上，那么加上 WAF 防护，且经过 access_rule 的优化后，可写为：

```nginx
    server {
        listen 443 ssl;
        server_name _;
        
        ssl_certificate /opt/OpenWAF/conf/ssl/nginx.crt;
        ssl_certificate_key /opt/OpenWAF/conf/ssl/nginx.key;
        ssl_protocols TLSv1.1 TLSv1.2;
        
        include                     /opt/OpenWAF/conf/twaf_server.conf;  #添加 WAF 防护
        ssl_certificate_by_lua_file /opt/OpenWAF/app/twaf_ssl_cert.lua;  #动态指定 SSL 证书

        location / {
            ...
        }
    }
```

此时只需在 access_rule 中指定 SSL 证书即可，如：

```
{
    "twaf_access_rule": [
        "rules": [
            {                                      
                "ngx_ssl": true,
                "ngx_ssl_cert": "opt/OpenWAF/conf/ssl/abc.crt",
                "ngx_ssl_key":  "/opt/OpenWAF/conf/ssl/abc.key",
                "host": "www.abc.com",
                "path": "/",
                "port": 443,
                ...
            },
            {                                      
                "ngx_ssl": true,
                "ngx_ssl_cert": "opt/OpenWAF/conf/ssl/xyz.crt",
                "ngx_ssl_key":  "/opt/OpenWAF/conf/ssl/xyz.key",
                "host": "www.xyz.com",
                "path": "/",
                "port": 443,
                ...
            }
        ]
    }
}
```

如此，多个 ssl 站点，也可用 access_rule 实现动态分配 SSL 证书，不需变更 nginx 配置

### rewrite_by_lua

rewrite_by_lua 阶段，会依据请求头中的 host，port，uri 等信息，确认后端服务器地址及选用的策略

下面详细讨论 nginx 配置是如何转到 access_rule 中配置的

```nginx

    upstream aaa {
        server 1.1.1.1;
    }
    
    server {
        listen       80;
        server_name  www.aaa.com;

        location / {
            proxy_pass http://aaa;
        }
    }
```

上面 nginx 配置，加上 OpenWAF 防御后，对应 nginx 配置如下：

```nginx
    upstream test {
       server 0.0.0.1; #just an invalid address as a place holder
       balancer_by_lua_file /opt/OpenWAF/app/twaf_balancer.lua;
    }
    
    server {
        listen       80;
        server_name  _;
        include      /opt/OpenWAF/conf/twaf_server.conf;

        location / {
            proxy_pass $twaf_upstream_server;
        }
    }
```

对应 access_rule 配置如下：

```
{
    "twaf_access_rule": [
        "rules": [
            {
                "host": "www.aaa.com",
                "path": "/",
                "port": 80,
                "forward": "test",
                "forward_addr": "1.1.1.1",
                "forward_port": 80
                ...
            }
        ]
    }
}
```

其中 forward 是为 nginx 配置中的 $twaf_upstream_server 变量赋值  
forward_addr 和 forward_port 只在 upstream 中使用 balancer_by_lua 才会生效，否则不需配置这两个值  

前面 ssl_certificate_by_lua 的配置，节省了因 ssl 证书配置使得一个 ssl 站点对应一个 nginx 的 server 配置的重复性

这部分 rewrite_by_lua 的配置同样可以节省 nginx 中配置的重复性，如：

```nginx

    upstream aaa_1 {
        server 1.1.1.1;
    }
    
    upstream_aaa_2 {
        server 1.1.1.2;
    }
    
    upstream bbb {
        server 2.2.2.2:8000;
    }
    
    server {
        listen       80;
        server_name  www.aaa.com;

        location / {
            proxy_pass http://aaa_1;
        }
        
        location /a {
            proxy_pass http://aaa_2;
        }
    }
    
    server {
        listen       90;
        server_name  www.bbb.com;

        location / {
            proxy_pass http://bbb;
        }
    }
    
    ...
```

上面 nginx 配置，加上 OpenWAF 防御后，对应 nginx 配置如下：

```nginx
    upstream test {
       server 0.0.0.1; #just an invalid address as a place holder
       balancer_by_lua_file /opt/OpenWAF/app/twaf_balancer.lua;
    }
    
    server {
        listen       80;
        listen       90;
        server_name  _;
        include      /opt/OpenWAF/conf/twaf_server.conf;

        location / {
            proxy_pass $twaf_upstream_server;
        }
    }
```

对应 access_rule 配置如下：

```
{
    "twaf_access_rule": [
        "rules": [
            {
                "host": "www.aaa.com",
                "path": "/a",
                "port": 80,
                "forward": "test",
                "forward_addr": "1.1.1.2",
                "forward_port": 80
                ...
            },
            {
                "host": "www.aaa.com",
                "path": "/",
                "port": 80,
                "forward": "test",
                "forward_addr": "1.1.1.1",
                "forward_port": 80
                ...
            },
            {
                "host": "www.bbb.com",
                "path": "/",
                "port": 90,
                "forward": "test",
                "forward_addr": "2.2.2.2",
                "forward_port": 8000
                ...
            }
        ]
    }
}
```

从以上配置可以看出，access_rule 节省了因域名，监听端口，路径，upstream 等因素造成的配置复杂性

而且，以后可通过 api，动态添加接入规则，不需中断业务，而修改 nginx 配置，可能会中断业务

注意：在上例中，www.aaa.com 站点下，有 '/' 和 '/a' 两个路径，access_rule 是数组，因此，要将有关 '/a' 的配置放在 '/' 前

本地资源配置:

```nginx
    upstream test {
       server 0.0.0.1; #just an invalid address as a place holder
       balancer_by_lua_file /opt/OpenWAF/app/twaf_balancer.lua;
    }
    
    server {
        listen       80;
        server_name  www.aaa.com;
        include      /opt/OpenWAF/conf/twaf_server.conf;

        location / {
            proxy_pass $twaf_upstream_server;
        }
        
        location /a {      #本地资源
            root /xxx;
            index xxx;
        }
    }
```

对应 access_rule 配置如下:

```
{
    "twaf_access_rule": [
        "rules": [
            {
                "host": "www.aaa.com",
                "path": "/",
                "port": 80,
                "forward": "test",
                "forward_addr": "1.1.1.1",
                "forward_port": 80
                ...
            }
        ]
    }
}
```

这里可以看到，仅仅是配置了根目录的接入规则，并不需单独为 '/a' 进行配置  

因为访问 www.aaa.com/a 目录下资源，已经匹配中了这条接入规则，但对应的 nginx 配置中并没有 proxy_pass，  
因此 forward ，forward_addr 和 forward_port 三个参数并不会生效

当然如果你很任性，非要添加有关 '/a' 目录的接入规则，则配置如下：

```
{
    "twaf_access_rule": [
        "rules": [
            {
                "host": "www.aaa.com",
                "path": "/a",
                "port": 80,
                ...
            },
            {
                "host": "www.aaa.com",
                "path": "/",
                "port": 80,
                "forward": "test",
                "forward_addr": "1.1.1.1",
                "forward_port": 80
                ...
            }
        ]
    }
}
```

从上面配置看出，因为 forward ，forward_addr 和 forward_port 三个参数并不会生效，所以无需配置

access_rule 中还剩最后两个参数，uuid 和 policy  
uuid:   用来标记接入规则的 uuid，api 中会用到，要保证全局唯一  
policy: 指定策略名称，OpenWAF 自带策略有 twaf_default_conf 和 twaf_policy_conf，若不配置 policy，缺省使用 twaf_default_conf 策略  
        

