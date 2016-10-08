Name
====

OpenWAF-基于[openresty](https://github.com/openresty/openresty)的Web安全防护系统

Table of Contents
=================

* [Name](#name)
* [Version](#version)
* [Synopsis](#synopsis)
* [Description](#description)
* [Installation](#installation)
* [Community](#community)
* [Bugs and Patches](#bugs-and-patches)
* [TODO](#todo)
* [Changes](#changes)
* [Copyright and License](#copyright-and-license)
* [Modules Configuration Directives](#modules-configuration-directives)
* [Variables](#variables)

Version
=======

This document describes OpenWAF v0.01 released on 26 July 2016.

Synopsis
========
```nginx
    #nginx.conf
    lua_package_path '/twaf/?.lua;;';
    
    init_by_lua_file /twaf/app/twaf_init.lua;
    init_worker_by_lua_file /twaf_app/twaf_init_worker.lua;

    lua_shared_dict twaf_shm 50m;
    
    upstream test {
        server 0.0.0.1; #just an invalid address as a place holder
        balancer_by_lua_file twaf_balancer.lua;
    }
    
    server {
        listen 443 ssl;
        server_name _;
        
        ssl_certificate_by_lua_file  twaf_ssl_cert.lua;
        rewrite_by_lua_file          /twaf/app/twaf_rewrite.lua;
        access_by_lua_file           /twaf/app/twaf_access.lua;
        header_filter_by_lua_file    /twaf/app/twaf_header_filter.lua;
        body_filter_by_lua_file      /twaf/app/twaf_body_filter.lua
        log_by_lua_file              /twaf/app/twaf_log.lua;
        
        set $twaf_https 1;
        set $twaf_upstream_server "";
        
        ssl_certificate nginx.crt;
        ssl_certificate_key nginx.key;
        
        location / {
            lua_need_request_body on;
            proxy_pass $twaf_upstream_server;
        }
    }
    
    server {
        listen      80;
        server_name  _;
        
        rewrite_by_lua_file       /twaf/app/twaf_rewrite.lua;
        access_by_lua_file        /twaf/app/twaf_access.lua;
        header_filter_by_lua_file /twaf/app/twaf_header_filter.lua;
        body_filter_by_lua_file   /twaf/app/twaf_body_filter.lua
        log_by_lua_file           /twaf/app/twaf_log.lua;
        
        set $twaf_upstream_server "";
        
        location / {
            lua_need_request_body on;
            proxy_pass $twaf_upstream_server;
        }
    }
```

```json
    #default_config-json
    {
        "access_order" : [
            {"twaf_debug":            "lib.twaf.twaf_debug"},
            {"twaf_attack_response":  "lib.twaf.twaf_attack_response"},
            {"twaf_secrules":         "lib.twaf.twaf_secrules"},
            {"twaf_upload_radar":     "lib.twaf.twaf_upload_radar"},
            {"twaf_anti_mal_crawler": "lib.twaf.twaf_anti_mal_crawler"},
            {"twaf_balancer":         "lib.twaf.twaf_balancer"},
            {"twaf_anti_detection":   "lib.twaf.twaf_anti_detection"},
            {"twaf_anti_robot":       "lib.twaf.twaf_anti_robot"},
            {"twaf_limit_conn":       "lib.twaf.twaf_anti_cc.twaf_anti_cc"},
            {"twaf_shell_radar":      "lib.twaf.twaf_shell_radar"},
            {"twaf_anti_hotlink":     "lib.twaf.twaf_anti_hotlink"},
            {"twaf_cookie_guard":     "lib.twaf.twaf_cookie_guard"},
            {"twaf_iwsc":             "lib.twaf.twaf_iwsc"}
        ],
        "twaf_global": {
            "unique_id_len": 34,
            "dict_name": "twaf_shm",
            "timer_flush_expired": 10,
            "process_multipart_body": true,
            "allow_unknow_content_types": true,
            "allowed_content_types":{
                "text/xml": true
            },
            "simulation": false,
            "twaf_redis":{
                "select": 1,
                "ipaddr": "1.1.1.1",
                "port":20000
            }
            
        }
    }
    
    #main_safe_policy-json
```

[Back to TOC](#table-of-contents)

Description
===========

基础模块如下:
* [twaf_conf](https://github.com/titansec/openwaf_conf)
* [twaf_log](https://github.com/titansec/openwaf_log)
* [twaf_reqstat](https://github.com/titansec/openwaf_reqstat)
* [twaf_core](https://github.com/titansec/openwaf_core)
* [twaf_access_rule](https://https://github.com/titansec/openwaf_access_rule)

功能模块如下:
* [twaf_secrules](https://github.com/titansec/openwaf_rule_engine)
  
[Back to TOC](#table-of-contents)

Installation
============

1. 安装[openresty](https://openresty.org/en/installation.html)
2. 下载[OpenWAF]()

[Back to TOC](#table-of-contents)

Community
=========

Chinese Mailing List
--------------------

The [OpenWAF](https://groups.google.com/group/TWAF) mailing list is for Chinese speakers.

[Back to TOC](#table-of-contents)

Bugs and Patches
================

Please submit bug reports, wishlists, or patches by

1. creating a ticket on the [GitHub Issue Tracker](https://github.com/290557551/twaf/issues),
1. or posting to the [OpenWAF community](#community).

[Back to TOC](#table-of-contents)

TODO
====

* 1. 核心框架(twaf_conf, twaf_core)
* 2. 日志
* 3. 统计
* 4. 接入规则
* 5. 规则引擎
* 6. 其余文档，包括Install、Description等

[Back to TOC](#table-of-contents)

Changes
=======



[Back to TOC](#table-of-contents)

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2016-2016, by Jian "Miracle" Qi (齐健) <miracleqi25@gmail.com>, Titan Co.Ltd.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

Modules Configuration Directives
================================
* [twaf_access_rule](#twaf_access_rule)
* [twaf_anti_hotlink](#twaf_anti_hotlink)
* [twaf_anti_mal_crawler](#twaf_anti_mal_crawler)

[Back to TOC](#table-of-contents)

twaf_access_rule
----------------
```txt
{
    "twaf_access_rule": [
        "rules": [                                 -- 注意先后顺序
            {                                      
                "client_ssl": false,               -- 客户端认证的开关，与ngx_ssl组成双向认证
                "client_ssl_cert": "path",         -- 客户端认证所需公钥地址
                "ngx_ssl": false,                  -- nginx认证的开关
                "ngx_ssl_cert": "path",            -- nginx认证所需公钥地址
                "ngx_ssl_key": "path",             -- nginx认证所需私钥地址
                "host": "^1\\.1\\.1\\.1$",         -- 域名，支持字符串、正则
                "path": "\/",                      -- 路径，支持字符串、正则
                "server_ssl": false,               -- 后端服务器ssl开关
                "forward": "server_5",             -- 后端服务器upstream名称
                "forward_addr": "1.1.1.2",         -- 后端服务器ip地址
                "forward_port": "8080",            -- 后端服务器端口号（缺省80）
                "uuid": "access_567b067ff2060",    -- 用来标记此规则的uuid
                "policy": "policy_uuid"            -- 安全策略ID
            }
        ]
    }
}
```
###rules
**syntax:** *"rules": table*

**default:** *none*

**context:** *twaf_access_rule*

接入规则，顺序执行

###client_ssl
**syntax:** *"client_ssl": true|false*

**default:** *false*

**context:** *twaf_access_rule*

客户端认证开关，与ngx_ssl组成双向认证，默认false

###client_ssl_cert
**syntax:** *"client_ssl_cert": "path"*

**default:** *none*

**context:** *twaf_access_rule*

客户端认证所需公钥地址

###ngx_ssl
**syntax:** *"ngx_ssl": true|false*

**default:** *false*

**context:** *twaf_access_rule*

服务器端(nginx)认证开关，与client_ssl组成双向认证，默认关闭

###ngx_ssl_cert
**syntax:** *"ngx_ssl_cert": "path"*

**default:** *none*

**context:** *twaf_access_rule*

服务器端(nginx)认证所需公钥地址

###ngx_ssl_key
**syntax:** *"ngx_ssl_key": "path"*

**default:** *none*

**context:** *twaf_access_rule*

服务器端(nginx)认证所需私钥地址

###host
**syntax:** *"host": "ip|domain name string|regex"*

**default:** *none*

**context:** *twaf_access_rule*

域名，支持正则

例如:
```
    "host": "^1\\.1\\.1\\.1$"
    "host": "test\\.com"
    "host": "^.*\\.com$"
```

###path
**syntax:** *"path": "string|regex"*

**default:** *none*

**context:** *twaf_access_rule*

路径，支持字符串及正则

例如:
```
    "path": "/"
    "path": "/images"
    "path": "/[a|b]test"
```

###server_ssl
**syntax:** *"server_ssl": true|false*

**default:** *false*

**context:** *twaf_access_rule*

OpenWAF向后端服务器连接的ssl开关

例如:
```
    upstream test {
    	server 1.1.1.1;
    }
    
    http {
    	server {
    	    listen 80;
    	    server_name _;
    	    
    	    location / {
    	        #server_ssl为true，相当于proxy_pass后为https
    	    	proxy_pass https://test;
    	        #server_ssl为false，相当于proxy_pass后为http
    	    	#proxy_pass http://test;
    	    }
    	}
    }
```

###forward
**syntax:** *"forward": "string"*

**default:** *none*

**context:** *twaf_access_rule*

forward表示后端服务器的uuid即upstream的名称

```
    #如：forward值为test
    upstream test {
        server 1.1.1.1;
    }
```

###forward_addr
**syntax:** *"forward_addr": "ip"*

**default:** *none*

**context:** *twaf_access_rule*

forward_addr表示后端服务器的ip地址（TODO：支持域名）
```
    upstream test {
        #如：forward_addr值为1.1.1.1
    	server 1.1.1.1;
    }
```

###forward_port
**syntax:** *"forward_port": port*

**default:** *80*

**context:** *twaf_access_rule*

forward_port表示后端服务器端口号，默认80

```
    upstream test {
    	#如：forward_port值为50001
    	server 1.1.1.1:50001;
    }
```

###uuid
**syntax:** *"uuid": "string"*

**default:** *none*

**context:** *twaf_access_rule*

接入规则的唯一标识

###policy
**syntax:** *"policy": "policy_uuid"*

**default:** *none*

**context:** *twaf_access_rule*

满足此接入规则的请求，所使用安全策略的ID

[Back to TOC](#table-of-contents)
```
    upstream test {
    	server 1.1.1.1;
    }
    
    http {
    	server {
    	    listen 80;
    	    server_name _;
    	    
    	    location / {
    	        #server_ssl为true，则proxy_pass后为https
    	    	proxy_pass https://test;
    	        #server_ssl为false，则proxy_pass后为http
    	    	#proxy_pass http://test;
    	    }
    	}
    }
```

###forward
**syntax:** *"forward": "string"*

**default:** *none*

**context:** *twaf_access_rule*

forward表示后端服务器的uuid即upstream的名称
```
    #如：forward值为test
    upstream test {
        server 1.1.1.1;
    }
```

###forward_addr
**syntax:** *"forward_addr": "ip"*

**default:** *none*

**context:** *twaf_access_rule*

forward_addr表示后端服务器的ip地址（TODO：支持域名）
```
    upstream test {
        #如：forward_addr值为1.1.1.1
    	server 1.1.1.1;
    }
```

###forward_port
**syntax:** *"forward_port": port*

**default:** *80*

**context:** *twaf_access_rule*

forward_port表示后端服务器端口号，默认80
```
    upstream test {
    	#如：forward_port值为50001
    	server 1.1.1.1:50001;
    }
```

###uuid
**syntax:** *"uuid": "string"*

**default:** *none*

**context:** *twaf_access_rule*

uuid表示接入规则的唯一标识，利用此标识可以查看此站点的访问频率（单位：个/秒）

###policy
**syntax:** *"policy": "policy_uuid"*

**default:** *none*

**context:** *twaf_access_rule*

policy表示此站点使用安全策略的ID

twaf_anti_hotlink
-----------------
```json
{
    "twaf_anti_hotlink":{
        "state":false,
        "log_state":true,
        "event_id":"110001",
        "event_severity":"medium",
        "ct_state":false,
        "action_meta":403,
        "action":"DENY",
        "mode":"referer",
        "allow_noreferer":true,
        "cookie_name":"TWAF_AH",
        "uri_ext":["javascript", "css", "html", ""]
    }
}
```
###state
**syntax:** *"state": true|false|"$dynamic_state"*

**default:** *false*

**context:** *twaf_anti_hotlink*

###log_state
**syntax:** *"log_state": true|false|"$dynamic_state"*

**default:** *true*

**context:** *twaf_anti_hotlink*

###ct_state
**syntax:** *"ct_state": true|false|"$dynamic_state"*

**default:** *false*

**context:** *twaf_anti_hotlink*

###event_id
**syntax:** *"event_id": "string"*

**default:** *"110001"*

**context:** *twaf_anti_hotlink*

###event_severity
**syntax:** *"event_severity": "string"*

**default:** *"medium"*

**context:** *twaf_anti_hotlink*

###action
**syntax:** *"action": "string"*

**default:** *"DENY"*

**context:** *twaf_anti_hotlink*

###action_meta
**syntax:** *"action_meta": "string"|number*

**default:** *403*

**context:** *twaf_anti_hotlink*

###mode
**syntax:** *"mode": "string"*

**default:** *"referer"*

**context:** *twaf_anti_hotlink*

###allow_noreferer
**syntax:** *"allow_noreferer": true|false*

**default:** *true*

**context:** *twaf_anti_hotlink*

###cookie_name
**syntax:** *"cookie_name": "string"*

**default:** *TWAF_AH*

**context:** *twaf_anti_hotlink*

cookie_name表示盗链模块发送COOKIE的名称，默认"TWAF_AH"

此配置只有mode为cookie模式下生效

[Back to MCD](#twaf_anti_hotlink)

###uri_ext
**syntax:** *"uri_ext": array|exten|"all"*

**default:** *none*

**context:** *twaf_anti_hotlink*

uri_ext表示对哪些资源进行盗链防护

```
     #对html类型资源进行盗链防护
     "uri_ext": "html"
     
     #对未知类型资源进行盗链防护，nginx无法解析出资源类型时为空字符串
     "uri_ext": ""
     
     #对html、css及未知类型资源进行盗链防护
     "uri_ext": ["html", "css", ""]
     
     #对所有资源进行盗链防护
     "uri_ext": "all"
```

[Back to MCD](#twaf_anti_hotlink)



twaf_anti_mal_crawler
---------------------
```json
{
    "state":false,
    "cookie_state":true,
    "log_state":true,
    "event_id":"710001",
    "event_severity":"high",
    "force_scan_robots_state":false,
    "shared_dict_key":["remote_addr", "http_user_agent"],
    "timeout":300,
    "crawler_cookie_name":"crawler",
    "mal_cookie_name":"mcrawler",
    "trap_uri":"/abc/abc.html",
    "trap_args":"id=1",
    "action":"DENY",
    "action_meta":403
}
```
###state
**syntax:** *state true|false|$dynamic_state*

**default:** *false*

**context:** *twaf_anti_mal_crawler*

模块开关，默认false（关闭），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

###cookie_state
**syntax:** *cookie_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_anti_mal_crawler*

是否发送cookie,默认true（发送），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

###log_state
**syntax:** *log_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_anti_mal_crawler*

安全日志开关， 默认true（记录），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

###event_id
**syntax:** *event_id <string>*

**default:** *"710001"*

**context:** *twaf_anti_mal_crawler*

记录安全日志时，显示的事件ID

[Back to MCD](#twaf_anti_mal_crawler)

###event_severity
**syntax:** *event_severity critical|high|medium|low*

**default:** *high*

**context:** *twaf_anti_mal_crawler*

记录安全日志时，显示的事件等级

[Back to MCD](#twaf_anti_mal_crawler)

[Back to TOC](#table-of-contents)

Variables
==========

###$twaf_https
**syntax:** *set $twaf_https 0|1*

**default:** *0*

**context:** *server*

用于标记请求是否通过ssl加密

"set $twaf_https 1"，则表示请求通过ssl加密

"set $twaf_https 1"，则表示请求未通过ssl加密

###$twaf_upstream_server
**syntax:** *set $twaf_upstream_server ""*

**default:** *none*

**context:** *server*

只需要初始化为空字符串即可

**syntax:** *proxy_pass $twaf_upstream_server*

**default:** *none*

**context:** *location*

后端服务器地址，其值由接入规则"server_ssl"和"forward"配置确定

例如：
```
    若"server_ssl"值为true, "forward"值为"server_1"
    则$twaf_upstream_server值为"https://server_1"
    等价于proxy_pass https://server_1;
    
    若"server_ssl"值为false, "forward"值为"server_2"
    则$twaf_upstream_server值为"http://server_2"
    等价于proxy_pass http://server_2;
```

[Back to TOC](#table-of-contents)
