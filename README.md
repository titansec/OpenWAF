Name
====

OpenWAF

The first all-round open source Web security protection system, more protection than others.

Table of Contents
=================

* [Name](#name)
* [Version](#version)
* [Synopsis](#synopsis)
* [Description](#description)
* [Installation](#installation)
* [Community](#community)
    * [English Mailing List](#english-mailing-list)
    * [Chinese Mailing List](#chinese-mailing-list)
    * [Personal QQ Mail](#personal-qq-mail)
* [Bugs and Patches](#bugs-and-patches)
* [TODO](#todo)
* [Changes](#changes)
* [Copyright and License](#copyright-and-license)
* [Modules Configuration Directives](#modules-configuration-directives)
* [Nginx Variables](#nginx-variables)
* [SecRules](#secrules)
    * [Variables](#variables)
    * [Transformation Functions](#transformation-functions)
    * [Operators](#operators)
    * [Others](#others)
* [Donation](#donation)

Version
=======

This document describes OpenWAF v1.1 released on Mar 8, 2021.

[Dockerfile](https://github.com/titansec/docker-openwaf) and [Docker Images](https://hub.docker.com/r/titansec/openwaf/tags) have been upgraded to version 1.1 on Mar 8, 2021.

Synopsis
========
```nginx
    #nginx.conf
    lua_package_path '/twaf/?.lua;;';
    
    init_by_lua_file /twaf/app/twaf_init.lua;
    
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

    #main_safe_policy-json
```

[Back to TOC](#table-of-contents)

Description
===========

&emsp;&emsp;OpenWAF is the first fully open source Web application protection system (WAF), based on nginx_lua API analysis of HTTP request information. OpenWAF is composed of two functional engines: behavior analysis engine and rule engine. The rule engine mainly analyzes the individual requests, and the behavior analysis engine is mainly responsible for the tracking of the request information.  
&emsp;&emsp;Rule engine inspired by [modsecurity](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual) and [freewaf(lua-resty-waf)](https://github.com/p0pr0ck5/lua-resty-waf), the ModSecurity rules will be implemented using lua. The rule engine can be based on the protocol specification, automatic tools, injection attacks, cross site attacks, information leaks and other security exception request, adding support for dynamic rules, timely repair vulnerabilities.  
&emsp;&emsp;Behavior analysis engine including fuzzy identification based on frequency, anti malware crawler, human-computer identification anti detection module, anti CSRF, anti CC, anti right, protection against attack file upload module, cookie tamper proof, anti-theft chain, custom headers and attack response page proof module of information disclosure.  
&emsp;&emsp;In addition to the two engines, but also includes statistics, log, attack response page, access rules and other basic modules. In addition to the existing functional modules, OpenWAF also supports dynamic modification of the configuration, the dynamic addition of third party modules, so that the engine does not restart under the conditions of the outage, upgrade protection.  
&emsp;&emsp;OpenWAF supports the above features as a strategy for different web application applications with different strategies to protect. The future will build a cloud platform, the strategy can also be shared for others.

basic modules:
* [openwaf_conf](https://github.com/titansec/openwaf_conf)
* [openwaf_log](https://github.com/titansec/openwaf_log)
* [openwaf_reqstat](https://github.com/titansec/openwaf_reqstat)
* [openwaf_core](https://github.com/titansec/openwaf_core)
* [openwaf_access_rule](https://github.com/titansec/openwaf_access_rule)

safe modules:
* [openwaf_rule_engine](https://github.com/titansec/openwaf_rule_engine)
* [openwaf_attack_response](https://github.com/titansec/openwaf_attack_response)
* [openwaf_api](https://github.com/titansec/openwaf_api)
* [openwaf_anti_mal_crawler](https://github.com/titansec/openwaf_anti_mal_crawler)
* [openwaf_anti_cc](https://github.com/titansec/openwaf_anti_cc)

Detailed configuration documents and examples, please refer to the above module documentation
  
[Back to TOC](#table-of-contents)

Installation
============

[请看 OpenWAF 安装文档](https://github.com/titansec/OpenWAF/blob/master/doc/%E8%BD%BB%E6%9D%BE%E7%8E%A9%E8%BD%ACOpenWAF%E4%B9%8B%E5%AE%89%E8%A3%85%E7%AF%87.md)

[Back to TOC](#table-of-contents)

Community
=========

English Mailing List
--------------------

The [OpenWAF-en](https://groups.google.com/group/openwaf-en) mailing list is for English speakers.

Chinese Mailing List
--------------------

The [OpenWAF-cn](https://groups.google.com/group/openwaf-cn) mailing list is for Chinese speakers.

Personal QQ Mail
----------------

290557551@qq.com

QQ Group
---------

579790127

[Back to TOC](#table-of-contents)

Bugs and Patches
================

Please submit bug reports, wishlists, or patches by

1. creating a ticket on the [GitHub Issue Tracker](https://github.com/titansec/OpenWAF/issues),
1. or posting to the [OpenWAF community](#community).

[Back to TOC](#table-of-contents)

TODO
====

* Add access_rule module dynamic switch
* Support connecting SSO
* Dynamic token
* APISG(API Security gateway)
* Mock

[Back to TOC](#table-of-contents)

Changes
=======

[Changelog](https://github.com/titansec/OpenWAF/blob/master/Changelog)

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
* [twaf_reqstat](#twaf_reqstat)
* [twaf_log](#twaf_log)
* [twaf_secrules](#twaf_secrules)
* [twaf_anti_cc](#twaf_anti_cc)

[Back to TOC](#table-of-contents)

twaf_access_rule
----------------

```txt
{
    "twaf_access_rule": {
        "rules": [                                 -- 注意先后顺序
            {                                      
                "user": "user_id",                 -- 用户名ID，非必填，默认值"-"
                "ngx_ssl": false,                  -- nginx认证的开关，非必填，默认值false
                "ngx_ssl_cert": "path",            -- nginx认证所需PEM证书地址
                "ngx_ssl_key": "path",             -- nginx认证所需PEM私钥地址
                "host": "^1\\.1\\.1\\.1$",         -- 域名，支持正则匹配，支持字符串或数组，同时支持IPv4/IPv6
                "port": 80,                        -- 端口号。支持number或数组类型，非必填，默认值80或443
                "path": "\/",                      -- 路径，支持正则匹配，非必填，默认值"/"
                "url_case_sensitive": false,       -- 路径区分大小写，boolean类型，非必填，默认值 false
                "server_ssl": false,               -- 后端服务器ssl开关，boolean类型，非必填，默认值 false
                "forward": "server_5",             -- 后端服务器upstream名称，string类型
                "forward_addr": "1.1.1.2",         -- 后端服务器ip地址，string类型
                "forward_port": "8080",            -- 后端服务器端口号，非必填，默认值80或443
                "uuid": "access_567b067ff2060",    -- 用来标记此规则的uuid，非必填，默认16位随机字符串
                "policy": "policy_uuid"            -- 安全策略ID，string类型，非必填，默认值twaf_default_conf
            }
        ]
    }
}
```
rules
-----
**syntax:** *"rules": table*

**default:** *none*

**context:** *twaf_access_rule*

table类型，接入规则，顺序匹配

user
----
**syntax:** *"user": string*

**default:** *-*

**context:** *twaf_access_rule:rules*

string类型。用户名ID。对应变量 %{USERID}。

非必填，默认值"-".

ngx_ssl
-------
**syntax:** *"ngx_ssl": true|false*

**default:** *false*

**context:** *twaf_access_rule:rules*

boolean类型，服务器端(nginx)认证开关，可与client_ssl组成双向认证

非必填，默认值false

ngx_ssl_cert
------------
**syntax:** *"ngx_ssl_cert": "path"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string类型，服务器端(nginx)认证所需PEM证书地址，目前仅支持绝对地址

ngx_ssl_key
-----------
**syntax:** *"ngx_ssl_key": "path"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string类型，服务器端(nginx)认证所需PEM私钥地址，目前仅支持绝对地址

host
----
**syntax:** *"host": "ip|domain name regex"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string或数组类型。发布域名。(从 v1.0.0β 版本开始支持数组)

支持正则表达式(匹配时，自动忽略大小写)。

同时支持IPv4/IPv6。(从 v1.0.0β 版本开始支持IPv6)

例如:
```
    "host": "^1\\.1\\.1\\.1$"
    "host": "test\\.com"
    "host": "^.*\\.com$"
    "host": "www.baidu.com"
    "host": ["www.baidu.com", "1.1.1.1", "8888::192.168.1.1"]
```

port
----
**syntax:** *"port": number*

**default:** *80|443*

**context:** *twaf_access_rule:rules*

number或数组类型，端口号。(从 v1.0.0β 版本开始支持数组)

非必填，默认值80或443

若"host"参数为数组时，"port"也应为数组。例如:
```
    "host": ["www.baidu.com", "1.1.1.1", "8888::192.168.1.1"]
    "posrt": [80, 8088, 8099]
```

path
----
**syntax:** *"path": "regex"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string类型，路径，支持正则匹配

非必填，默认值"/"

例如:
```
    "path": "/"
    "path": "/images"
    "path": "/[a|b]test"
```

url_case_sensitive
------------------
**syntax:** *"url_case_sensitive": "true|false"*

**default:** *false*

**context:** *twaf_access_rule:rules*

boolean类型，路径区分大小写(从 v1.0.0β 版本开始支持此参数)

非必填，默认值false(不区分大小写)

server_ssl
----------
**syntax:** *"server_ssl": true|false*

**default:** *false*

**context:** *twaf_access_rule:rules*

boolean类型，OpenWAF向后端服务器连接的ssl开关

非必填，默认值 false

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

forward
-------
**syntax:** *"forward": "upstream_uuid"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string类型，forward表示后端服务器的uuid，即upstream的名称

若不使用OpenWAF提供的$twaf_upstream_server变量，则"forward","forward_addr","forward_port"均非必填(从 v1.0.0β 版本开始支持非必填)

```
    #如：使用OpenWAF自带的$twaf_upstream_server变量，forward值为test
    upstream test {
        server 1.1.1.1;
    }
    
    server {
        ...
        location / {
            proxy_pass $twaf_upstream_server;
        }
    }
    
    ---------------------------------
    
    #如：未使用OpenWAF自带的$twaf_upstream_server变量，forward非必填
    server {
        ...
        location / {
            proxy_pass http://1.1.1.1;
        }
    }
    
    ---------------------------------
    
    #如：未使用OpenWAF自带的$twaf_upstream_server变量，forward非必填
    server {
        ...
        location / {
            root html;
            index index.htm;
        }
    }
```

forward_addr
------------
**syntax:** *"forward_addr": "ip"*

**default:** *none*

**context:** *twaf_access_rule:rules*

string类型，forward_addr表示后端服务器的ip地址（TODO：支持域名）

```
    upstream test {
        #如：forward_addr值为1.1.1.1
    	server 1.1.1.1;
    }
```

forward_port
------------
**syntax:** *"forward_port": port*

**default:** *80|443*

**context:** *twaf_access_rule:rules*

number类型，forward_port表示后端服务器端口号

非必填，默认值80或443

```
    upstream test {
    	#如：forward_port值为50001
    	server 1.1.1.1:50001;
    }
```

uuid
----
**syntax:** *"uuid": "string"*

**default:** *random(16)*

**context:** *twaf_access_rule:rules*

string类型，接入规则的唯一标识

非必填，默认16位随机字符串(从 v1.0.0β 版本开始默认16位随机字符串)

policy
------
**syntax:** *"policy": "policy_uuid"*

**default:** *twaf_default_conf*

**context:** *twaf_access_rule:rules*

string类型，满足此接入规则的请求，所使用安全策略的uuid

非必填，默认值twaf_default_conf

[Back to twaf_access_rule](#twaf_access_rule)

[Back to TOC](#table-of-contents)

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
state
-----
**syntax:** *"state": true|false|"$dynamic_state"*

**default:** *false*

**context:** *twaf_anti_hotlink*

当前模块暂未开源

log_state
---------
**syntax:** *"log_state": true|false|"$dynamic_state"*

**default:** *true*

**context:** *twaf_anti_hotlink*

ct_state
--------
**syntax:** *"ct_state": true|false|"$dynamic_state"*

**default:** *false*

**context:** *twaf_anti_hotlink*

event_id
--------
**syntax:** *"event_id": "string"*

**default:** *"110001"*

**context:** *twaf_anti_hotlink*

event_severity
--------------
**syntax:** *"event_severity": "string"*

**default:** *"medium"*

**context:** *twaf_anti_hotlink*

action
------
**syntax:** *"action": "string"*

**default:** *"DENY"*

**context:** *twaf_anti_hotlink*

action_meta
-----------
**syntax:** *"action_meta": "string"|number*

**default:** *403*

**context:** *twaf_anti_hotlink*

mode
----
**syntax:** *"mode": "string"*

**default:** *"referer"*

**context:** *twaf_anti_hotlink*

allow_noreferer
---------------
**syntax:** *"allow_noreferer": true|false*

**default:** *true*

**context:** *twaf_anti_hotlink*

cookie_name
-----------
**syntax:** *"cookie_name": "string"*

**default:** *TWAF_AH*

**context:** *twaf_anti_hotlink*

cookie_name表示盗链模块发送COOKIE的名称，默认"TWAF_AH"

此配置只有mode为cookie模式下生效

uri_ext
-------
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

[Back to twaf_anti_hotlink](#twaf_anti_hotlink)

[Back to TOC](#table-of-contents)

twaf_anti_mal_crawler
---------------------
```txt
{
    "state": false,                                            -- 模块开关，支持 true，false
    "log_state":true,                                          -- 日志开关

    "dict_state": false,                                       -- shared_dict 开关
    "shared_dict_name":"twaf_anti_mal_crawler",                -- shared_dict 名称,若为空，则值为 "twaf_global" 下的 "dict_name"
    "shared_dict_key": "remote_addr",                          -- shared_dict 键值
    "timeout":300,                                             -- shared_dict 保存状态有效时长（单位秒）
    "timer_flush_expired":200,                                 -- shared_dict 清除过期信息的间隔时间（单位秒）,若为空，则值为 "twaf_global" 下的 "timer_flush_expired"

    "cookie_state":true,                                       -- cookie机制开关
    "crawler_cookie_name":"TWAF_crawler",                      -- 爬虫cookie名称
    "mal_cookie_name":"TWAF_mcrawler",                         -- 恶意爬虫cookie名称

    "force_scan_robots_state":true,                            -- 页面注入诱捕路径的开关
    "force_scan_times": 3,                                     -- 注入诱捕路径的页面个数
    "trap_uri":"/abc/abc.html",                                -- 诱捕路径
    "trap_args":"id=1",                                        -- 诱捕参数

    "action":"DENY",                                           -- 执行动作，支持 "ALLOW", "DENY", "REDIRECT", "ROBOT", "RESET_CONNECTION", "PASS" 等
    "action_meta": 403                                         -- 执行动作的附属信息，若 action 为 DENY，action_meta为响应码，若 action 为 REDIRECT，action_meta 为重定向 url
}
```
state
-----
**syntax:** *state true|false|$dynamic_state*

**default:** *false*

**context:** *twaf_anti_mal_crawler*

模块开关，默认false（关闭），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

log_state
---------
**syntax:** *log_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_anti_mal_crawler*

安全日志开关， 默认true（记录），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

dict_state
----------
**syntax:** *dict_state true|false*

**default:** *false*

**context:** *twaf_anti_mal_crawler*

shared_dict 开关。当 dict_state 为 true，某 IP 被此模块拦截，会被记录在内存中，在 timeout 时间内访问会被拦截(且重置timeout)

[Back to MCD](#twaf_anti_mal_crawler)

shared_dict_name
----------------
**syntax:** *shared_dict_name <string>*

**default:** *nil*

**context:** *twaf_anti_mal_crawler*

shared_dict 名称。对应 nginx 中的配置项，不可轻易修改

若为空，则值为 "twaf_global" 下的 "dict_name"

[Back to MCD](#twaf_anti_mal_crawler)

shared_dict_key
---------------
**syntax:** *shared_dict_key <string>|<array>*

**default:** *remote_addr*

**context:** *twaf_anti_mal_crawler*

shared_dict 键值。支持数组

[Back to MCD](#twaf_anti_mal_crawler)

timeout
-------
**syntax:** *timeout <number>*

**default:** *300*

**context:** *twaf_anti_mal_crawler*

shared_dict 保存状态有效时长（单位秒）

[Back to MCD](#twaf_anti_mal_crawler)

timer_flush_expired
-------------------
**syntax:** *timeout <number>*

**default:** *200*

**context:** *twaf_anti_mal_crawler*

shared_dict 清除过期信息的间隔时间（单位秒）,若为空，则值为 "twaf_global" 下的 "timer_flush_expired"

[Back to MCD](#twaf_anti_mal_crawler)

cookie_state
------------
**syntax:** *cookie_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_anti_mal_crawler*

是否发送cookie,默认true（发送），支持动态开关

[Back to MCD](#twaf_anti_mal_crawler)

crawler_cookie_name
-------------------
**syntax:** *crawler_cookie_name <string>*

**default:** *"TWAF_crawler"*

**context:** *twaf_anti_mal_crawler*

爬虫 cookie 名称

[Back to MCD](#twaf_anti_mal_crawler)

mal_cookie_name
---------------
**syntax:** *mal_cookie_name <string>*

**default:** *TWAF_mcrawler*

**context:** *twaf_anti_mal_crawler*

恶意爬虫cookie名称

[Back to MCD](#twaf_anti_mal_crawler)
    
force_scan_robots_state
-----------------------
**syntax:** *force_scan_robots_state true|false*

**default:** *true*

**context:** *twaf_anti_mal_crawler*

页面注入诱捕路径的开关

某些扫描工具不会去访问 /robots.txt，因此在他访问的页面中插入禁爬目录的暗链

[Back to MCD](#twaf_anti_mal_crawler)

force_scan_times
----------------
**syntax:** *force_scan_times <number>*

**default:** *3*

**context:** *twaf_anti_mal_crawler*

注入诱捕路径的页面数

[Back to MCD](#twaf_anti_mal_crawler)

trap_uri
--------
**syntax:** *trap_uri <string>*

**default:** */abc/abc.html*

**context:** *twaf_anti_mal_crawler*

诱捕路径，访问此路径，被标识为恶意爬虫

[Back to MCD](#twaf_anti_mal_crawler)

trap_args
---------
**syntax:** *trap_args <string>*

**default:** *id=1*

**context:** *twaf_anti_mal_crawler*

诱捕参数。携带此参数访问诱捕路径，不会标识为攻击

[Back to MCD](#twaf_anti_mal_crawler)

[Back to twaf_anti_mal_crawler](#twaf_anti_mal_crawler)

[Back to TOC](#table-of-contents)

twaf_reqstat
------------
```txt
    "twaf_reqstat": {
        "state":true,                       -- 统计模块总开关
        "safe_state":true,                  -- 安全信息统计开关
        "access_state":true,                -- 访问信息统计开关
        "upstream_state":true,              -- upstream信息统计开关
        "shared_dict_name":"twaf_reqstat",  -- shm名称
        "shared_dict_key":"policy_id"       -- shm键值。依据此值进行分类统计
    }
    
    PS: 当前统计模块是全局模块，仅支持在twaf_default_conf中进行全局配置，不支持在自定义策略中进行配置
```

state
-----
**syntax:** *state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

统计模块开关，支持动态开关，默认开启

access_state
------------
**syntax:** *access_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

访问信息统计开关，支持动态开关，默认开启

safe_state
----------
**syntax:** *safe_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

安全信息统计开关，支持动态开关，默认开启

upstream_state
--------------
**syntax:** *upstream_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

转发信息统计开关，支持动态开关，默认开启

shared_dict_name
----------------
**syntax:** *shared_dict_name string*

**default:** *twaf_reqstat*

**context:** *twaf_reqstat*

指定shared_dict名称，在这之前需在nginx配置文件中配置[lua_shared_dict](https://github.com/openresty/lua-nginx-module#lua_shared_dict) <name> <size>

shared_dict_key
---------------
**syntax:** *shared_dict_key string*

**default:** *policyid*

**context:** *twaf_reqstat*

string类型。指定shm键值。依据此值进行分类统计。

如：值设为 policyid，则统计每一个策略相关的access、safe和upstream信息。

如：值设为 userid，则统计每一个用户相关的access、safe和upstream信息。

如：值设为 access_id，则统计每一个接入规则相关的access、safe和upstream信息。

[Back to twaf_reqstat](#twaf_reqstat)

[Back to TOC](#table-of-contents)

twaf_log
--------
```txt
"twaf_log": {
        "access_log_state":true,                         -- 访问日志总开关
        "security_log_state":true,                       -- 安全日志总开关
        "flush_limit":32768,                             -- 缓冲，当存储的日志大于阈值时发送日志
        "size_limit": 200,                               -- 控制日志中每一项的字符上限，如'raw_header'或请求体响应体，可能会使udp日志报错
        "drop_limit":65507,                              -- 缓冲上限，达到此值，丢弃当前日志，发送缓存并清空缓存，当sock_type为udp时，drop_limit值最大为65507（65508会报错message too long）
        "periodic_flush": 2,                             -- flush间隔周期。单位：秒。日志会在达到flush_limit或periodic_flush时输出
        "max_retry_times":5,                             -- 最大容错次数
                                                      -- -- 以下为socket输出日志配置
        "socket_access_log_state": true,                 -- socket模式的访问日志开关
        "socket_security_log_state": true,               -- socket模式的安全日志开关
        "sock_type":"udp",                               -- 支持tcp和udp两种协议
        "content_type":"JSON",                           -- sock支持JSON和INFLUXDB两种日志格式
        "host":"127.0.0.1",                              -- 日志服务器地址
        "port":60055,                                    -- 日志服务器端口号
        "ssl":false,                                     -- 是否开启ssl协议
        "access_log":{},                                 -- 访问日志格式
        "security_log":{},                               -- 安全日志格式
                                                      -- -- 以下为file输出日志配置
        "file_access_log_state": true,                   -- file模式的访问日志开关
        "file_security_log_state": true,                 -- file模式的安全日志开关
        "file_flush": false,                             -- 是否实时写入文件
        "file_content_type": "W3C",                      -- file模式时日志格式，当前仅支持W3C
        "file_access_log_path": "/var/log/openwaf_access.log",      -- file模式的访问日志路径
        "file_security_log_path": "/var/log/openwaf_security.log",  -- file模式的安全日志路径
        "access_log_w3c": "",                            -- file模式访问日志的w3c格式
        "security_log_w3c": ""                           -- file模式安全日志的w3c格式
}
```

access_log_state
----------------
**syntax:** *"access_log_state": true|false*

**default:** *false*

**context:** *twaf_log*

boolean类型，访问日志总开关，默认关闭。

security_log_state
------------------
**syntax:** *"security_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

boolean类型，安全事件日志总开关，默认开启

flush_limit
-----------
**syntax:** *"flush_limit": number*

**default:** *32768*

**context:** *twaf_log*

number类型。缓冲区大小，当存储的日志大于阈值才发送，默认值为32768

v0.0.6及之前版本默认值为0，即立刻发送日志，不进行缓存。

v1.0.0β版本开始，默认值为32768。

日志输出控制条件，还与 periodic_flush 参数有关.

size_limit
----------
**syntax:** *"size_limit": number*

**default:** *200*

**context:** *twaf_log*

number类型。控制日志中每一项的字符上限。单位：字节。

若'raw_header'或请求体响应体过长，可能会使udp日志报错

drop_limit
----------
**syntax:** *"drop_limit": number*

**default:** *65507*

**context:** *twaf_log*

number类型。缓冲上限，达到此值，丢弃当前日志，发送缓存并清空缓存，当sock_type为udp时，drop_limit值最大为65507（65508会报错message too long）

periodic_flush
--------------
**syntax:** *"periodic_flush": number*

**default:** *2*

**context:** *twaf_log*

number类型。日志flush间隔周期。单位：秒。

日志会在满足 flush_limit 或 periodic_flush 条件时输出

max_retry_times
---------------
**syntax:** *"max_retry_times": number*

**default:** *5*

**context:** *twaf_log*

number类型。最大容错次数

socket_access_log_state
-----------------------
**syntax:** *"socket_access_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

boolean类型，socket模式的访问日志开关

socket_security_log_state
-------------------------
**syntax:** *"socket_security_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

boolean类型，socket模式的安全日志开关

sock_type
---------
**syntax:** *"sock_type": tcp|udp*

**default:** *udp*

**context:** *twaf_log*

日志传输协议，默认udp

content_type
------------
**syntax:** *"content_type": JSON|INFLUXDB*

**default:** *JSON*

**context:** *twaf_log*

日志格式，默认JSON

host
----
**syntax:** *"host": string*

**default:** *"127.0.0.1"*

**context:** *twaf_log*

日志接收服务器的ip地址

port
----
**syntax:** *"port": number*

**default:** *60055*

**context:** *twaf_log*

日志接收服务器的端口号

ssl
---
**syntax:** *"ssl": true|false*

**default:** *false*

**context:** *twaf_log*

是否开启ssl协议，默认false

access_log
----------
**syntax:** *"access_log": table*

**default:** *false*

**context:** *twaf_log*

table类型。访问日志格式。格式详见 security_log 说明.

security_log
------------
**syntax:** *"security_log": table*

**default:** *false*

**context:** *twaf_log*

安全事件日志格式

若content_type为JSON，则日志格式为
```
[
    variable_key_1, 
    variable_key_2, 
    ...
]
```
若content_type为INFLUXDB，则日志格式为
```
{
    "db":MEASUREMENT名称, 
    "tags":[variable_key_1, variable_key_2, ...], 
    "fileds"[variable_key_1, variable_key_2, ...],
    "time":true|false
}
```

变量名称详见规则引擎模块 [twaf_secrules](https://github.com/titansec/OpenWAF#variables) 

```
    #日志格式举例
        #JSON格式
        "security_log": [
            "remote_addr",
            "remote_port",
            "userid",
            "dev_uuid",
            "original_dst_addr",
            "original_dst_port",
            "remote_user",
            "time_local",
            "msec",
            "request_method",
            "request_uri",
            "request_protocol",
            "status",
            "bytes_sent",
            "http_referer",
            "http_user_agent",
            "gzip_ratio",
            "http_host",
            "raw_header",
            "%{request_headers.host}"
        ]

        #INFLUXDB格式
        "security_log": {
            "db":"test",                  -- MEASUREMENT名称
            "tags":[],                    -- tags keys
            "fileds":[                    -- fileds keys
                "remote_addr",
                "remote_port",
                "userid",
                "dev_uuid",
                "original_dst_addr",
                "original_dst_port",
                "remote_user",
                "time_local",
                "msec",
                "request_method",
                "request_uri",
                "request_protocol",
                "status",
                "bytes_sent",
                "http_referer",
                "http_user_agent",
                "gzip_ratio",
                "http_host",
                "raw_header",
                "%{request_headers.host}"
            ],
            "time":true                   -- 日志是否携带时间戳
        }
        
    PS: JSON 和 INFLUXDB 格式的 access_log 和 security_log 支持自定义变量
        如上述举例，为了获取到 request_headers 中的 host 值，因此配置 "%{request_headers.host}"
```

file_access_log_state
---------------------
**syntax:** *"file_access_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

boolean类型。file模式的访问日志开关

file_security_log_state
-----------------------
**syntax:** *"file_security_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

boolean类型。file模式的安全日志开关

file_flush
----------
**syntax:** *"file_flush": true|false*

**default:** *false*

**context:** *twaf_log*

boolean类型。是否实时写入文件

file_content_type
-----------------
**syntax:** *"file_content_type": W3C*

**default:** *W3C*

**context:** *twaf_log*

string类型。file模式时日志格式，当前仅支持W3C

file_access_log_path
--------------------
**syntax:** *"file_access_log_path": path*

**default:** *"/var/log/openwaf_access.log"*

**context:** *twaf_log*

string类型。file模式的访问日志路径

file_security_log_path
----------------------
**syntax:** *"file_security_log_path": path*

**default:** *"/var/log/openwaf_security.log"*

**context:** *twaf_log*

string类型。file模式的安全日志路径

access_log_w3c
--------------
**syntax:** *"access_log_w3c": string*

**default:** *详见说明*

**context:** *twaf_log*

string类型。file模式访问日志的w3c格式

```
默认值为："%{remote_addr} - %{remote_user} [%{time_local}] \"%{request_method} %{request_uri} %{request_protocol}\" %{response_status} %{bytes_sent} \"%{http_referer}\" \"%{http_user_agent}\" %{userid} %{server_addr}:%{server_port} \"%{http_host}\" %{request_time} %{policyid} %{unique_id} %{api_id}"
```

变量名称详见规则引擎模块 [twaf_secrules](https://github.com/titansec/OpenWAF#variables) 

security_log_w3c
----------------
**syntax:** *"security_log_w3c": string*

**default:** *详见说明*

**context:** *twaf_log*

string类型。file模式安全日志的w3c格式

```
默认值为："%{remote_addr} - %{remote_user} [%{time_local}] \"%{request_method} %{request_uri} %{request_protocol}\" %{response_status} %{bytes_sent} \"%{http_referer}\" \"%{http_user_agent}\" %{userid} %{server_addr}:%{server_port} \"%{http_host}\" %{request_time} %{policyid} %{category} %{severity} %{action} %{id} %{rule_name} %{unique_id} %{api_id}"
```

变量名称详见规则引擎模块 [twaf_secrules](https://github.com/titansec/OpenWAF#variables) 

[Back to twaf_log](#twaf_log)

[Back to TOC](#table-of-contents)

twaf_secrules
-------------
```txt
    "twaf_secrules":{
        "state": true,                                              -- 总开关
        "reqbody_state": true,                                      -- 请求体检测开关
        "header_filter_state": true,                                -- 响应头检测开关
        "body_filter_state": true,                                  -- 响应体检测开关
        "system_rules_state": true,                                 -- 系统规则集检测开关
        "reqbody_limit":134217728,                                  -- 请求体检测阈值，大于阈值不检测
        "respbody_limit":524288,                                    -- 响应体检测阈值，大于阈值不检测
        "pre_path": "/opt/OpenWAF/",                                -- OpenWAF安装路径
        "path": "lib/twaf/inc/knowledge_db/twrules",                -- 特征规则库在OpenWAF中的路径
        "user_defined_rules":[ ],                                   -- 用户自定义规则，数组
        "rules_id":{                                                -- 特征排除
            "111112": [{"REMOTE_HOST":"a.com", "URI":"^/ab"}],      -- 匹配中数组中信息则对应规则失效，数组中key为变量名称，值支持正则
            "111113": {},                                           -- 特征未被排除
            "111114": [{}]                                          -- 特征被无条件排除
        },
        "ruleset_ids": [                                            -- 规则集引用。若 ruleset_ids 值为空，则默认所有的规则都生效(用于兼容无ruleset_ids的旧版本)
            "set_123456789",
            "set_987654321"
        ]
    }
```

state
-----
**syntax:** *state true|false*

**default:** *true*

**context:** *twaf_secrules*

规则引擎总开关

reqbody_state
-------------
**syntax:** *reqbody_state true|false*

**default:** *true*

**context:** *twaf_secrules*

请求体检测开关

header_filter_state
-------------------
**syntax:** *header_filter_state true|false*

**default:** *true*

**context:** *twaf_secrules*

响应头检测开关

body_filter_state
-----------------
**syntax:** *body_filter_state true|false*

**default:** *false*

**context:** *twaf_secrules*

响应体检测开关，默认关闭，若开启需添加第三方模块[ngx_http_twaf_header_sent_filter_module暂未开源]

system_rules_state
-----------------
**syntax:** *system_rules_state true|false*

**default:** *true*

**context:** *twaf_secrules*

系统规则集检测开关

lib/twaf/inc/knowledge_db/twrules 目录下的规则，都是系统规则

除了系统规则外，还有 twaf_secrules 模块下 user_defined_rules 的用户自定义规则

系统规则一般很少改动，而用户自定义规则却随着业务而增减，如动态配置缓存、压缩、时域控制和黑白名单等。

reqbody_limit
-------------
**syntax:** *reqbody_limit number*

**default:** *134217728*

**context:** *twaf_secrules*

请求体检测大小上限，默认134217728B(128MB)，若请求体超过设置上限，则不检测

PS：reqbody_limit值要小于nginx中client_body_buffer_size的值才会生效

respbody_limit
--------------
**syntax:** *respbody_limit number*

**default:** *134217728*

**context:** *twaf_secrules*

响应体检测大小上限，默认134217728B(128MB)，若响应体大小超过设置上限，则不检测

pre_path
--------
**syntax:** *pre_path string*

**default:** */opt/OpenWAF/*

**context:** *twaf_secrules*

OpenWAF的安装路径

path
----
**syntax:** *path string*

**default:** *lib/twaf/inc/knowledge_db/twrules*

**context:** *twaf_secrules*

特征规则库在OpenWAF中的路径

user_defined_rules
------------------
**syntax:** *user_defined_rules <array>*

**default:** *[]*

**context:** *twaf_secrules*

策略下的用户自定义特征规则

先执行用户自定义规则，再执行系统规则

系统特征规则适用于所有的策略，在引擎启动时通过加载特征库或通过 API 加载系统特征规则，系统特征规则一般不会动态更改

用户自定义特征在策略下生效，一般用于变动较大的特征规则，如：时域控制，修改响应头等临时性规则

```json
"user_defined_rules":[
    {
        "id": "1000001",
        "release_version": "858",
        "charactor_version": "001",
        "disable": false,
        "opts": {
            "nolog": false
        },
        "phase": "access",
        "action": "deny",
        "meta": 403,
        "severity": "high",
        "rule_name": "relative time",
        "desc": "周一至周五的8点至18点，禁止访问/test目录",
        "match": [{
            "vars": [{
                "var": "URI"
            }],
            "operator": "begins_with",
            "pattern": "/test"
        },
        {
            "vars": [{
                "var": "TIME_WDAY"
            }],
            "operator": "equal",
            "pattern": ["1", "2", "3", "4", "5"]
        },
        {
            "vars": [{
                "var": "TIME"
            }],
            "operator": "str_range",
            "pattern": ["08:00:00-18:00:00"]
        }]
    },
    {
        "id": "1000002",
        "release_version": "858",
        "charactor_version": "001",
        "disable": false,
        "opts": {
            "nolog": false
        },
        "phase": "access",
        "action": "deny",
        "meta": 403,
        "severity": "high",
        "rule_name": "iputil",
        "desc": "某ip段内不许访问",
        "match": [{
            "vars": [{
               "var": "REMOTE_ADDR"
            }],
            "operator": "ip_utils",
            "pattern": ["1.1.1.0/24","2.2.2.2-2.2.20.2"]
        }]
    }
]
```
        
rules_id
--------
**syntax:** *rules_id table*

**default:** *none*

**context:** *twaf_secrules*

用于排除特征

ruleset_ids
-----------
**syntax:** *ruleset_ids table*

**default:** *none*

**context:** *twaf_secrules*

table类型。规则集引用,用于不同策略加载不同的规则进行防护。从 v1.0.0β 版本开始引入规则集。

若 ruleset_ids 值为空，则默认引用所有加载的规则。

若 ruleset_ids 值为空数组，则无任何规则生效。

```
    "ruleset_ids": [       -- 有序引用 set_123456789 与 set_987654321 两个规则集。
        "set_123456789",
        "set_987654321"
    ]
    
    PS： 当前规则集有关具体配置仅支持通过rule_set API进行配置
```

[Back to twaf_secrules](#twaf_secrules)

[Back to TOC](#table-of-contents)

twaf_anti_cc
------------

```txt
{
    "twaf_limit_conn": {
        "state":false,                                       -- CC防护模块开关
        "log_state":true,                                    -- CC日志开关
        "trigger_state":true,                                -- 触发开关
        "clean_state":true,                                  -- 清洗开关
        "trigger_thr":{                                      -- 触发阈值（关系为“或”）
            "req_flow_max":1073741824,                       -- 每秒请求流量，单位B
            "req_count_max":10000                            -- 每秒请求数
        },
        "clean_thr":{                                        -- 清洗阈值
            "new_conn_max":40,                               -- 单一源ip每秒新建连接数
            "conn_max":100,                                  -- 单一源ip防护期间内连接总数
            "req_max":50,                                    -- 单一源ip每秒请求总数
            "uri_frequency_max":3000                         -- 单一路径每秒请求总数
        },
        "attacks": 1,                                        -- 在一次CC攻击过程中，某ip触发清洗值的次数大于attacks，则此ip会一直被拦截，直到CC攻击结束
        "timer_flush_expired":10,                            -- 清理shared_dict过期数据的时间间隔
        "interval":10,                                       -- 进入CC防护后发送日志的时间间隔，单位秒
        "shared_dict_name":"twaf_limit_conn",                -- 存放其他信息的shared_dict
        "shared_dict_key": "remote_addr",                    -- shared_dict的键值
        "action":"DENY",                                     -- 触发CC防护执行的动作
        "action_meta":403,
        "timeout":30                                         -- 清洗时长（当再次触发清洗值时，重置）
    }
}
```

rules
-----
**syntax:** *"state": true|false*

**default:** *false*

**context:** *twaf_limit_conn*

boolean类型，CC防护模块总开关，默认关闭

log_state
---------
**syntax:** *"log_state": true|false*

**default:** *true*

**context:** *twaf_limit_conn*

boolean类型，CC防护模块日志开关，默认开启

trigger_state
-------------
**syntax:** *"trigger_state": true|false*

**default:** *true*

**context:** *twaf_limit_conn*

boolean类型，CC防护模块的触发开关，默认开启

若关闭，则触发机制关闭，时刻进入CC清洗状态

clean_state
-----------
**syntax:** *"clean_state": true|false*

**default:** *true*

**context:** *twaf_limit_conn*

boolean类型，CC防护模块总开关，默认开启

若关闭（仅用于测试），则清洗机制关闭，CC模块将无法拦截请求

trigger_thr
-----------
**syntax:** *"trigger_thr": table*

**default:** *{"req_flow_max":1073741824,"req_count_max":10000}*

**context:** *twaf_limit_conn*

table类型，触发阈值

当达到其中一个触发阈值，进入CC清洗状态

当前有两个触发阈值  
```txt
    "trigger_thr":{                                      -- 触发阈值（关系为“或”）
        "req_flow_max":1073741824,                       -- 每秒请求流量，单位B，默认1GB/s
        "req_count_max":10000                            -- 每秒请求数，默认10000个/秒
    }
```

clean_thr
---------
**syntax:** *"clean_thr": table*

**default:** *{"new_conn_max":40,"conn_max":100,"req_max":50,"uri_frequency_max":3000}*

**context:** *twaf_limit_conn*

table类型，清洗阈值

当进入CC清洗状态，达到其中一个清洗阈值，则执行相应动作

当前有四个清洗阈值  
```txt
    "clean_thr":{                                        -- 清洗阈值（关系为“或”）
        "new_conn_max":40,                               -- 单一源ip每秒新建连接数，默认40个/秒
        "conn_max":100,                                  -- 单一源ip防护期间内连接总数，默认100个
        "req_max":50,                                    -- 单一源ip每秒请求总数，默认50个/秒
        "uri_frequency_max":3000                         -- 单一路径每秒请求总数，默认3000个/秒
    }
```

attacks
-------
**syntax:** *"attacks": number*

**default:** *1*

**context:** *twaf_limit_conn*

在一次 CC 攻击过程中，某ip触发清洗阈值的次数大于 attacks ，则此 ip 会一直被拦截，直到 CC 攻击结束

此前，在一次 CC 攻击过程中，当达到清洗阈值时，才会进行拦截。若未达到清洗阈值，即使之前被拦截过，也可正常访问后端服务器

正确设置此参数，可以大大提升 CC 防护性能

若想恢复以前的 CC 防护机制，只需 attacks 设为 0 即可

此参数出现在 OpenWAF-0.0.6 版本， twaf_anti_cc 的 0.0.3 版本

timer_flush_expired
-------------------
**syntax:** *"timer_flush_expired": number*

**default:** *10*

**context:** *twaf_limit_conn*

number类型，清理shared_dict过期数据的时间间隔，默认10秒

interval
--------
**syntax:** *"interval": number*

**default:** *10*

**context:** *twaf_limit_conn*

number类型，进入CC防护后发送日志的时间间隔，默认10秒

shared_dict_name
----------------
**syntax:** *"shared_dict_name": string*

**default:** *"twaf_limit_conn"*

**context:** *twaf_limit_conn*

string类型，存放当前CC防护信息的shared_dict名称

shared_dict_key
---------------
**syntax:** *"shared_dict_key": string|table*

**default:** *"remote_addr"*

**context:** *twaf_limit_conn*

string或table类型，shared_dict的键值，支持nginx变量

支持字符串类型和数组类型
```
    "shared_dict_key": "remote_addr"
    
    "shared_dict_key": ["remote_addr", "http_user_agent"]
```

action
------
**syntax:** *"action": string*

**default:** *"DENY"*

**context:** *twaf_limit_conn*

string类型，触发CC防护执行的动作，默认"DENY"

action_meta
-----------
**syntax:** *"action_meta": number|string*

**default:** *403*

**context:** *twaf_limit_conn*

string或number类型，执行动作的附属信息，默认403

timeout
-------
**syntax:** *"timeout": number*

**default:** *30*

**context:** *twaf_limit_conn*

number类型，清洗时长，N秒内不再达到触发阈值，则退出CC清洗状态

在清洗过程中，再次达到触发阈值，则时间重置为30秒

[Back to TOC](#table-of-contents)

Nginx Variables
===============

$twaf_https
-----------
**syntax:** *set $twaf_https 0|1*

**default:** *0*

**context:** *server*

用于标记请求是否通过ssl加密

"set $twaf_https 1"，则表示请求通过ssl加密

"set $twaf_https 0"，则表示请求未通过ssl加密

```
server {
    listen 443 ssl;
    set $twaf_https 1;
    ...
}

server {
    listen 80;
    set $twaf_https 0;
    ...
}
```

$twaf_upstream_server
---------------------
**syntax:** *set $twaf_upstream_server ""*

**default:** *none*

**context:** *server*

用于指定后端服务器地址，只需初始化为空字符串即可，其值由"server_ssl"和"forward"确定

```
upstream server_1 {
    ...
}

upstream server_2 {
    ...
}

server {
    ...
    
    set $twaf_upstream_server "";
    location / {
        ...
        proxy_pass $twaf_upstream_server;
    }
}

若"server_ssl"值为true, "forward"值为"server_1"
等价于proxy_pass https://server_1;

若"server_ssl"值为false, "forward"值为"server_2"
等价于proxy_pass http://server_2;
```

[Back to TOC](#table-of-contents)

SecRules
========

Variables
---------
* [ARGS](#args)
* [ARGS_COMBINED_SIZE](#args_combined_size)
* [ARGS_GET](#args_get)
* [ARGS_GET_NAMES ](#args_get_names)
* [ARGS_NAMES](#args_names)
* [ARGS_POST ](#args_post)
* [ARGS_POST_NAMES ](#args_post_names)
* [BYTES_IN](#bytes_in)
* [CONNECTION_REQUESTS](#connection_requests)
* [DURATION](#duration)
* [FILES](#files)
* [FILES_NAMES](#files_names)
* [GEO](#geo)
* [GEO_CODE3](#geo_code3)
* [GEO_CODE3](#geo_code)
* [GEO_ID](#geo_id)
* [GEO_CONTINENT](#geo_continent)
* [GEO_NAME](#geo_name)
* [GZIP_RATIO](#gzip_ratio)
* [HTTP_COOKIE](#http_cookie)
* [HTTP_HOST](#http_host)
* [HTTP_REFERER](#http_referer)
* [HTTP_USER_AGENT](#http_user_agent)
* [IP_VERSION](#ip_version)
* [MATCHED_VAR](#matched_var)
* [MATCHED_VARS](#matched_vars)
* [MATCHED_VAR_NAME](#matched_var_name)
* [MATCHED_VARS_NAMES](#matched_var_names)
* [ORIGINAL_DST_ADDR](#original_dst_addr)
* [ORIGINAL_DST_PORT](#original_dst_port)
* [POLICYID](#policyid)
* [QUERY_STRING](#query_string)
* [RAW_HEADER](#raw_header)
* [RAW_HEADER_TRUE](#raw_header_true)
* [REMOTE_ADDR](#remote_addr)
* [REMOTE_HOST](#remote_host)
* [REMOTE_PORT](#remote_port)
* [REMOTE_USER](#remote_user)
* [REQUEST_BASENAME](#request_basename)
* [REQUEST_BODY](#request_body)
* [REQUEST_COOKIES](#request_cookies)
* [REQUEST_COOKIES_NAMES](#request_cookies_names)
* [REQUEST_FILENAME](#request_filename)
* [REQUEST_HEADERS](#request_headers)
* [REQUEST_HEADERS_NAMES](#request_headers_names)
* [REQUEST_LINE](#request_line)
* [REQUEST_METHOD](#request_method)
* [REQUEST_PROTOCOL](#request_protocol)
* [HTTP_VERSION](#http_version)
* [URI](#uri)
* [URL](#url)
* [REQUEST_URI](#request_uri)
* [RESPONSE_BODY](#response_body)
* [RESPONSE_HEADERS](#response_headers)
* [RESPONSE_STATUS](#response_status)
* [SCHEME](#scheme)
* [SERVER_ADDR](#server_addr)
* [SERVER_NAME](#server_name)
* [SERVER_PORT](#server_port)
* [SESSION](#session)
* [SESSION_DATA](#session_data)
* [TIME](#time)
* [TIME_DAY](#time_day)
* [TIME_EPOCH](#time_epoch)
* [TIME_HOUR](#time_hour)
* [TIME_MIN](#time_min)
* [TIME_MON](#time_mon)
* [TIME_SEC](#time_sec)
* [TIME_WDAY](#time_wday)
* [TIME_YEAR](#time_year)
* [TIME_LOCAL](#time_local)
* [TX](#tx)
* [UNIQUE_ID](#unique_id)
* [UPSTREAM_CACHE_STATUS](#upstream_cache_status)
* [USERID](#userid)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS
----
table类型，所有的请求参数，包含ARGS_GET和ARGS_POST

```
例如：POST http://www.baidu.com?name=miracle&age=5

请求体为：time=123456&day=365

ARGS变量值为{"name": "miracle", "age": "5", "time": "123456", "day": "365"}
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_COMBINED_SIZE
------------------
number类型，请求参数总长度，只包含key和value的长度，不包含'&'或'='等符号

```
例如：GET http://www.baidu.com?name=miracle&age=5

ARGS_COMBINED_SIZE变量值为15，而不是18
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_GET
--------
table类型，querystring参数

```
例如：GET http://www.baidu.com?name=miracle&age=5

ARGS_GET变量值为{"name": "miracle", "age": "5"}
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_GET_NAMES
--------------
table类型，querystring参数key值

```
例如：GET http://www.baidu.com?name=miracle&age=5

ARGS_GET_NAMES变量值为["name", "age"]
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_NAMES
----------
table类型，querystring参数key值及post参数key值

```
例如：POST http://www.baidu.com?name=miracle&age=5

请求体为：time=123456&day=365

ARGS_NAMES变量值为["name", "age", "time", "day"]
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_POST
---------
table类型，POST参数

```
例如：

POST http://www.baidu.com/login.html

请求体为：time=123456&day=365

ARGS_POST变量值为{"time": "123456", "day": "365"}
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ARGS_POST_NAMES
---------------
table类型，POST参数key值

```
例如：

POST http://www.baidu.com/login.html

请求体为：time=123456&day=365

ARGS_POST_NAMES变量值为["time", "day"]
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

BYTES_IN
--------
number类型，接收信息字节数

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

CONNECTION_REQUESTS
-------------------
number类型，当前连接中的请求数

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

DURATION
--------
string类型，处理事务用时时间，单位:微秒(μs)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

FILES
-----
table类型，从请求体中得到的原始文件名(带有文件后缀名)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

FILES_NAMES
-----------
table类型，上传文件名称（不带有后缀名）

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO
---
table类型，包含code3,code,id,continent,name等字段信息

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO_CODE3
---------
string类型，3个字母长度的国家缩写

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO_CODE
--------
string类型，2个字母长度的国家缩写

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO_ID
------
number类型，国家ID

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO_CONTINENT
-------------
string类型，国家所在大洲

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GEO_NAME
--------
string类型，国家全称

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

GZIP_RATIO
----------
string类型，压缩比率

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

HTTP_COOKIE
-----------
string类型，请求头中的cookie字段

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

HTTP_HOST
---------
string类型，请求头中的host字段值，既域名:端口(80缺省)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

HTTP_REFERER
------------
string类型，请求头中的referer字段

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

HTTP_USER_AGENT
---------------
string类型，请求头中的user-agent字段

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

IP_VERSION
----------
string类型，IPv4 or IPv6

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

MATCHED_VAR
-----------
类型不定，当前匹配中的变量

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

MATCHED_VARS
------------
table类型，单条规则匹配中的所有变量

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

MATCHED_VAR_NAME
----------------
string类型，当前匹配中的变量名称

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

MATCHED_VARS_NAMES
------------------
table类型，单条规则匹配中的所有变量名称

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ORIGINAL_DST_ADDR
-----------------
string类型，服务器地址，应用代理模式为WAF地址，透明模式为后端服务器地址

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

ORIGINAL_DST_PORT
-----------------
string类型，服务器端口号，应用代理模式为WAF端口号，透明模式为后端服务器端口号

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

POLICYID
--------
string类型，策略ID

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

QUERY_STRING
------------
string类型，未解码的请求参数

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

RAW_HEADER
----------
string类型，请求头信息，带请求行

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

RAW_HEADER_TRUE
---------------
string类型，请求头信息，不带请求行

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REMOTE_ADDR
-----------
string类型，客户端地址

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REMOTE_HOST
-----------
string类型，域名

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REMOTE_PORT
-----------
number类型，端口号

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REMOTE_USER
-----------
string类型，用于身份验证的用户名

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_BASENAME
----------------
string类型，请求的文件名

```
例如: GET http://www.baidu.com/test/login.php

REQUEST_BASENAME值为/login.php
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_BODY
------------
类型不定，请求体

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_COOKIES
---------------
table类型，请求携带的cookie

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_COOKIES_NAMES
---------------------
table类型，请求携带cookie的名称

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_FILENAME
----------------
string类型，relative request URL(相对请求路径)

```
例如: GET http://www.baidu.com/test/login.php

REQUEST_FILENAME值为/test/login.php
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_HEADERS
---------------
table类型，请求头信息

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_HEADERS_NAMES
---------------------
table类型，请求头key值

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_LINE
------------
string类型，请求行

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_METHOD
--------------
string类型，请求方法

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_PROTOCOL
----------------
string类型，http请求协议，如: HTTP/1.1

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

HTTP_VERSION
------------
number类型，http请求协议版本，如: 1, 1.1, 2

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

URI
---
string类型，请求路径，既不带域名，也不带参数

```
例如: GET http://www.baid.com/test/login.php?name=miracle

URI变量值为/test/login.php
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

URL
---
string类型，统一资源定位符，SCHEME与HTTP_HOST与URI的拼接

```
例如: GET http://www.baid.com/test/login.php?name=miracle

URL变量值为http://www.baid.com/test/login.php
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

REQUEST_URI
-----------
string类型，请求路径，带参数，但不带有域名

```
例如: GET http://www.baid.com/test/login.php?name=miracle

REQUEST_URI变量值为/test/login.php?name=miracle
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

RESPONSE_BODY
-------------
string类型，响应体

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

RESPONSE_HEADERS
----------------
table类型，响应头信息

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

RESPONSE_STATUS
---------------
function类型，响应状态码

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SCHEME
------
string类型，http or https

```
例如：GET http://www.baidu.com/

SCHEME变量值为http
```

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SERVER_ADDR
-----------
string类型，服务器地址

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SERVER_NAME
-----------
string类型，服务器名称

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SERVER_PORT
-----------
number类型，服务器端口号

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SESSION
-------
table类型，第三方模块lua-resty-session提供的变量

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

SESSION_DATA
------------
table类型，session信息，第三方模块lua-resty-session提供的变量

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME
----
string类型，hour:minute:second

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_DAY
--------
number类型，天(1-31)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_EPOCH
----------
number类型，时间戳，seconds since 1970

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_HOUR
---------
number类型，小时(0-23)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_MIN
--------
number类型，分钟(0-59)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_MON
--------
number类型，月份(1-12)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_SEC
--------
number类型，秒(0-59)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_WDAY
---------
number类型，周(0-6)

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_YEAR
---------
number类型，年份，four-digit，例如: 1997

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TIME_LOCAL
----------
string类型，当前时间，例如: 26/Aug/2016:01:32:16 -0400

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

TX
--
table类型，用于存储当前请求信息的变量，作用域仅仅是当前请求

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

UNIQUE_ID
---------
string类型，ID标识，随机生成的字符串，可通过配置来控制随机字符串的长度

从 v1.0.0β 版本开始，默认34位自定义随机字符串 改为从 ngx.request_id 变量获取的 16/32 位随机字符串

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

UPSTREAM_CACHE_STATUS
---------------------
keeps the status of accessing a response cache (0.8.3). The status can be either “MISS”, “BYPASS”, “EXPIRED”, “STALE”, “UPDATING”, “REVALIDATED”, or “HIT”.

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

USERID
------
string类型，从接入规则配置得到的用于ID标识

[Back to Var](#variables)

[Back to TOC](#table-of-contents)

Transformation Functions
------------------------
* [base64_decode](#base64_decode)
* [sql_hex_decode](#sql_hex_decode)
* [base64_encode](#base64_encode)
* [counter](#counter)
* [compress_whitespace ](#compress_whitespace )
* [hex_decode](#hex_decode)
* [hex_encode](#hex_encode)
* [html_decode](#html_decode)
* [length](#length)
* [lowercase](#lowercase)
* [md5](#md5)
* [normalise_path](#normalise_path)
* [remove_nulls](#remove_nulls)
* [remove_whitespace](#remove_whitespace)
* [replace_comments](#replace_comments)
* [remove_comments_char](#remove_comments_char)
* [remove_comments](#remove_comments)
* [uri_decode](#uri_decode)
* [uri_encode](#uri_encode)
* [sha1](#sha1)
* [trim_left](#trim_left)
* [trim_right](#trim_right)
* [trim](#trim)

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

base64_decode
-------------
Decodes a Base64-encoded string.

Note: 注意transform的执行顺序

```
例如：
{
   "id": "xxxx",
   ...
   "transform": ["base64_decode", "lowercase"],
   ...
}

先执行base64解码，然后字符串最小化，若顺序调换，会影响结果
```

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

sql_hex_decode
--------------
Decode sql hex data.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

base64_encode
-------------
Encodes input string using Base64 encoding.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

counter
-------
计数，相当于modsecurity中的'&'符号

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

compress_whitespace
-------------------
Converts any of the whitespace characters (0x20, \f, \t, \n, \r, \v, 0xa0) to spaces (ASCII 0x20), compressing multiple consecutive space characters into one.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

hex_decode
----------
Decodes a string that has been encoded using the same algorithm as the one used in hexEncode 

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

hex_encode
----------
Encodes string (possibly containing binary characters) by replacing each input byte with two hexadecimal characters.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

html_decode
-----------
Decodes the characters encoded as HTML entities.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

length
------
Looks up the length of the input string in bytes

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

lowercase
---------
Converts all characters to lowercase

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

md5
---
Calculates an MD5 hash from the data in input. The computed hash is in a raw binary form and may need encoded into text to be printed (or logged). Hash functions are commonly used in combination with hex_encode (for example: "transform": ["md5", "hex_encode").

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

normalise_path
--------------
Removes multiple slashes, directory self-references, and directory back-references (except when at the beginning of the input) from input string.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

remove_nulls
------------
Removes all NUL bytes from input

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

remove_whitespace
-----------------
Removes all whitespace characters from input.

移除空白字符\s，包含水平定位字符 ('\t')、归位键('\r')、换行('\n')、垂直定位字符('\v')或翻页('\f')等

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

replace_comments
----------------
用一个空格代替/*...*/注释内容

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

remove_comments_char
--------------------
Removes common comments chars (/*, */, --, #).

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

remove_comments
---------------
去掉/*...*/注释内容

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

uri_decode
----------
Unescape str as an escaped URI component.

```
例如: 
"b%20r56+7" 使用uri_decode转换后为 b r56 7
```

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

uri_encode
----------
Escape str as a URI component.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

sha1
----
Calculates a SHA1 hash from the input string. The computed hash is in a raw binary form and may need encoded into text to be printed (or logged). Hash functions are commonly used in combination with hex_encode (for example, "transform": ["sha1", "hex_encode"]).

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

trim_left
---------
Removes whitespace from the left side of the input string.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

trim_right
----------
Removes whitespace from the right side of the input string.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

trim
----
Removes whitespace from both the left and right sides of the input string.

[Back to TFF](#transformation-functions)

[Back to TOC](#table-of-contents)

Operators
---------

* [begins_with](#begins_with)
* [contains](#contains)
* [contains_word](#contains_word)
* [detect_sqli](#detect_sqli)
* [detect_xss](#detect_xss)
* [ends_with](#ends_with)
* [equal](#equal)
* [greater_eq](#greater_eq)
* [greater](#greater)
* [ip_utils](#ip_utils)
* [less_eq](#less_eq)
* [less](#less)
* [num_range](#num_range)
* [regex](#regex)
* [str_match](#str_match)
* [str_range](#str_range)
* [validate_url_encoding](#validate_url_encoding)

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

begins_with
-----------
Returns true if the parameter string is found at the beginning of the input.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

contains
--------
Returns true if the parameter string is found anywhere in the input.

operator 为 contains 且 pattern 为数组，等价于 modsecurity 的 pm

PS: modsecurity的pm忽略大小写，OpenWAF中contains不忽略大小写

```
例如:
{
    "id": "xxx",
    ...
    "operator": "contains",
    "pattern": ["abc", "def"],
    ...
}
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

contains_word
-------------
Returns true if the parameter string (with word boundaries) is found anywhere in the input.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

detect_sqli
-----------
This operator uses LibInjection to detect SQLi attacks.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

detect_xss
----------
This operator uses LibInjection to detect XSS attacks.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

ends_with
---------
Returns true if the parameter string is found at the end of the input.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

equal
-----
Performs a string comparison and returns true if the parameter string is identical to the input string.

等价于 modsecurity 的 eq 和 streq

```
例如:
{
    "id": "xxx",
    ...
    "operator": "equal",
    "pattern": [12345, "html", "23456"]
    ...
}
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

greater_eq
----------
Performs numerical comparison and returns true if the input value is greater than or equal to the provided parameter.

return false, if a value is provided that cannot be converted to a number.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

greater
-------
Performs numerical comparison and returns true if the input value is greater than the operator parameter.

return false, if a value is provided that cannot be converted to a number.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

ip_utils
--------
Performs a fast ipv4 or ipv6 match of REMOTE_ADDR variable data. Can handle the following formats:

Full IPv4 Address: 192.168.1.100
Network Block/CIDR Address: 192.168.1.0/24
IPv4 Address Region: 1.1.1.1-2.2.2.2

从 v1.0.0β 版本开始支持 IPv6，如8888::192.168.1.1

ip_utils与pf的组合相当于modsecurity中的ipMatchF和ipMatchFromFile

```
例如:
规则如下：
{
    "id": "xxxx",
    ...
    "operator": "ip_utils",
    "pf": "/tmp/ip_blacklist.txt",
    ...
}
"/tmp/ip_blacklist.txt"文件内容如下：
192.168.1.100
192.168.1.0/24
1.1.1.1-2.2.2.2
8888::192.168.1.1
8888::1:1
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

less_eq
-------
Performs numerical comparison and returns true if the input value is less than or equal to the operator parameter.

return false, if a value is provided that cannot be converted to a number.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

less
----
Performs numerical comparison and returns true if the input value is less than to the operator parameter.

return false, if a value is provided that cannot be converted to a number.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents

num_range
---------
判断是否在数字范围内

它与transform的length组合，相当于modsecurity的validateByteRange

```
{
    "id": "xxx",
    ...
    "operator": "num_range",
    "pattern": [10, "13", "32-126"],
    "transform": "length",
    ...
}
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

regex
-----
Performs a regular expression match of the pattern provided as parameter. 

regex 等于 rx + capture，即 regex 同时包含 modsecurity 的 rx 功能 和 capture 捕获功能

modsecurity有关capture的描述如下：
When used together with the regular expression operator (@rx), the capture action will create copies of the regular expression captures and place them into the transaction variable collection.

OpenWAF 中无单独的 capture 指令，但使用 regex 默认开启 capture 功能

```
例如:
{
    "id": "000031",
    "release_version": "858",
    "charactor_version": "001",
    "opts": {
        "nolog": false
    },
    "phase": "access",
    "action": "deny",
    "meta": 403,
    "severity": "low",
    "rule_name": "protocol.reqHeader.c",
    "desc": "协议规范性约束，检测含有不合规Range或Request-Range值的HTTP请求",
    "match": [
        {
            "vars": [
                {
                    "var": "REQUEST_HEADERS",
                    "parse": {
                        "specific": "Range"
                    }
                },
                {
                    "var": "REQUEST_HEADERS",
                    "parse": {
                        "specific": "Request-Range"
                    }
                }
            ],
            "operator": "regex",
            "pattern": "(\\d+)\\-(\\d+)\\,"
        },
        {
            "vars": [{
                "var": "TX",
                "parse": {
                    "specific": "2"
                }
            }],
            "operator": "greater_eq",
            "pattern": "%{TX.1}",
            "parse_pattern": true,
            "op_negated": true
        }
    ]
}
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

str_match
---------
等同于contains

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

str_range
---------
判断是否在字符串范围内

```
例如时间区间判断:
{
    "id": "xxx",
    ...
    "operator": "str_range",
    "pattern": ["01:42:00-04:32:00"],
    ...
}
```

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)

validate_url_encoding
---------------------
Validates the URL-encoded characters in the provided input string.

[Back to OPERATORS](#operators)

[Back to TOC](#table-of-contents)


Others
------

* [allow](#allow)
* [allow_phase](#allow_phase)
* [deny](#deny)
* [id](#id)
* [nolog](#nolog)
* [op_negated](#op_negated)
* [parse](#parse)
* [pass](#pass)
* [warn](#warn)
* [audit](#audit)
* [phase](#phase)
* [proxy_cache](#proxy_cache)
* [pf](#pf)
* [pset](#pset)
* [redirect](#redirect)
* [charactor_version](#charactor_version)
* [severity](#severity)
* [setvar](#setvar)
* [meta](#meta)
* [ngx_var](#ngx_var)
* [transform](#transform)
* [tag](#tag)
* [release_version](#release_version)
* [robot](#robot)
* [add_resp_headers](#add_resp_headers)


[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

allow
-----
Stops processing of the current phase but also skipping over all other phases.

```
"action": "allow"
```

一旦执行此动作，则后面的防护规则及其他安全模块均不进行安全检测，此动作一般用于白名单

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

allow_phase
-----------
Stops processing of the current phase.

```
"action": "allow_phase"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

deny
----
Stops rule processing and intercepts transaction.

```
"action": "deny",
"meta": 403
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

id
--
Stops rule processing and intercepts transaction.

```
"id": "xxxxxxx"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

nolog
-----
不记录日志

```
"opts": {
    "nolog": true
}
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

op_negated
----------
对operator结果的取反

```
"match": [{
    "vars": [{
        "var": "HTTP_USER_AGENT"
    }],
    "transform": "length",
    "operator": "less_eq",
    "pattern": 50,
    "op_negated": true
}]

等价于

"match": [{
    "vars": [{
        "var": "HTTP_USER_AGENT"
    }],
    "transform": "length",
    "operator": "greater",
    "pattern": 50
}]

若请求头中user_agent字段长度大于50，则匹配中此条规则
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

parse
-----
对变量进一步解析

```
若请求GET http://www.baidu.com?name=miracle&age=5

"match": [{
    "vars": [{
        "var": "ARGS_GET"
    }]，
    ...
}]
得到的值为{"name": "miracle", "age": "5"}


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "specific": "name"
        }
    }]
}]
得到的值为["miracle"]


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "specific": ["name", "age"]
        }
    }]
}]
得到的值为["miracle", "5"]


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "ignore": "name"
        }
    }]
}]
得到的值为{"age": "5"}


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "ignore": ["name", "age"]
        }
    }]
}]
得到的值为[]


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "keys": true
        }
    }]
}]
得到的值为["name", "age"]


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "values": true
        }
    }]
}]
得到的值为["miracle", "5"]


"match": [{
    "vars": [{
        "var": "ARGS_GET",
        "parse": {
            "all": true
        }
    }]
}]
得到的值为["name", "age", "miracle", "5"]
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

pass
----
Continues processing with the next rule in spite of a successful match.

```
"action": "pass"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

warn
----
like 'pass'

```
"action": "warn"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

audit
-----
like 'pass'

```
"action": "audit"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

phase
-----
规则执行的阶段，取值可为"access","header_filter","body_filter"的组合

```
{
    "id": "xxx_01",
    "phase": "access",
    ...
}
"xxx_01"规则在access阶段执行

{
    "id": "xxx_02",
    "phase": ["access", "header_filter"],
    ...
}
"xxx_02规则在access阶段和"header_filter"阶段各执行一次
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

proxy_cache
-----------
```
{
    ...
    phase = "header_filter",         -- 缓存开关需在header_filter阶段配置
    action = "pass",                 -- 无需拦截请求
    opts = {
        nolog = true,                -- 不需记录日志
        proxy_cache = {
            state = true|false,      -- 缓存开关
            expired = 600            -- 缓存时长（单位秒）,默认600秒
        }
    }
    ...
}

若state为true，且得到的缓存状态为"MISS"或"EXPIRED"，则对响应内容进行缓存，同时设置缓存时长
若state为false，则清除对应缓存键的缓存（包含其缓存文件）
```

举例如下：
```
# nginx.conf 有关proxy cache 配置如下
http {
    proxy_cache_path  /opt/cache/OpenWAF-proxy levels=2:2 keys_zone=twaf_cache:101m max_size=100m use_temp_path=off;
    proxy_cache_key $host$uri;
    proxy_cache twaf_cache;
    proxy_ignore_headers X-Accel-Expires Cache-Control Set-Cookie;
    proxy_no_cache $twaf_cache_flag;
    
    server {
        set $twaf_cache_flag 1;         #默认不缓存
    }
}

# lua 格式 配置
{ 
    id = "test_x01",                      -- id 全局唯一
    opts = {
        nolog = true,
        proxy_cache = {
            state = true,
            expired = 300
        }
    },
    phase = "header_filter", 
    action = "pass",
    match = {{
        vars = {{
            var = "URI"
        },{
            var = "REQUEST_HEADERS",
            parse = {
                specific = "Referer"
            }
        }},
        operator = "equal",
        pattern = {"/xampp/", "%{SCHEME}://%{HTTP_HOST}/xampp/"},
        parse_pattern = true
    }}
}
此规则将缓存URI为'/xampp/'的页面，更新时间为300秒

若match中过滤条件为响应码，则相当于Nginx的proxy_cache_valid指令
若match中过滤条件为请求方法，则相当于Nginx的proxy_cache_methods指令
若macth中过滤条件为资源类型，则相当于Nginx的proxy_cache_content_type指令

PS: proxy_cache_content_type指令为官方指令，是miracle Qi修改Nginx源码扩展的功能
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

pf
----
pattern是operator操作的参数

pf是指pattern from file，与pattern和pset互斥（三者不可同时出现），目前仅支持绝对路径

pf 与 contains 组合，相当于modsecurity的 pmf 或 pmFromFile

pf 与 ip_utils 组合，相当于modsecurity的 ipMatchF 或 ipMatchFromFile

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

pset
----
集合。pattern、pf 和 pset 互斥(只能同时出现一个)。

暂不支持数组。

使用方法详见 https://github.com/titansec/openwaf_api#pset_post

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

redirect
--------
```
"action": "redirect",
"meta": "/index.html"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

charactor_version
-----------------
指定此条规则的版本，同modsecurity中Action的rev功能

```
"charactor_version": "001"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

severity
--------
Assigns severity to the rule in which it is used.

The data below is used by the OWASP ModSecurity Core Rule Set (CRS):

EMERGENCY: is generated from correlation of anomaly scoring data where there is an inbound attack and an outbound leakage.
ALERT: is generated from correlation where there is an inbound attack and an outbound application level error.
CRITICAL: Anomaly Score of 5. Is the highest severity level possible without correlation. It is normally generated by the web attack rules (40 level files).
ERROR: Error - Anomaly Score of 4. Is generated mostly from outbound leakage rules (50 level files).
WARNING: Anomaly Score of 3. Is generated by malicious client rules (35 level files).
NOTICE: Anomaly Score of 2. Is generated by the Protocol policy and anomaly files.
INFO
DEBUG

也可自定义严重等级，如:low，medium，high，critical等

```
"severity": "high"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

setvar
------
Creates, removes, or updates a variable. 

```
{
    "id": "xxx_01",
    "opts":{
        "nolog": false,
        "setvar": [{
            "column": "TX",
            "key": "score",
            "value": 5,
            "incr": true
        }]
    },
    ...
}
"xxx_01"规则中，给变量TX中score成员的值加5，若TX中无score成员，则初始化为0，再加5

{
    "id": "xxx_02",
    "opts":{
        "nolog": false,
        "setvar": [{
            "column": "TX",
            "key": "score",
            "value": 5
        }]
    },
    ...
}

"xxx_02"规则中，给变量TX中score成员的值赋为5
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

meta
----
"action"的附属信息

```
若"action"为"deny"，则"meta"为响应码
"action": "deny",
"meta": 403

若"action"为"redirect"，则"meta"为重定向地址
"action": "redirect",
"meta": "/index.html"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

ngx_var
-------
为 nginx 变量赋值，支持赋值字符串

v1.0.0β版本之后支持赋值变量%{}

```
如在 nginx.conf 中 set $twaf_test "";

可在 secrules 中基于条件动态赋值
"opts": {
    "ngx_var": {
        "twaf_test": "1.1.1.1"      -- 也可赋值变量，如 "twaf_test": "%{remote_addr}"
    }
}
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

transform
---------
This action is used to specify the transformation pipeline to use to transform the value of each variable used in the rule before matching.

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

tag
---
Assigns a tag (category) to a rule.

```
支持数组    "tag": ["xxx_1", "xxx_2"]
支持字符串  "tag": "xxx_3"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

release_version
---------------
规则集版本，等同于modsecurity中Action的ver功能

```
"release_version": "858"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

robot
-----
人机识别

需提前配置人机识别模块配置，此功能暂未放开

```
"action": "robot"
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

add_resp_headers
----------------
增删改响应头

```
例如隐藏server字段:
"opts": {
    "add_resp_headers": {
        "server": ""
    }
}
```

[Back to OTHERS](#others)

[Back to TOC](#table-of-contents)

Donation
========

PayPal
------

[通过 PayPal 来支持 OpenWAF](https://www.paypal.me/miracleqi)

Alipay
------

<img src="http://i.imgur.com/0rSpXc8.png">

WeChat
------

<img src="http://i.imgur.com/FzbU2z4.png">

[Back to TOC](#table-of-contents)
