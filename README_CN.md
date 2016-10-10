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
    * [English Mailing List](#english-mailing-list)
    * [Chinese Mailing List](#chinese-mailing-list)
    * [Personal QQ Mail](#personal-qq-mail)
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
```
1. 下载openresty
   详见 https://openresty.org/en/installation.html
   
   1.1 cd /opt
   1.2 wget -c https://openresty.org/download/openresty-1.11.2.1.tar.gz
   1.3 tar -xzvf openresty-1.11.2.1.tar.gz

2. 安装OpenWAF
   2.1 cd /opt
   2.2 获取OpenWAF源文件
       git clone https://github.com/titansec/OpenWAF.git
   2.3 移动配置文件
       mv /opt/OpenWAF/lib/openresty/ngx_openwaf.conf /etc
   2.4 覆盖openresty的configure文件
       mv /opt/OpenWAF/lib/openresty/configure /opt/openresty-1.11.2.1
   2.5 移动第三方模块至openresty中
       mv /opt/OpenWAF/lib/openresty/* /opt/openresty-1.11.2.1/bundle/
   2.6 删除OpenWAF/lib/openresty目录
       rm -rf /opt/OpenWAF/lib/openresty
       
3. 编译openresty
   3.1 cd /opt/openresty-1.11.2.1/
   3.2 ./configure --with-pcre-jit --with-ipv6 \
                   --with-http_stub_status_module \
                   --with-http_ssl_module \
                   --with-http_realip_module \
                   --with-http_sub_module
   3.3 make && make install
   
4. 编辑配置文件
   4.1 接入规则
       vi /opt/OpenWAF/conf/twaf_access_rule.conf
       编辑域名，后端服务器地址等信息
   4.2 日志服务器
       vi /opt/OpenWAF/conf/twaf_default_conf.json
       配置```[twaf_log](https://github.com/titansec/OpenWAF/blob/master/README_CN.md#twaf_log)```日志接收服务器地址
   
5. 启动引擎
   /usr/local/openresty/nginx/sbin/nginx -c /etc/ngx_openwaf.conf
       
problem
1. nginx:[emerg] at least OpenSSL 1.0.2e required but found OpenSSL xxx
   更新OpenSSL版本至1.0.2e以上即可
   
   如：wget -c http://www.openssl.org/source/openssl-1.0.2h.tar.gz
      ./config
      make && make install
      
   PS: 
      1. 查看当前openssl版本命令： openssl version
      2. 若更新openssl后，版本未变，请详看http://www.cnblogs.com/songqingbo/p/5464620.html
      3. 若依然提示版本问题，编译openresty时带上--with-openssl=/path/to/openssl-xxx/
```

```
1. 下载openresty
   详见 https://openresty.org/en/installation.html
   
   1.1 cd /opt
   1.2 wget -c https://openresty.org/download/openresty-1.11.2.1.tar.gz
   1.3 tar -xzvf openresty-1.11.2.1.tar.gz

2. 安装OpenWAF
   2.1 cd /opt
   2.2 获取OpenWAF源文件
       git clone https://github.com/titansec/OpenWAF.git
   2.3 移动配置文件
       mv /opt/OpenWAF/lib/openresty/ngx_openwaf.conf /etc
   2.4 覆盖openresty的configure文件
       mv /opt/OpenWAF/lib/openresty/configure /opt/openresty-1.11.2.1
   2.5 移动第三方模块至openresty中
       mv /opt/OpenWAF/lib/openresty/* /opt/openresty-1.11.2.1/bundle/
   2.6 删除OpenWAF/lib/openresty目录
       rm -rf /opt/OpenWAF/lib/openresty
       
3. 编译openresty
   3.1 cd /opt/openresty-1.11.2.1/
   3.2 ./configure --with-pcre-jit --with-ipv6 \
                   --with-http_stub_status_module \
                   --with-http_ssl_module \
                   --with-http_realip_module \
                   --with-http_sub_module
   3.3 make && make install
   
4. 编辑配置文件
   4.1 接入规则
       vi /opt/OpenWAF/conf/twaf_access_rule.conf
       编辑域名，后端服务器地址等信息
   4.2 日志服务器
       vi /opt/OpenWAF/conf/twaf_default_conf.json
       配置[twaf_log](https://github.com/titansec/OpenWAF/blob/master/README_CN.md#twaf_log)日志接收服务器地址
   
5. 启动引擎
   /usr/local/openresty/nginx/sbin/nginx -c /etc/ngx_openwaf.conf
       
problem
1. nginx:[emerg] at least OpenSSL 1.0.2e required but found OpenSSL xxx
   更新OpenSSL版本至1.0.2e以上即可
   
   如：wget -c http://www.openssl.org/source/openssl-1.0.2h.tar.gz
      ./config
      make && make install
      
   PS: 
      1. 查看当前openssl版本命令： openssl version
      2. 若更新openssl后，版本未变，请详看http://www.cnblogs.com/songqingbo/p/5464620.html
      3. 若依然提示版本问题，编译openresty时带上--with-openssl=/path/to/openssl-xxx/
```

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
* [twaf_reqstat](#twaf_reqstat)
* [twaf_log](#twaf_log)
* [twaf_secrules](#twaf_secrules)

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

[Back to twaf_anti_hotlink](#twaf_anti_hotlink)

[Back to TOC](#table-of-contents)

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

[Back to twaf_anti_mal_crawler](#twaf_anti_mal_crawler)

[Back to TOC](#table-of-contents)

twaf_reqstat
------------
```json
    "twaf_reqstat": {
        "state":true,
        "safe_state":true,
        "access_state":true,
        "upstream_state":true,
        "shared_dict_name":"twaf_reqshm",
        "content_type":"JSON"
    }
```

###state
**syntax:** *state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

统计模块开关，支持动态开关，默认开启

###access_state
**syntax:** *access_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

访问信息统计开关，支持动态开关，默认开启

###safe_state
**syntax:** *safe_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

安全信息统计开关，支持动态开关，默认开启

###upstream_state
**syntax:** *upstream_state true|false|$dynamic_state*

**default:** *true*

**context:** *twaf_reqstat*

转发信息统计开关，支持动态开关，默认开启

###shared_dict_name
**syntax:** *shared_dict_name string*

**default:** *openwaf_reqshm*

**context:** *twaf_reqstat*

指定shared_dict名称，在这之前需在nginx配置文件中配置[lua_shared_dict](https://github.com/openresty/lua-nginx-module#lua_shared_dict) <name> <size>

默认shared_dict名称为openwaf_reqshm

###content_type
**syntax:** *content_type JSON|INFLUXDB*

**default:** *JSON*

**context:** *twaf_reqstat*

指定统计信息输出格式，目前支持JSON和INFLUXDB两种格式

[Back to twaf_reqstat](#twaf_reqstat)

[Back to TOC](#table-of-contents)

twaf_log
--------
```txt
"twaf_log": {
        "access_log_state":false,     -- 访问日志开关
        "security_log_state":true,    -- 安全日志开关
        "sock_type":"udp",            -- 支持tcp和udp两种协议
        "content_type":"JSON",        -- 支持JSON和INFLUXDB两种日志格式
        "host":"127.0.0.1",           -- 日志服务器地址
        "port":60055,                 -- 日志服务器端口号
        "flush_limit":0,              -- 缓冲，当存储的日志大于阈值才发送
        "drop_limit":1048576,
        "max_retry_times":5,          -- 最大容错次数
        "ssl":false,                  -- 是否开启ssl协议
        "access_log":{}               -- 访问日志格式
        "security_log":{}             -- 安全日志格式
}
```

###access_log_state
**syntax:** *"access_log_state": true|false*

**default:** *false*

**context:** *twaf_log*

访问日志开关，默认关闭

###security_log_state
**syntax:** *"security_log_state": true|false*

**default:** *true*

**context:** *twaf_log*

安全事件日志开关，默认开启

###sock_type
**syntax:** *"sock_type": tcp|udp*

**default:** *udp*

**context:** *twaf_log*

日志传输协议，默认udp

###content_type
**syntax:** *"content_type": JSON|INFLUXDB*

**default:** *JSON*

**context:** *twaf_log*

日志格式，默认JSON

###host
**syntax:** *"host": string*

**default:** *"127.0.0.1"*

**context:** *twaf_log*

日志接收服务器的ip地址

###port
**syntax:** *"port": number*

**default:** *60055*

**context:** *twaf_log*

日志接收服务器的端口号

###flush_limit
**syntax:** *"flush_limit": number*

**default:** *0*

**context:** *twaf_log*

缓冲区大小，当存储的日志大于阈值才发送，默认值为0，即立即发送日志

###drop_limit
**syntax:** *"drop_limit": number*

**default:** *1048576*

**context:** *twaf_log*

###max_retry_times
**syntax:** *"max_retry_times": number*

**default:** *5*

**context:** *twaf_log*

最大容错次数

###ssl
**syntax:** *"ssl": true|false*

**default:** *false*

**context:** *twaf_log*

是否开启ssl协议，默认false

###access_log
**syntax:** *"access_log": table*

**default:** *false*

**context:** *twaf_log*

访问日志格式

###security_log
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

变量名称详见规则引擎模块[twaf_secrules](#https://github.com/titansec/openwaf_rule_engine#variables)

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
            "raw_header"
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
                "raw_header"
            ],
            "time":true                   -- 日志是否携带时间戳
        }
```

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
        "reqbody_limit":134217728,                                  -- 请求体检测阈值，大于阈值不检测
        "respbody_limit":524288,                                    -- 响应体检测阈值，大于阈值不检测
        "pre_path": "/opt/OpenWAF/",                                -- OpenWAF安装路径
        "path": "lib/twaf/inc/knowledge_db/twrules",                -- 特征规则库在OpenWAF中的路径
        "msg": [                                                    -- 日志格式
            "category",
            "severity",
            "action",
            "meta",
            "version",
            "id",
            "charactor_name",
            {                                                       -- 字典中为变量
                "transaction_time": "%{DURATION}",
                "logdata": "%{MATCHED_VAR}"
            }
        ],
        "rules_id":{                                                -- 特征排除
            "111112": [{"REMOTE_HOST":"a.com", "URI":"^/ab"}]       -- 匹配中数组中信息则对应规则失效，数组中key为变量名称，值支持正则
            "111113": {}                                            -- 特征未被排除
            "111114": [{}]                                          -- 特征被无条件排除
        }
    }
```

###state
**syntax:** *state true|false*

**default:** *true*

**context:** *twaf_secrules*

规则引擎总开关

###reqbody_state
**syntax:** *reqbody_state true|false*

**default:** *true*

**context:** *twaf_secrules*

请求体检测开关

###header_filter_state
**syntax:** *header_filter_state true|false*

**default:** *true*

**context:** *twaf_secrules*

响应头检测开关

###body_filter_state
**syntax:** *body_filter_state true|false*

**default:** *false*

**context:** *twaf_secrules*

响应体检测开关，默认关闭，若开启需添加第三方模块[ngx_http_twaf_header_sent_filter_module暂未开源]

###reqbody_limit
**syntax:** *reqbody_limit number*

**default:** *134217728*

**context:** *twaf_secrules*

请求体检测大小上限，默认134217728B(128MB)，若请求体超过设置上限，则不检测

PS：reqbody_limit值要小于nginx中client_body_buffer_size的值才会生效

###respbody_limit
**syntax:** *respbody_limit number*

**default:** *134217728*

**context:** *twaf_secrules*

响应体检测大小上限，默认134217728B(128MB)，若响应体大小超过设置上限，则不检测

###pre_path
**syntax:** *pre_path string*

**default:** */opt/OpenWAF/*

**context:** *twaf_secrules*

OpenWAF的安装路径

###path
**syntax:** *path string*

**default:** *lib/twaf/inc/knowledge_db/twrules*

**context:** *twaf_secrules*

特征规则库在OpenWAF中的路径

###msg
**syntax:** *msg table*

**default:** *[
            "category",
            "severity",
            "action",
            "meta",
            "version",
            "id",
            "charactor_name",
            {
                "transaction_time": "%{DURATION}",
                "logdata": "%{MATCHED_VAR}"
            }
        ]*

**context:** *twaf_secrules*

日志格式

###rules_id
**syntax:** *rules_id table*

**default:** *none*

**context:** *twaf_secrules*

用于排除特征

[Back to twaf_secrules](#twaf_secrules)

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
