名称
====

OpenWAF快速入门，即从安装到上线测试的一个快速体验流程，包括安装，发布应用，查看日志，上线测试

Table of Contents
=================

* [安装](#安装)
* [发布应用](#发布应用)
* [日志](#日志)
* [规则](#规则)

安装
====

[请看 OpenWAF 安装文档](https://github.com/titansec/OpenWAF/blob/master/doc/%E8%BD%BB%E6%9D%BE%E7%8E%A9%E8%BD%ACOpenWAF%E4%B9%8B%E5%AE%89%E8%A3%85%E7%AF%87.md)

发布应用
=======

* [简介](#简介)  
* [接入规则配置简要说明](#接入规则配置简要说明)  
* [发布应用举例](#发布应用举例)  
    * [初次使用OpenWAF](#初次使用openwaf)  
        * [使用OpenWAF提供的nginx配置文件](#使用openwaf提供的nginx配置文件)   
        * [使用自己原有的nginx配置](#使用自己原有的nginx配置)  

简介
----

    发布应用，需要配置 OpenWAF 的接入规则，配置文件位置：/opt/OpenWAF/conf/twaf_access_rule.json
    
    OpenWAF的接入规则和nginx的配置结合，达到发布应用的目的

接入规则配置简要说明
------------------
```
{
    "twaf_access_rule": [
        "rules": [                                 -- 数组，注意先后顺序
            {                                      
                "ngx_ssl": false,                  -- nginx认证的开关
                "ngx_ssl_cert": "path",            -- nginx认证所需PEM证书地址
                "ngx_ssl_key": "path",             -- nginx认证所需PEM私钥地址
                "host": "www.baidu.com",           -- 域名，正则匹配
                "port": 80,                        -- 端口号（缺省80）
                "path": "\/",                      -- 路径，正则匹配
                "server_ssl": false,               -- 后端服务器ssl开关
                "forward": "server_5",             -- 后端服务器upstream名称
                "forward_addr": "1.1.1.2",         -- 后端服务器ip地址
                "forward_port": "8080",            -- 后端服务器端口号（缺省80）
                "policy": "policy_uuid"            -- 安全策略ID
            }
        ]
    }
}
```

发布应用举例
-----------
    接下来结合nginx配置举例讲解接入规则的使用  
    
### 初次使用OpenWAF

#### 使用OpenWAF提供的nginx配置文件

    如果用 OpenWAF 默认的 /etc/ngx_openwaf.conf 配置文件（默认监听 80 端口）
    
    修改 /opt/OpenWAF/conf/twaf_access_rule.json 文件中第一条接入规则的"forward_addr"值  
    
```txt
    要防护的服务器为192.168.3.1:80，配置如下：
        "forward_addr": "192.168.3.1"
    
    要防护的服务器为22.22.22.22:8090，配置如下：
        "forward_addr": "22.22.22.22",
        "forward_port": 8090
```
    
    此时启动nginx，进行访问即可    
    
```
小提示：
    启动nginx命令  /usr/local/openresty/nginx/sbin/nginx -c /etc/ngx_openwaf.conf  
    停止nginx命令  /usr/local/openresty/nginx/sbin/nginx -c /etc/ngx_openwaf.conf -s stop
```

    默认SQLI，CC防护都是开启的，可以进行SQL注入或CC攻击，看防护效果  

    深入防护，深入测试，请看其他文档  
    
#### 使用自己原有的nginx配置

    拥有自己的nginx配置，仅需以下两步即可体验OpenWAF防护
    
1. nginx配置修改  
    在 nginx 的 http 级别添加如下两行：
```
    include /opt/OpenWAF/conf/twaf_main.conf;
    include /opt/OpenWAF/conf/twaf_api.conf;
```
  
    要防护的 server 或 location 级别添加如下一行：
```
    include /opt/OpenWAF/conf/twaf_server.conf;
```

2. OpenWAF接入规则修改  
    修改/opt/OpenWAF/conf/twaf_access_rule.json文件  
    将"state"值设为false即可
    



