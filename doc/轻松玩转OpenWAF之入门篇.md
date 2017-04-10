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

* [源码安装](#源码安装)
    * [Debian&Ubuntu](#debianubuntu)
    * [Others](#others)
* [Docker容器](#docker容器)

源码安装
--------

### Debian&Ubuntu  

1. 安装 openresty  

   写在安装前的注意事项：  
   
```txt
   注意1：OpenResty 要求 OpenSSL 最低版本在 1.0.2e 以上，但 apt-get 安装 openssl 不满足此版本，因此提供解决方法如下：  
       方法1. apt-get 使用 backports 源安装 openssl，如jessie-backports  
           echo "deb http://mirrors.163.com/debian/ jessie-backports main" >> /etc/apt/sources.list  
           apt-get update  
           apt-get install -t jessie-backports openssl  
       方法2. 下载 openssl 源代码，如 1.0.2h 版本  
           wget -c http://www.openssl.org/source/openssl-1.0.2h.tar.gz  
           ./config  
           make && make install  
           
           若 openssl version 输出的版本依旧低于 1.0.2e 版本，  
           则下面第三步编译openresty时通过 --with-openssl=/path/to/openssl-xxx/ 指定 openssl 安装路径  
           
    注意2：OpenResty 依赖 PCRE ，但通过 apt-get 安装无法开启 pcre-jit，解决方法：  
        下载 pcre 源代码，如pcre-8.40版本  
            wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.40.tar.gz  
            tar -xvf pcre-8.40.tar.gz  
            cd pcre-8.40  
            ./configure --enable-jit  
            make && make install  
            
            到此 pcre 已支持 jit ，也可在第三步编译 openresty 时通过 --with-pcre=/path/to/pcre-xxx/ 指定 pcre 安装路径  
```

    安装openresty依赖  
        apt-get install libreadline-dev libncurses5-dev libpcre3-dev libssl-dev perl make build-essential

    下载openresty源码
    
```txt
   1.1 cd /opt  
   1.2 wget -c https://openresty.org/download/openresty-1.11.2.2.tar.gz  
   1.3 tar -xzvf openresty-1.11.2.2.tar.gz  
```

2. 安装 OpenWAF  

```txt
   2.1 安装 OpenWAF 依赖
       apt-get install libgeoip-dev swig  
   2.2 下载 OpenWAF 源码
       cd /opt  
       git clone https://github.com/titansec/OpenWAF.git  
   2.3 将 nginx 配置文件移至 /etc 目录下
       mv /opt/OpenWAF/lib/openresty/ngx_openwaf.conf /etc  
   2.4 覆盖 OpenResty 的 configure
       mv /opt/OpenWAF/lib/openresty/configure /opt/openresty-1.11.2.2  
   2.5 将 OpenResty 第三方模块移至 OpenResty 目录下
       mv /opt/OpenWAF/lib/openresty/* /opt/openresty-1.11.2.2/bundle/  
   2.6 删除空目录 OpenWAF/lib/openresty  
       rm -rf /opt/OpenWAF/lib/openresty  
```

3. 编译 openresty  

```txt
   3.1 cd /opt/openresty-1.11.2.2/  
   3.2 ./configure --with-pcre-jit --with-ipv6 \  
                   --with-http_stub_status_module \  
                   --with-http_ssl_module \  
                   --with-http_realip_module \  
                   --with-http_sub_module  \
                   --with-http_geoip_module
   3.3 make && make install 
```

Docker容器
----------
```txt
1. pull docker images from repository
   docker pull titansec/openwaf

2. start-up docker
   2.1 docker run, named openwaf
       docker run -d -p 22:22 -p 80:80 -p 443:443 --name openwaf titansec/openwaf
   2.2 enter openwaf
       docker exec -it openwaf /bin/bash
```

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
    



