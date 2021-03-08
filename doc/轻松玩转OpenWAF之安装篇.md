名称
====

OpenWAF 支持源码安装和 Docker 安装

学习、开发、需求变动大、有一定维护能力，建议源码安装  
仅使用 OpenWAF 进行防护，建议 Docker 安装

Table of Contents
=================

* [源码安装](#源码安装)
    * [Debian&Ubuntu](#debianubuntu)
    * [CentOS](#centos)
    * [Others](#others)
* [Docker容器安装](#docker容器安装)


源码安装
--------

### Debian&Ubuntu  

1. 安装OpenWAF依赖

```txt
    cd /opt
    apt-get install gcc wget git swig make perl build-essential zlib1g-dev libgeoip-dev libncurses5-dev libreadline-dev -y
    wget http://www.over-yonder.net/~fullermd/projects/libcidr/libcidr-1.2.3.tar.xz
    wget https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz
    wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz
    wget https://openresty.org/download/openresty-1.19.3.1.tar.gz
    tar -xvf libcidr-1.2.3.tar.xz
    tar -zxvf pcre-8.44.tar.gz
    tar -zxvf openssl-1.1.1d.tar.gz
    tar -zxvf openresty-1.19.3.1.tar.gz
    rm -rf pcre-8.44.tar.gz \
           openssl-1.1.1d.tar.gz \
           openresty-1.19.3.1.tar.gz
    cd /opt/libcidr-1.2.3
    make && make install
```

```txt
PS: 
    1.1 OpenSSL 版本要求
    
        OpenResty 要求 OpenSSL 最低版本在 1.0.2e 以上，但 apt-get 安装 openssl 并不满足此版本，因此提供解决方法如下：
        
        方法 1. apt-get 使用 backports 源安装 openssl，如 jessie-backports  
            echo "deb http://mirrors.163.com/debian/ jessie-backports main" >> /etc/apt/sources.list  
            apt-get update  
            apt-get install -t jessie-backports openssl  
            
        方法 2. 下载 openssl 源代码，如 1.1.1d 版本  
            wget -c http://www.openssl.org/source/openssl-1.1.1d.tar.gz  
            tar -zxvf openssl-1.1.1d.tar.gz
            ./config  
            make && make install  
            
        若用方法 1 和 方法 2 后， openssl version 命令显示的版本依旧低于 1.0.2e 版本，请求方法 3
        
        方法 3. 编译 openresty 时指定 openssl 安装目录
            wget -c http://www.openssl.org/source/openssl-1.1.1d.tar.gz
            tar -zxvf openssl-1.1.1d.tar.gz
            编译 openresty 时通过 --with-openssl=/path/to/openssl-xxx/ 指定 openssl 安装路径  
 
        本示例使用方法 3
    
    1.2 pcre-jit
    
        OpenResty 依赖 PCRE ，但通过 apt-get 安装无法开启 pcre-jit，解决方法：  
        
        方法 1. 源码编译
            wget https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz  
            tar -zxvf pcre-8.44.tar.gz  
            cd pcre-8.44  
            ./configure --enable-jit  
            make && make install  
            
        方法 2. 编译 openresty 时指定 pcre 安装目录
            wget https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz  
            tar -zxvf pcre-8.44.tar.gz  
            编译 openresty 时通过 --with-pcre=/path/to/pcre-xxx/ 指定 pcre 安装路径 
        
        本示例使用方法 2
```
    
2. 安装 OpenWAF  

```txt
    cd /opt  
    git clone https://github.com/titansec/OpenWAF.git
    mv /opt/OpenWAF/lib/openresty/ngx_openwaf.conf /etc
    mv /opt/OpenWAF/lib/openresty/configure /opt/openresty-1.19.3.1
    cp -RP /opt/OpenWAF/lib/openresty/* /opt/openresty-1.19.3.1/bundle/
    cd /opt/OpenWAF
    make clean
    make install
    ln -s /usr/local/lib/libcidr.so /opt/OpenWAF/lib/resty/libcidr.so
```

```txt
PS:
    2.1 ngx_openwaf.conf
        ngx_openwaf.conf 是 OpenResty 的 [nginx](http://nginx.org/en/docs/) 配置文件
        
    2.2 configure 
        configure 是 OpenResty 的编译文件
        OpenWAF 修改了此文件，用于编译 OpenWAF 所依赖的第三方模块
```

3. 编译 openresty  

```txt
    cd /opt/openresty-1.19.3.1/  
    ./configure --with-pcre-jit --with-ipv6 \  
                --with-http_stub_status_module \  
                --with-http_ssl_module \  
                --with-http_realip_module \  
                --with-http_sub_module  \  
                --with-http_geoip_module \  
                --with-openssl=/opt/openssl-1.1.1d \ 
                --with-pcre=/opt/pcre-8.44
    make && make install 
```

### CentOS

    与 [Debian](#debianubuntu) 安装几乎一致，只需在安装依赖时，将 apt-get 一行命令换成以下命令即可：
    
```txt
    yum install gcc gcc-c++ wget GeoIP-devel git swig make perl perl-ExtUtils-Embed readline-devel zlib-devel -y
```

### Others

    其他操作系统安装 OpenWAF，可参考 [OpenResty](https://openresty.org/cn/installation.html) 安装  
    再安装 OpenWAF 依赖的 swig 即可  

Docker容器安装
--------------
```txt
1. pull docker images from repository
   docker pull titansec/openwaf

2. start-up docker 
    docker run -d --name openwaf \
               -p 80:80 -p 443:443 \
               -v /opt/openwaf/conf/ngx_openwaf.conf:/etc/ngx_openwaf.conf \
               -v /opt/openwaf/conf/twaf_access_rule.json:/opt/OpenWAF/conf/twaf_access_rule.json \
               -v /opt/openwaf/log/openwaf_error.log:/var/log/openwaf_error.log \
               titansec/openwaf 
```

```txt
PS:
    1. docker pull titansec/openwaf 
        docker pull titansec/openwaf 获取 jessie 的 OpenWAF 最新版
        docker pull titansec/openwaf:latest 获取 jessie 的 OpenWAF 最新版
        docker pull titansec/openwaf:jessie 获取 jessie 的 OpenWAF 最新版
        docker pull titansec/openwaf:centos 获取 centos 的 OpenWAF 最新版
        
        获取历史版本：
        docker pull titansec/openwaf:x.x.x-jessie 获取 jessie 的 OpenWAF x.x.x 版
        docker pull titansec/openwaf:x.x.x-centos 获取 centos 的 OpenWAF x.x.x 版
        
        历史版本列表：
            国外镜像源：https://hub.docker.com/r/titansec/openwaf/tags/  
            国内镜像源：https://cr.console.aliyun.com/images/cn-hangzhou/titansec/openwaf/detail
        
    2. 挂载配置文件和日志
        将配置文件保留在宿主机中，更新 OpenWAF 只需更新 Docker 镜像即可
        2.1 挂载 nginx 配置文件
            如，事先将 ngx_openwaf.conf 放在宿主机 /opt/openwaf/conf/ 目录下，然后启动 docker 容器时添加参数如下：
            -v /opt/openwaf/conf/ngx_openwaf.conf:/etc/ngx_openwaf.conf
        2.2 挂载 twaf_access_rule.json 接入规则配置文件
            如，事先将 twaf_access_rule.json 放在宿主机 /opt/openwaf/conf/ 目录下，然后启动 docker 容器时添加参数如下：
            -v /opt/openwaf/conf/twaf_access_rule.json:/opt/OpenWAF/conf/twaf_access_rule.json
        2.3 挂载 nginx 错误日志
            -v /opt/openwaf/log/openwaf_error.log:/var/log/openwaf_error.log
        
    3. restart 
        修改宿主机中的配置文件后，执行 docker restart openwaf(容器名称) 即可
```
