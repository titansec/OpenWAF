名称
====

ELK 是比较火的开源日志分析系统

本节主要介绍，ELK 的 docker 部署及与 OpenWAF 的结合

Table of Contents
=================

* [ELK简介](#elk简介)
* [安装](#安装)
    * [Elasticsearch](#elasticsearch)
    * [Logstash](#logstash)
    * [Kibana](#kibana)
* [OpenWAF配置](#openwaf配置)
* [测试](#测试)

ELK简介
=======

ELK是三个不同工具的简称,组合使用可以完成各种日志分析

Elasticsearch: 是一个基于 Apache Lucene(TM) 的开源搜索引擎,简单点说就是用于建立索引并存储日志的工具

Logstash: 是一个应用程序,它可以对日志的传输、过滤、管理和搜索提供支持。我们一般用它来统一对应用程序日志进行收集管理，提供Web接口用于查询和统计

Kibana: 用于更友好的展示分析日志的web平台,简单点说就是有图有真相,可以在上面生成各种各样的图表更直观的显示日志分析的成果


安装
====

ELK 的安装，网上有很多，这里只描述 docker 方式的部署

Elasticsearch
-------------

1. 拉取 elasticsearch docker 镜像  
```
    docker pull elasticsearch  
```

2. 启动 elasticsearch 容器  
```
    docker run -d --name openwaf_es elasticsearch  
```

3. 获取 openwaf_es 地址  
```
    docker inspect openwaf_es | grep IPAddress  
    得到地址为：192.168.39.17
    
    PS: elasticsearch 服务端口为 9200
```

Logstash
--------

1. 拉取 logstash docker 镜像  
```
    docker pull logstash
```

2. 启动 logstash 容器
```
    docker run -it --name openwaf_logstash -v /root/logstash.conf:/usr/share/logstash/config/logstash.conf logstash -f /usr/share/logstash/config/logstash.conf
    
PS:
    /root/logstash.conf 文件内容如下：
    
    udp {                  # udp 服务配置
        port => 60099      # 表示日志服务器监听在 60099 端口
        codec => "json"    # 接收 json 格式信息
    }
    output {
        elasticsearch {
            hosts => ["192.168.39.17:9200"] # elasticsearch 的地址为 39.17，且端口为 9200
        }
    }
    
    上面的配置表示：openwaf 向 logstash 的 60099 端口，发送 udp 协议的 json 日志，然后 logstash 将其存入 Elasticsearch
```

3. 获取 openwaf_logstash 地址  
```
    docker inspect openwaf_logstash | grep IPAddress  
    得到地址为：192.168.39.18
```

Kibana
------

1. 拉取 kibana docker 镜像  
```
    docker pull kibana
```

2. 启动 logstash 容器
```
    docker run -d --name openwaf_kibana -e ELASTICSEARCH_URL=http://192.168.39.17:9200 kibana
```

3. 获取 openwaf_kibana 地址  
```
    docker inspect openwaf_kibana | grep IPAddress  
    得到地址为：192.168.39.19
    
    PS: kibana 服务端口为 5601
```

OpenWAF配置
===========

    conf/twaf_default_conf.json 中 twaf_log 模块
    
```
    "twaf_log": {
        "sock_type":"udp",
        "content_type":"JSON",
        "host":"192.168.39.18",
        "port":60099,
        ...
    }
```


测试
====

    测试版 OpenWAF 地址 192.168.36.44，反向代理后端服务器 192.168.39.216
    
    现访问 192.168.36.44/?a=1 order by 1
    
    访问结果如下：
    
<img src="http://i.imgur.com/BPYPBfB.png">
    
    此时，访问 192.168.39.19:5601，在 kibana 上查看日志
    
    若第一次使用 kibana，需要生成一个索引，如下（使用默认）：
    
<img src="http://i.imgur.com/oH2toG6.png">

    kibana 日志显示如下：
    
<img src="http://i.imgur.com/jzDlUuu.png">

kibana 功能强大，可以做各种视图，用来分析日志，生成报表，更多功能请看 [kibana官方文档](https://www.elastic.co/guide/en/kibana/current/index.html)



