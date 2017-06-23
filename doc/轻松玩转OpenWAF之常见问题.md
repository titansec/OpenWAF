Name
====

在安装和使用OpenWAF的过程中，不同的环境，不同的场景都会碰到不同的问题，很多问题是重复的，因此在这里记录，供他人参考

[端口问题](#端口问题)

端口问题
=======

port_in_redirect
----------------

```
场景描述：
    
       应用发布在 80 端口              nginx 监听 8800 端口
        lb（负载均衡）         ---->      OpenWaf （转发请求）     ------>     tomcat 
    
    
    tomcat 发起重定向，客户端会显示 nginx 的端口 8800，导致访问失败
    
原因分析：

    抓包发现，tomcat 返回给 nginx 响应，带有 Location 头，其中端口是 80
    但 nginx 返回给 lb，将 Location 中的端口进行了替换
    
解决方式：

Syntax: 	port_in_redirect on | off;
Default:	port_in_redirect on;
Context:	http, server, location

Enables or disables specifying the port in absolute redirects issued by nginx.

port_in_redirect 默认是 on，会替换端口，只需设为 off，即可正常访问。
```



