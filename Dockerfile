####################################################
# Dockerfile to build OpenWAF container images
# Based on jessie
####################################################

#Set the base image to jessie
FROM debian:jessie

#File Author
MAINTAINER Miracle

#make,c++ packages
RUN echo "deb http://mirrors.163.com/debian/ jessie main" > /etc/apt/sources.list \
    && echo "deb http://mirrors.163.com/debian/ jessie-updates main" >> /etc/apt/sources.list \
    && echo "deb http://mirrors.163.com/debian-security/ jessie/updates main" >> /etc/apt/sources.list \
    && echo "deb http://mirrors.163.com/debian/ jessie-backports main" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y wget git sudo net-tools vim \
    && apt-get install make gcc automake autoconf libtool g++  -y 
    
#1.install openrestry related
RUN apt-get install libreadline-dev libncurses5-dev libpcre3-dev libssl-dev perl build-essential -y \
    && apt-get install libgeoip-dev swig -y \
    && apt-get install -t jessie-backports openssl -y \
    && apt-get autoremove curl -y \
    && cd /opt \
    && wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.40.tar.gz \
    && tar -xvf pcre-8.40.tar.gz \
    && cd pcre-8.40 \
    && ./configure --enable-jit \
    && make && make install \
    && cd /opt \
    && rm -rf pcre-8.40.tar.gz pcre-8.40/ \
    && cd /opt \
    && wget https://openresty.org/download/openresty-1.11.2.2.tar.gz \
    && tar -zxvf openresty-1.11.2.2.tar.gz \
    && rm -rf openresty-1.11.2.2.tar.gz
    
#2. install OpenWAF
RUN cd /opt \
    #clone OpenWAF
    && git clone https://github.com/titansec/OpenWAF.git \
    #move conf file
    && mv /opt/OpenWAF/lib/openresty/ngx_openwaf.conf /etc \
    #overwrite the configure file of openresty
    && mv /opt/OpenWAF/lib/openresty/configure /opt/openresty-1.11.2.2 \
    #move third-party modules to openresty
    && cp -RP /opt/OpenWAF/lib/openresty/* /opt/openresty-1.11.2.2/bundle/ \
    && cd /opt/OpenWAF \
    && make install
    
#3. install openresty
#	&& wget -c http://www.lua.org/ftp/lua-5.1.4.tar.gz \
#	&& tar zxf lua-5.1.4.tar.gz \
#	&& cd lua-5.1.4 \
#	&& make linux test \
#	&& make install \
RUN cd /opt/openresty-1.11.2.2/ \	
    && ./configure \
        --with-pcre-jit --with-ipv6 \
        --with-http_stub_status_module \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_sub_module \
    && make \
    && make install 

#ssh
RUN apt-get install openssh-server -y --fix-missing	
RUN sed -i "s/^PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config
RUN echo "root:root" | chpasswd
RUN mkdir /var/run/sshd  
EXPOSE 22 

CMD ["/usr/sbin/sshd", "-D"]
