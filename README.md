# DNSLog
DNSlog And DNS_Server And Interception analysis
DNSLog 功能 DNS_Server 功能 恶意拦截域名劫持 功能
小脚本用于学习原理
![image](https://github.com/chinaYozz/DNSLog/blob/main/help/dnslog.PNG)

# 安装使用
# nstallation and use
**Python3**

# 安装DNS模块
# install DNS module
```txt
pip3 install dnslib pythondns -i https://pypi.tuna.tsinghua.edu.cn/simple
```
# 更新socks
# to update socks
```txt
pip3 install -U requests[socks] -i https://pypi.tuna.tsinghua.edu.cn/simple
```

# DNSLog使用
1.把脚本放置公网服务器运行，并开放53 UDP端口
2.域名服务商那 添加一条A 解析到公网服务器 比如：1.nstns.com
3.在添加一条NS记录 记录到1.nstns.com
4.并在脚本里面设置NS 域名，这个NS域名就是DNSLog了

# Dnslog use
1. Put the script on the public network server to run, and open the 53 UDP port
2. The domain name service provider adds an a resolution to the public network server, for example: 1 nstns. com
3. Add an ns record to 1 nstns. com
4.The domain name is set in the SLNs script

# DNS_Server使用
1.在脚本里面设置DNS服务器，比如8.8.8.8 114.114.114.114
2.更改电脑 网关等设备 DNS服务器到你搭建得公网IP
3.这个时候就已经搭建了个DNS服务器了

# DNS_ Server usage
1. Set the DNS server in the script, such as 8.8.8.8 114.114.114.114
2. Change the DNS server of computer gateway and other devices to the public network IP you built
3. At this time, a DNS server has been set up

# 恶意拦截域名劫持使用
在脚本里面设置 要拦截得域名，指向到那个IP，脚本默认拦截百度到127.0.0.1
由此可以搭建钓鱼网站，拦截黄色等网站.等

# Malicious interception of domain name hijacking
Set the domain name to be intercepted in the script and point to the IP. The script intercepts Baidu to 127.0.0.1 by default
From this, we can build phishing websites and intercept pornographic websites etc.

# 免责说明/Disclaimer
该脚本仅用于网络学习测试，不得用于违法用途，出现问题概不负责
使用脚本及为同意以上条约
The script is only used for e-learning test and shall not be used for illegal purposes. We will not be responsible for any problems
Use scripts and to agree to the above treaties
