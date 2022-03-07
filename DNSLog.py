from threading import Thread
from dnslib import *
import socks,socket,dns.resolver,sys,random,datetime,re,time

# www.nstns.com
# https://github.com/chinaYozz

#Set dnslog server and DNS query server
#设置dnslog服务器，设置DNS查询服务器
#DNS NS
DomainName_DnsLog,DNS_Server_IP = "dnslog.nstns.com",['114.114.114.114','8.8.8.8']


#Set the domain name to be blocked and resolve to the specified IPv4
#设置要拦截得域名，和解析到指定IPv4
Hijack_domain_name,Hijack_ipv4 = 'www.baidu.com%s'%'.','127.0.0.1'


def time_master(func):
    def wrap(*args, **kwargs):
        start = time.time()
        ret = func(*args, **kwargs)
        end = time.time()
        print("\u005b\u002b\u005d\u0020\u0051\u0075\u0065\u0072\u0079\u0020\u0074\u0069\u006d\u0065\u002f\u67e5\u8be2\u8017\u65f6\u003a{:.8f}".format(end-start))
        return ret
    return wrap


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(f'{item}%s'%'.%s'%self)

#@time_master  #Query time
def DNS_Query(domain_name,domain_type):
    my_resolver=dns.resolver.Resolver()
    my_resolver.nameservers=DNS_Server_IP
    try:
        answer=my_resolver.resolve(domain_name,domain_type,raise_on_no_answer=True)
    except dns.resolver.NoAnswer as e:
        return False;
    except dns.resolver.LifetimeTimeout as e:
        return False;
    except dns.resolver.NXDOMAIN as e:
        print("\u005b\u002d\u005d\u0020\u004e\u006f\u0074\u0020\u0066\u006f\u0075\u006e\u0064\u672a\u67e5\u8be2\u5230",domain_name,"\u0044\u006f\u006d\u0061\u0069\u006e\u0020\u004e\u0061\u006d\u0065\u57df\u540d",domain_type,"\u0052\u0065\u0063\u006f\u0072\u0064\u8bb0\u5f55")
        return False;
    except dns.resolver.NoNameservers as e:
        return False;
    else:
        for ipval in answer:
            return ipval


def dnslog(dnslog):
    try:
        log = re.findall(r"(^.*).%s"%DomainName_DnsLog,dnslog)[0]
    except IndexError as e:
        pass
    else:
        print("\u005b\u002b\u005d\u0020\u0044\u006e\u0073\u004c\u006f\u0067\u003a",log)
        return True;



class DNS_Server():
    def __init__(self):
        LISTEN_PORT = 53
        LISTEN_IP = "0.0.0.0"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((LISTEN_IP, LISTEN_PORT))
        print(f'\u005b\u002b\u005d\u0020\u004c\u0069\u0073\u0074\u0065\u006e\u0069\u006e\u0067\u0020\u006f\u006e\u003a\u0020{LISTEN_IP}:{LISTEN_PORT}','\u0050\u0072\u0065\u0073\u0073\u0020\u0043\u0074\u0072\u006c\u0020\u002b\u0020\u0043\u0020\u0074\u006f\u0020\u0073\u0074\u006f\u0070\u0020\u0072\u0075\u006e\u006e\u0069\u006e\u0067')

 
    def response(self, data, client):
        request = DNSRecord.parse(data)
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        qname,qtype = request.q.qname,request.q.qtype
        print(str(qname),QTYPE[qtype])
        if dnslog(str(qname).lower()) == True:
            reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE,'A'), rclass=1, ttl=0, rdata=A("127.0.0.1")))
        elif QTYPE[qtype] == 'A' and str(qname).lower() == Hijack_domain_name:
            print(f"\u005b\u002b\u005d\u0020\u0069\u006e\u0074\u0065\u0072\u0063\u0065\u0070\u0074\u002f\u62e6\u622a\u0020{Hijack_domain_name}\u0020\u0044\u006f\u006d\u0061\u0069\u006e\u0020\u006e\u0061\u006d\u0065\u0020\u0072\u0065\u0073\u006f\u006c\u0076\u0065\u0064\u0020\u0074\u006f\u002f\u57df\u540d\u89e3\u6790\u5230\u0020{Hijack_ipv4}")
            reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE,'A'), rclass=1, ttl=0, rdata=A(Hijack_ipv4)))
        elif QTYPE[qtype] == 'A':
            ipv4 = DNS_Query(str(qname).lower(),"A")
            if ipv4 == False:
                pass
            else:
                rogue_domain = A(str(ipv4))
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'A'), rclass=1, ttl=30, rdata=rogue_domain))
        elif QTYPE[qtype] == 'AAAA':
            ipv6 = DNS_Query(str(qname).lower(),"AAAA")
            if ipv6 == False:
                pass
            else: 
                rogue_domain = AAAA(str(ipv6))
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'AAAA'), rclass=1, ttl=0, rdata=rogue_domain))
        elif QTYPE[qtype] == 'CNAME':
            return_cname = DNS_Query(str(qname).lower(),"CNAME")
            if return_cname == False:
                pass
            else:
                rogue_domain = CNAME(str(return_cname))
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'CNAME'), rclass=1, ttl=0, rdata=rogue_domain))
        elif QTYPE[qtype] == 'TXT':
            ip = DNS_Query(str(qname).lower(),"TXT")
            if ip == False:
                pass
            else:
                rogue_domain = TXT(str(ip))
                reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, 'TXT'), rclass=1, ttl=0, rdata=rogue_domain))
        self.sock.sendto(reply.pack(), client)


    def start(self):
        while True:
            #Adjust DNS query frequency in seconds / 调整DNS查询频率 单位秒
            #time.sleep(1)
            try:
                data, client = self.sock.recvfrom(512)
            except ConnectionResetError as e:
                print(f"\u005b\u002d\u005d\u0020\u0043\u006f\u006e\u006e\u0065\u0063\u0074\u0069\u006f\u006e\u0020\u0074\u0069\u006d\u0065\u006f\u0075\u0074\u0020\u0066\u0061\u0069\u006c\u0065\u0064\u002f\u8fde\u63a5\u8d85\u65f6\u5931\u8d25\u0020{client[0]}")
            else:
                now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                print(f"\u005b\u002b\u005d\u0020{now}\u0020{client[0]}",end='\u0020')
                new_thread = Thread(target=self.response, args=(data, client))
                new_thread.setDaemon(True)
                new_thread.start()
             
def DNS():
    DNS_Server().start()


if __name__ == '__main__':
    print("\u0020\u005f\u005f\u005f\u005f\u0020\u0020\u005f\u0020\u0020\u0020\u005f\u0020\u005f\u005f\u005f\u005f\u0020\u0020\u005f\n\u007c\u0020\u0020\u005f\u0020\u005c\u007c\u0020\u005c\u0020\u007c\u0020\u002f\u0020\u005f\u005f\u005f\u007c\u007c\u0020\u007c\u0020\u0020\u0020\u0020\u005f\u005f\u005f\u0020\u0020\u0020\u005f\u005f\u0020\u005f\n\u007c\u0020\u007c\u0020\u007c\u0020\u007c\u0020\u0020\u005c\u007c\u0020\u005c\u005f\u005f\u005f\u0020\u005c\u007c\u0020\u007c\u0020\u0020\u0020\u002f\u0020\u005f\u0020\u005c\u0020\u002f\u0020\u005f\u0060\u0020\u007c\n\u007c\u0020\u007c\u005f\u007c\u0020\u007c\u0020\u007c\u005c\u0020\u0020\u007c\u005f\u005f\u005f\u0029\u0020\u007c\u0020\u007c\u005f\u005f\u007c\u0020\u0028\u005f\u0029\u0020\u007c\u0020\u0028\u005f\u007c\u0020\u007c\n\u007c\u005f\u005f\u005f\u005f\u002f\u007c\u005f\u007c\u0020\u005c\u005f\u007c\u005f\u005f\u005f\u005f\u002f\u007c\u005f\u005f\u005f\u005f\u005f\u005c\u005f\u005f\u005f\u002f\u0020\u005c\u005f\u005f\u002c\u0020\u007c\n\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u007c\u005f\u005f\u005f\u002f\n\u0042\u006c\u006f\u0067\uff1a\u0077\u0077\u0077\u002e\u006e\u0073\u0074\u006e\u0073\u002e\u0063\u006f\u006d\n\u0047\u0069\u0074\u0068\u0075\u0062\u0020\u003a\u0020\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u0067\u0069\u0074\u0068\u0075\u0062\u002e\u0063\u006f\u006d\u002f\u0063\u0068\u0069\u006e\u0061\u0059\u006f\u007a\u007a")
    DNS=Thread(name="DNS_Server",target=DNS)
    DNS.setDaemon(True)
    DNS.start()
    try:
     while 1:
        pass
    except KeyboardInterrupt:
        print("\u005b\u002b\u005d\u0020\u0053\u0074\u006f\u0070\u0020\u006f\u0070\u0065\u0072\u0061\u0074\u0069\u006f\u006e")
        sys.exit()