#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.fields import *

class Hula(Packet):
   fields_desc = [ BitField("dir", 0, 1),
                   BitField("qdepth", 0, 15),
                   BitField("digest", 0, 32),]

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, Hula, type=0x2345)
bind_layers(Hula, SourceRoute)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[2])
    iface = sys.argv[1]

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / Hula(dir=0, qdepth=0, digest=0)
    pkt = pkt / SourceRoute(bos=0, port=2) / SourceRoute(bos=0, port=2)
    pkt = pkt / SourceRoute(bos=0, port=1) / SourceRoute(bos=1, port=1)
    pkt = pkt / IP(dst=addr, src='10.0.1.0') / UDP(dport=4321, sport=1234)
#    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff') / IP(dst=addr) / UDP(dport=4321, sport=1234)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
