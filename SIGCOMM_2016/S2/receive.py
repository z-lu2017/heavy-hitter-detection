#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

VALID_IPS = ("10.0.0.1", "10.0.0.2", "10.0.0.3")
totals = {}

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)
        if src_ip in VALID_IPS:
            if id_tup not in totals:
                totals[id_tup] = 0
            totals[id_tup] += 1
            print ("Received from %s total: %s" %
                    (id_tup, totals[id_tup]))
        s = summation()
        print("Total packets received thus far= ", s)

def summation():
    t = 0;
    for k in totals:
	t = t + totals[k];    
    return t;

def main():
    sniff(iface = conf.iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
