#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import string

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw
import sys
import random, string

def randomword(max_length):
    length = random.randint(1, max_length)
    return ''.join(random.choice(string.lowercase) for i in range(length))

def read_topo():
    nb_hosts = 0
    nb_switches = 0
    links = []
    with open("topo.txt", "r") as f:
        line = f.readline()[:-1]
        w, nb_switches = line.split()
        assert(w == "switches")
        line = f.readline()[:-1]
        w, nb_hosts = line.split()
        assert(w == "hosts")
        for line in f:
            if not f: break
            a, b = line.split()
            links.append( (a, b) )
    return int(nb_hosts), int(nb_switches), links

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def send_random_traffic(dst):
    dst_mac = None
    dst_ip = None
    iface = get_if()
    src_mac = [get_if_hwaddr(i) for i in get_if_list() if i == iface]
    if len(src_mac) < 1:
        print ("No interface for output")
        sys.exit(1)
    src_mac = src_mac[0]
    src_ip = None
    if src_mac =="00:00:00:00:00:01":
        src_ip = "10.0.0.1"
    elif src_mac =="00:00:00:00:00:02":
        src_ip = "10.0.0.2"
    elif src_mac =="00:00:00:00:00:03":
        src_ip = "10.0.0.3"
    else:
        print ("Invalid source host")
        sys.exit(1)

    if dst == 'h1':
        dst_mac = "00:00:00:00:00:01"
        dst_ip = "10.0.0.1"
    elif dst == 'h2':
        dst_mac = "00:00:00:00:00:02"
        dst_ip = "10.0.0.2"
    elif dst == 'h3':
        dst_mac = "00:00:00:00:00:03"
        dst_ip = "10.0.0.3"
    else:
        print ("Invalid host to send to")
        sys.exit(1)

    total_pkts = 0
    random_ports = random.sample(xrange(1024, 65535), 10)
    for port in random_ports:
        num_packets = random.randint(10, 50)
        for i in range(num_packets):
            data = randomword(10)
            p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
            p = p/TCP(dport=port)/Raw(load=data)
            print p.show()
            sendp(p, iface = "h1-eth0")
            total_pkts += 1
    print "Sent %s packets in total" % total_pkts

def main():

    if len(sys.argv)<2:
        print 'pass 1 arguments: <destination>'
        exit(1)

    dst_name = sys.argv[1]
    send_random_traffic(dst_name)


if __name__ == '__main__':
    main()
