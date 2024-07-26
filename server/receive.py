#!/usr/bin/env python3
from scapy.all import *

def packet_callback(packet):
    if packet[UDP].dport == 7777:
        #print(packet.show())
        print(packet[Raw].load[-4:])
        
#TODO: set your iface here
sniff(iface="ens1f0", filter='inbound and udp' ,prn=packet_callback, store=0)