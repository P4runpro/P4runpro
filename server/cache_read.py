#!/usr/bin/env python3
from scapy.all import *

eth = Ether()
ip = IP(dst="1.2.3.4")
udp = UDP(sport=7777, dport=7777)
# 128-bit payload for the NetChahe header:
# 32-bit op: cache read
# 64-bit key: 0x0000000000008888
# 32 bit value: whatever
payload = b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x88\x88\x00\x00\x00\x00'

pkt = eth / ip / udp / payload
#TODO: set your iface here
sendp(pkt, iface = "ens1f0")
print(pkt.show())