#!/usr/bin/env python
from scapy.all import *
import sys
import getopt




name = "Coffee Packet Sniffer"
def banner(name, char="#"):
	frame_line = char * (len(name) + 4)
	print(frame_line)
	print('{0} {1} {0}'.format(char, name))
	print(frame_line)
banner(name)

def tcp_sniff(packet):
	if packet.haslayer(IP):
		pckt_src = packet[IP].src
		pckt_dst = packet[IP].dst
		pckt_ttl = packet[IP].ttl
		print("Packet: %s -----> %s with TTL value %s |>| TCP/IP " % (pckt_src, pckt_src, pckt_ttl))
	
def arp_sniff(packet):
	if packet.haslayer(ARP):
		if packet[ARP].op == 1:
			print("REQUEST: %s <----- asks about -----> %s" % (packet[ARP].psrc, packet[ARP].pdst))
		if packet[ARP].op == 2:
			print("RESPONSE: %s <----- with address -----> %s" % (packet[ARP].hwsrc, packet[ARP].psrc))
def ipv6_sniff(packet):
	if packet.haslayer(IPv6):
		i6src = packet[IPv6].src
		i6dst = packet[IPv6].dst
		print("Packet: %s -----> %s |>| ICMPv6 " % (i6src, i6dst))

def usage():	
	print("COFFEE Packet Sniffer, to see this message use ./coffee.py -h")
	print("Use -i switch to capture ICMP packets")
	print("Use -a switch to capture ARP packets")
	print("Use -s switch to capture ICMPv6 packets")

def main():
	try:
	    opts, args = getopt.getopt(sys.argv[1:],"iash")
	except getopt.GetoptError as e:
	    print (str(e))
	    print("Example of usage: %s -t (TCP capture mode) " % (sys.argv[0]))
	    sys.exit(2)

	 
	for o, a in opts:
		if o == '-i':
			sniff(iface="eth0", prn=tcp_sniff, store=0)
		elif o == '-a':
			sniff(iface="eth0", prn=arp_sniff, store=0)
		elif o == '-s':
			sniff(iface="eth0", prn=ipv6_sniff, store=0)
		elif o == '-h':
			usage()

if __name__ == "__main__":
	main()