#!/usr/bin/python3
from scapy.all import *
import pprint
from ipwhois import IPWhois
pp = pprint.PrettyPrinter(indent=4)
packets = rdpcap('work.pcapng')
newpcap = PcapWriter ("new.pcap", append= True)

counter = 0
print(packets)
iplist= []
for packet in PcapReader("work.pcapng"):
	try:
	   if packet[IP]:
	      iplist.append(packet[IP].dst)
	      newpcap.write(packet)
	      counter+=1
	      
	except:
	   pass
	if counter >110:
		break

#pp.pprint(iplist)


uniqueIPS = set(iplist) 


local = "10.0"
uniqueIPS = [ip for ip in uniqueIPS if not ip.startswith(local)]
unique2 = list(uniqueIPS)
diction ={str(unique2[0]):0, str(unique2[1]):0, str(unique2[2]):0, str(unique2[3]):0}

for x in range(0,len(iplist)):
	if(str(iplist[x]) in diction):
		diction[str(iplist[x])] +=1
for x in range(0, len(unique2)):
	
	ip0= str(unique2[x])	
	whoisinfo = IPWhois(ip0)
	results = whoisinfo.lookup_rdap (depth=1)
#print(results["asn_description"])
	print(unique2[x], results["entities"], results["asn_date"], results["asn_registry"])
print(max(diction.items(), key=operator.itemgetter(1))[0], "is most frequent in destination")
print(diction)
#pp.pprint(uniqueIPS)
#for packet in PcapReader("work.pcapng"):
	#try:
	  #print(packet[IP].src, packet[IP].dst)
	#except:
	  #pass
	  
#for packet in packets:
	#if packet.haslayer(DNSRR):
		#if isinstance(packet.an, DNSRR):
			#print(packet.an.rrname)

