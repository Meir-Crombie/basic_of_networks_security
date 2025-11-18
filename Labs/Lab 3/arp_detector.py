from scapy.all import ARP, sniff

captured = []
counter = 1
def find_pkt_by_src(src_ip):
    for pkt in captured:
        if pkt[ARP].pdst == src_ip:
            return pkt
    
    return None

def callback(pkt):
    print(f"({counter}) Incoming packet ----------------->")
    print(pkt)
    print("<----------------------------------------------")
    counter = counter + 1
    
    if pkt[ARP].op == 2:
        val = find_pkt_by_src(pkt[ARP].psrc)
        if val:
            captured.remove(val)
        else:
            print(f"Indicator #1 - Reply without Request: SRC: {pkt[ARP].psrc} / {pkt[ARP].hwsrc}")
    else:
        captured.append(pkt)
    

sniff(filter="arp",prn=callback)