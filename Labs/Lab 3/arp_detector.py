# Yedidia Bakuradze - 332461854
# Meir Crombie - 214736688

from scapy.all import ARP, sniff,conf,get_if_addr,get_if_hwaddr
import subprocess


# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def print_regular(message):
    print(f"{Colors.GREEN}{message}{Colors.END}")

def print_suspected(message):
    print(f"{Colors.YELLOW}{message}{Colors.END}")

def print_alert(message):
    print(f"{Colors.RED}{message}{Colors.END}")

# Data structures to store current ARP table's state
captured = []
counter = 1
arp_table = {}
sus_counter = {}

my_ip = get_if_addr(conf.iface) 
my_mac = get_if_hwaddr(conf.iface)



# Checks faster if there are any duplicated values of mac_add MAC addresses 
def is_dup_exists(mac_add):
    result = subprocess.run(["arp",'-n'],capture_output=True,text=True)
    count_time_of_appear = 0
    skip_first = True

    for line in result.stdout.split('\n'):
        try:
            # Skip the headers
            if skip_first:
                skip_first = False
                continue
            
            args = line.split()
            mac = args[2]
            
            if mac == mac_add:
                count_time_of_appear = count_time_of_appear + 1
                if count_time_of_appear >=2:
                    return True
            
        # The last line of the table is empty
        except Exception:
            pass
    return False

# Initializes a copy of the ARP table so we would analyze the situation relative to the optimal state
def init():
    global arp_table,counter
    
    # Take a snapshot of the current state of the ARP table
    print_regular("Building ARP table ...")
    subprocess.run(["sudo", "arp-scan", "-I", f"{conf.iface}", "--localnet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print_regular("ARP Table Build is Completed! Storing State ...")
    result = subprocess.run(["arp",'-n'],capture_output=True,text=True)
    if not result: print("unable to load arp table")

    # Build the ARP table while checking out if attacked
    attacked = True
    while attacked:
        # Rescan the network and checkout again
        subprocess.run(["sudo", "arp-scan", "-I", f"{conf.iface}", "--localnet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.run(["arp",'-n'],capture_output=True,text=True)
        
        attacked = False
        skip_first = True
        arp_table = {}
        for line in result.stdout.split('\n'):
            try:
                # Skip the headers
                if skip_first:
                    skip_first = False
                    continue
                
                args = line.split()
                ip = args[0]
                mac = args[2]

                # Find if there is such enterence already
                try:
                    tmp = arp_table[mac]
                    print_alert("You're Playing it Dirty, I Didn't Even Start Up Yet!")
                    print_alert("Indicators: Duplicate MAC and ARP Reply without Request been Detected")
                    attacked = True
                    break
                except KeyError:
                    arp_table[mac] = ip
            # The last line of the table is empty
            except Exception:
                pass

    print_regular("ARP Table State has been Stored!")

# The function that's preformed when packet is sniffed
def callback(pkt):
    global my_ip,counter,my_mac,sus_counter,captured

    # Ignore packets that didn't meant for me
    if not (pkt[ARP].pdst == my_ip or pkt[ARP].psrc == my_ip): return

    indi_1 = False
    indi_2 = False
    # ARP reply messages
    if pkt[ARP].op == 2 and pkt[ARP].hwdst == my_mac:
        print_regular(f"({counter}) Incoming packet ----------------->")
        print_regular(str(pkt))
        print_regular("<----------------------------------------------")
        counter = counter + 1

        # Find if there is a request for the reply message
        found = False
        for cap in captured:
            if cap[ARP].pdst == pkt[ARP].psrc:
                captured.remove(cap)
                found = True
                break

        # If this packet is a reply for a request that this device made - its ok
        if found: return 
        else:
            # Set a counter for each source which targets
            try:
                sus_counter[pkt[ARP].hwsrc] = sus_counter[pkt[ARP].hwsrc] + 1
                print(f"Counter for: {pkt[ARP].hwsrc}: {sus_counter[pkt[ARP].hwsrc]}")
            except KeyError:
                sus_counter[pkt[ARP].hwsrc] = 1
                print(f"Rest Counter for: {pkt[ARP].hwsrc}: {sus_counter[pkt[ARP].hwsrc]}")
            except Exception:
                print("Unexpected err")
                exit(0)
            
            if sus_counter[pkt[ARP].hwsrc] >= 4:
                print_suspected(f"Indicator #1 - ARP Reply without Request")
                indi_1 = True

        # Check indicator 2
        try:
            ip = arp_table[pkt[ARP].hwsrc]
            if ip != pkt[ARP].psrc:
                print_suspected("Indicator #2 - Duplicated MAC Addresses for Different IP's")
                indi_2 = True
        except KeyError:
            pass
        
        # Edge case: New device just entered - check out
        if is_dup_exists(pkt[ARP].hwsrc) and not indi_2:
            print_suspected("Indicator #2 - (New Device) Duplicated MAC Addresses for Different IP's")
        if indi_2 and indi_1:
            print_alert(f"NETWORK IS UNDER ATTACK! | {str(pkt)}")
        elif indi_1 or indi_2:
            print_suspected("Something is off ... Watch Out!")
        
    # Save packets
    elif pkt[ARP].op == 1:
        captured.append(pkt[ARP])
    

init()
sniff(filter="arp",prn=callback)