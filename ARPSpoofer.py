import sys
import subprocess
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

out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=True)
parts = out.stdout.split()
src = parts[2]
iface = parts[4]
delay = 0
should_attack_gateway = False
target_ip = None

def send_to_target():
    pass

def send_to_victem():
    pass

def main():
    print(sys.argv)
    if len(sys.argv) <= 1 :
        print("Default ope")
        exit()

    args = sys.argv[1:]


    # Help
    if args[0] == '-h' or args[0] == '--help' :
        print(help_msg)
        exit()

    while len(args) > 0:
        global iface, src,delay,should_attack_gateway,target_ip

        # IFACE Set
        if args[0] == '-i' or args[0] == '--iface' :
            # Run the ifconfig command, and search via Regex if interface exsits
            iface = args[1]
            if not iface:  
                print("You must specify the value of the new IFACE")
            args = args[2:]
            continue
        
        if args[0] == '-s' or args[0] == '--src' :
            src = args[1]
            if not src:  
                print("You must specify the value of the new SRC address")
            args = args[2:]
            continue

        if args[0] == '-d' or args[0] == '--delay' :
            delay = args[1]
            if not delay:  
                print("You must specify the value of the delay")
            args = args[2:]
            continue
        
        if args[0] == '-gw' :
            should_attack_gateway = True
            args = args[1:]
            continue

        if args[0] == '-t' or args[0] == '--target' :
            target_ip = args[1]
            if not delay:  
                print("You must specify the value of the TARGET")
            args = args[2:]
            continue
    
    if target_ip == None:
        print("Please specify the target value")
        exit()
    
    # Run the attack
    print (f"IFACE {iface}")
    print (f"SRC {src}")
    print (f"Delay {delay}")
    print (f"GW {should_attack_gateway}")
    print (f"TARGET {target_ip}")

main()