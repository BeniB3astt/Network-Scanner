#!/usr/bin/python3

import argparse
import ipaddress
import scapy.all as scapy
import netifaces
import sys
from pwn import *

def get_arguments():
    parser = argparse.ArgumentParser(description="Realizar un escaneo ARP en la red de una interfaz específica.")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface [example: python3 Network_Scanner -i eth0]")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[!] Por favor, añada su interfaz de red con el parametro -i, --help para más información.")
    return options

class Scan:
    def arp_scan(self, interface):
        try:
            # Obtener la dirección IP y máscara de red de la interfaz especificada
            iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
            target_ip = iface_info['addr']
            netmask = iface_info['netmask']

            network = ipaddress.IPv4Network(f"{target_ip}/{netmask}", strict=False)

            print(""" __  _ ___ _____ _   _  __  ___ _  __    __   ___ __  __  _ __  _ ___ ___   
|  \| | __|_   _| | | |/__\| _ \ |/ /  /' _/ / _//  \|  \| |  \| | __| _ \  
| | ' | _|  | | | 'V' | \/ | v /   <   `._`.| \_| /\ | | ' | | ' | _|| v /  
|_|\__|___| |_| !_/ \_!\__/|_|_\_|\_\  |___/ \__/_||_|_|\__|_|\__|___|_|_\  """)
            print("=========================================")

            p1 = log.progress("NETWORK-SCANNER")
            p1.status(f"[+] Escaneando dispositivos en la red de la interfaz {interface} (Network: {network})")

            arp_request = scapy.ARP(pdst=str(network))
            br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            request = br / arp_request
            answered = scapy.srp(request, timeout=1, inter=0.02, verbose=False)[0]

            print('IP\t\t\tMAC')
            print('_' * 37)
            for i in answered:
                ip, mac = i[1].psrc, i[1].hwsrc
                print(ip, '\t\t' + mac)
                print('-' * 37)

        except ValueError as ve:
            print(f"\nInterfaz {interface} no encontrada... :(")
            sys.exit(1)

if __name__ == "__main__":
    args = get_arguments()
    arp_scan_instance = Scan()
    arp_scan_instance.arp_scan(args.interface)
