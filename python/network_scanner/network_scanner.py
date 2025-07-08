from scapy.layers.l2 import ARP, Ether
from manuf import manuf
from scapy.all import srp
import  argparse
import socket
# from scapy.layers.l2 import ARP, Ether
# import scapy.all as scapy

# def scan(ip):
#     # arping(ip)
#     arp_request= scapy.ARP(pdst=ip)
#     print(arp_request.summary())
#     # scapy.ls(scapy.ARP() )

# Internet frame


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown hostname"
    
def get_vendor(mac_address):
    parser = manuf.MacParser()
    vendor = parser.get_manuf(mac_address)
    return vendor if vendor else "Unknown vendor"

def scan(ip_range):
    arp_request = ARP(pdst=ip_range)
    # arp_request.show()
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    ans = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    # print(ans.summary())
    # for _, r in ans:
    #     print("[-] Ip ", r.psrc,"[-] Mack", r.hwsrc, _)

    client_lists = []
    for element in ans:
        client_dict = {"ip": element[1].psrc, "mac":element[1].hwsrc}
        client_lists.append(client_dict)
    return client_lists

def print_result(result_lists):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    # print("IP\t\t\tMAC Address\t\t\tVendor\t\t\tHostname")
    for client in result_lists:
        # print(client)
        # vendor = get_vendor(client["mac"])
        # hostname = get_hostname(client["ip"])
        print(client["ip"] + "\t\t" + client["mac"])
        # print(f"{client['ip']}\t\t{client['mac']}\t\t{vendor}")
        # print(f"{client['ip']}\t\t{client['mac']}\t{vendor[:20]}\t{hostname}")


options=get_argument()
scan_result = scan(options.target)
print_result(scan_result)