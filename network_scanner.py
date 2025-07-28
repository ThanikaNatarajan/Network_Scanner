import argparse
from scapy.all import Ether, ARP, srp, IP, TCP, sr

def arp_scan(ip):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, unans = srp(request, timeout=2, verbose=0)
    result = []
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
    return result

def tcp_scan(ip, ports):
    syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    ans, unans = sr(syn, timeout=2, verbose=0)
    result = []
    for sent, received in ans:
        # SYN+ACK flag means open port
        if received.haslayer(TCP) and received[TCP].flags & 0x12 == 0x12:
            result.append(received[TCP].sport)
    return result

def main():
    parser = argparse.ArgumentParser(description="Network Scanner (ARP and TCP SYN scan)")
    subparsers = parser.add_subparsers(dest='command', required=True)

    arp_parser = subparsers.add_parser('ARP', help="Perform ARP scan")
    arp_parser.add_argument('IP', help='Target IP address or subnet (e.g., 192.168.1.1/24)')

    tcp_parser = subparsers.add_parser('TCP', help="Perform TCP SYN scan")
    tcp_parser.add_argument('IP', help='Target IP address or hostname')
    tcp_parser.add_argument('PORTS', nargs='+', type=int, help='Target port(s) (space separated)')
    tcp_parser.add_argument('--range', action='store_true', help='Treat two ports as a range (low high)')

    args = parser.parse_args()

    if args.command == 'ARP':
        result = arp_scan(args.IP)
        for r in result:
            print(f"{r['IP']} ==> {r['MAC']}")
    elif args.command == 'TCP':
        if args.range and len(args.PORTS) == 2:
            ports = list(range(args.PORTS[0], args.PORTS[1] + 1))
        else:
            ports = args.PORTS
        open_ports = tcp_scan(args.IP, ports)
        for port in open_ports:
            print(f"Port {port} is open.")

if __name__ == "__main__":
    main()