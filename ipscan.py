from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

def arp_scan_ip(ip):
    """
    単一IPに対してARPスキャンを実行し、応答があれば結果を返す
    """
    arp = ARP(pdst=str(ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=1, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return devices

def arp_scan_parallel(network_range, max_workers=50):
    """
    ネットワーク範囲に対して並列ARPスキャンを実行
    """
    devices_found = []
    ip_list = list(ipaddress.IPv4Network(network_range, strict=False).hosts())

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(arp_scan_ip, ip) for ip in ip_list]
        
        for future in as_completed(futures):
            devices_found.extend(future.result())

    return devices_found

if __name__ == "__main__":
    # 実行例: 自宅LAN (192.168.0.0/24) をスキャン
    devices = arp_scan_parallel("192.168.0.0/24", max_workers=100)

    print("\n=== 検出されたデバイス ===")
    for dev in devices:
        print(f"IP: {dev['ip']}, MAC: {dev['mac']}")
