import argparse
import subprocess
import platform
import psutil
import netifaces
from scapy.all import ARP, Ether, srp, sniff
import ipaddress
import signal
import sys
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------
# グローバル
# ----------------------------
original_config = {}
selected_iface = None
lock = threading.Lock()
backup_file = "ip_config_backup.json"

# Ctrl+Cで元設定復元
def signal_handler(sig, frame):
    print("\n[!] 中断シグナル受信。元の設定に戻します…")
    restore_original_config()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ----------------------------
# インターフェイス選択
# ----------------------------
def select_interface():
    interfaces = list(psutil.net_if_addrs().keys())
    print("利用可能なインターフェース:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    idx = int(input("番号を選択してください: "))
    return interfaces[idx]

# ----------------------------
# 現在のIP設定取得＆表示
# ----------------------------
def get_iface_config(iface):
    addrs = netifaces.ifaddresses(iface)
    ipv4_info = addrs.get(netifaces.AF_INET, [{}])[0]
    ip = ipv4_info.get('addr')
    netmask = ipv4_info.get('netmask')
    gateways = netifaces.gateways()
    default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
    gateway = default_gw[0] if default_gw else None

    # DHCPか静的か判定
    mode = "STATIC"
    os_name = platform.system().lower()
    if os_name != "windows":
        try:
            result = subprocess.run(["nmcli", "dev", "show", iface], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "IP4.DHCP" in line and line.strip().split(":")[1].strip():
                    mode = "DHCP"
                    break
        except:
            pass
    else:
        # Windowsでは簡易的にDHCPかを確認
        try:
            result = subprocess.run(["netsh", "interface", "ip", "show", "config", iface],
                                    capture_output=True, text=True)
            if "DHCP enabled: Yes" in result.stdout:
                mode = "DHCP"
        except:
            pass

    return {
        "interface": iface,
        "ip": ip,
        "netmask": netmask,
        "gateway": gateway,
        "mode": mode
    }

def save_original_config(iface):
    global original_config
    original_config = get_iface_config(iface)
    print("\n[INFO] 現在のIP設定:")
    for k, v in original_config.items():
        print(f"  {k}: {v}")
    # バックアップ保存
    with open(backup_file, "w") as f:
        json.dump(original_config, f, indent=2)
    print(f"[INFO] 設定をバックアップファイルに保存: {backup_file}")

def restore_original_config(file=None):
    global selected_iface
    config = original_config
    if file:
        try:
            with open(file, "r") as f:
                config = json.load(f)
            print(f"[INFO] バックアップファイルから設定を読み込み: {file}")
        except Exception as e:
            print(f"[!] バックアップファイル読み込み失敗: {e}")
            return
    if not config.get("ip"):
        print("[!] 復元情報なし")
        return
    os_name = platform.system().lower()
    iface = config["interface"]
    ip = config["ip"]
    netmask = config["netmask"]
    gateway = config["gateway"]
    if os_name != "windows":
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface])
        subprocess.run(["sudo", "ip", "addr", "add", f"{ip}/{netmask_to_prefix(netmask)}", "dev", iface])
        subprocess.run(["sudo", "ip", "route", "add", "default", "via", gateway, "dev", iface])
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"])
    else:
        subprocess.run(["netsh", "interface", "ip", "set", "address", iface, "static", ip, netmask, gateway])
    print("[+] IP設定を復元しました。")

# ----------------------------
# IP変更
# ----------------------------
def set_ip(iface, ip, netmask):
    os_name = platform.system().lower()
    if os_name == "windows":
        subprocess.run(["netsh", "interface", "ip", "set", "address", iface, "static", ip, netmask])
    else:
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface])
        subprocess.run(["sudo", "ip", "addr", "add", f"{ip}/{netmask_to_prefix(netmask)}", "dev", iface])
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"])

def netmask_to_prefix(netmask):
    return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen

# ----------------------------
# 受動的ARP検知
# ----------------------------
def passive_discovery(iface, timeout=5):
    print("[*] 受動的検知を開始します…")
    hosts = set()

    def arp_display(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:
            hosts.add((pkt[ARP].psrc, pkt[ARP].hwsrc))

    sniff(iface=iface, prn=arp_display, store=0, timeout=timeout)
    print(f"[+] 受動的検知完了。検出IP/MAC: {[f'IP: {ip}, MAC: {mac}' for ip, mac in hosts]}")
    return hosts

# ----------------------------
# IP使用確認（ping）
# ----------------------------
def is_ip_in_use(ip):
    os_name = platform.system().lower()
    try:
        if os_name == "windows":
            result = subprocess.run(["ping", "-n", "1", "-w", "500", ip], stdout=subprocess.DEVNULL)
        else:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

# ----------------------------
# 空きIP探索
# ----------------------------
def find_free_ip(base_ip, netmask, fast_range):
    octets = base_ip.split('.')
    for third in range(fast_range):
        for host in range(1, 255):
            candidate = f"{octets[0]}.{octets[1]}.{third}.{host}"
            if not is_ip_in_use(candidate):
                return candidate
    return None

# ----------------------------
# 能動スキャン（並列＋リアルタイム進捗＋MAC取得）
# ----------------------------
def arp_scan_ip(ip, iface):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, iface=iface, timeout=0.5, verbose=False)
    return [(rcv.psrc, rcv.hwsrc) for _, rcv in ans]

def active_scan(iface, scan_segments, max_threads=20):
    total_found = set()
    for segment in scan_segments:
        net = ipaddress.IPv4Network(segment)
        hosts = list(net.hosts())
        total = len(hosts)
        scanned_count = 0
        found = set()

        def worker(ip):
            nonlocal scanned_count
            result = arp_scan_ip(ip, iface)
            with lock:
                scanned_count += 1
                print(f"\r[SCAN] {segment} をスキャン中... {scanned_count}/{total}", end="")
            return result

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(worker, str(ip)) for ip in hosts]
            for future in as_completed(futures):
                result = future.result()
                with lock:
                    found.update(result)
                    total_found.update(result)

        print()
        for ip, mac in found:
            print(f"IP: {ip}, MAC: {mac}")

    return total_found

# ----------------------------
# メイン
# ----------------------------
def main():
    global selected_iface
    parser = argparse.ArgumentParser(
        description="ハイブリッドネットワークスキャナー",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--iface", help="使用するネットワークインターフェース名 例: eth0")
    parser.add_argument("--segments", help="カンマ区切りでスキャン対象セグメント指定（例: 192.168.0.0/24,172.16.0.0/24）")
    parser.add_argument("--full", action="store_true", help="全範囲スキャンを有効化（リンクローカル169.254.x.xを含む）")
    parser.add_argument("--fast-range", type=int, default=2,
                        help="fast scanの第3オクテット範囲（デフォルト2 → 0と1）")
    parser.add_argument("--threads", type=int, default=20,
                        help="並列スレッド数（デフォルト20 max50）")
    parser.add_argument("--restore", help="バックアップファイルからIP設定を復元")

    args = parser.parse_args()

    if args.restore:
        restore_original_config(args.restore)
        return

    selected_iface = args.iface or select_interface()
    save_original_config(selected_iface)

    # 受動検知
    passive_results = passive_discovery(selected_iface)

    # 空きIP探索
    free_ip = find_free_ip(original_config["ip"], original_config["netmask"], args.fast_range)
    if not free_ip:
        print("[!] 空きIPが見つかりません。fast範囲を広げるかfull scanを試してください。")
        restore_original_config()
        return
    print(f"[*] 使用可能なIPを発見: {free_ip}")
    set_ip(selected_iface, free_ip, original_config["netmask"])

    # スキャン対象セグメント
    if args.segments:
        scan_segments = [seg.strip() for seg in args.segments.split(",")]
    else:
        scan_segments = ["192.168.0.0/24", "172.16.0.0/24"]
        common_dhcp_segments = ["192.168.1.0/24", "172.16.1.0/24"]
        scan_segments = list(dict.fromkeys(scan_segments + common_dhcp_segments))

    if args.full:
        scan_segments += ["169.254.0.0/16"]

    print("[*] 能動スキャン開始...")
    active_results = active_scan(selected_iface, scan_segments, max_threads=args.threads)

    print(f"\n[+] スキャン結果（受動+能動）:")
    for ip, mac in passive_results | active_results:
        print(f"IP: {ip}, MAC: {mac}")

    restore_original_config()

if __name__ == "__main__":
    main()

