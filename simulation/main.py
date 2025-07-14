import os
import time
import random
import uuid
import psutil
import socket
import hashlib
import json
import subprocess
import pandas as pd
from scapy.all import IP, TCP, wrpcap, Raw
from colorama import Fore, Style, init
from tabulate import tabulate
import pyfiglet

init()

DEFAULT_DURATION = 10
MIN_PACKETS_PER_ATTACK = 1000
MIN_SUSPICIOUS_IPS = 3
MAX_SUSPICIOUS_IPS = 10
MIN_TOTAL_IPS = 50
MAX_TOTAL_IPS = 500

def get_intrusion_x_appdata_dir():
    appdata_dir = os.path.expandvars(r'%LOCALAPPDATA%\intrusion_x')
    os.makedirs(appdata_dir, exist_ok=True)
    return appdata_dir

def calculate_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return None

def store_simulation_metadata(uuid_str, metadata):
    try:
        appdata_dir = get_intrusion_x_appdata_dir()
        metadata_file = os.path.join(appdata_dir, f"{uuid_str}.json")
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return True
    except Exception:
        return False

def protect_file_from_rn(file_path):
    try:
        if os.name == 'nt':
            username = os.getenv('USERNAME')
            cmd = ['icacls', file_path, '/deny', f'{username}:W']
            subprocess.run(cmd, capture_output=True, text=True)
    except Exception:
        pass

def print_header():
    print(Fore.CYAN + Style.BRIGHT + "=" * 80)
    
    ascii_art = pyfiglet.figlet_format("CYBER SIMULATOR", font="slant")
    for line in ascii_art.split('\n'):
        if line.strip():
            print(Fore.YELLOW + Style.BRIGHT + line.center(80))
    
    print(Fore.CYAN + Style.BRIGHT + "=" * 80)
    print(Fore.WHITE + Style.BRIGHT + (" " * 19) + "Network Traffic Simulation for IDS Testing")
    print(Fore.GREEN + (" " * 22) + "Part of Intrusion X - ML-Based NIDS")
    print(Fore.CYAN + Style.BRIGHT + "=" * 80)
    print()
    print(Fore.WHITE + "This simulation generates realistic attack packets for testing IDS models:")
    print(Fore.YELLOW + "  * DoS attacks (Hulk, GoldenEye, Slowloris, Slowhttptest)")
    print(Fore.YELLOW + "  * Brute force attacks (FTP-Patator, SSH-Patator)")
    print(Fore.YELLOW + "  * Botnet traffic")
    print(Fore.YELLOW + "  * Heartbleed exploits")
    print()
    print(Fore.GREEN + "Designed to test: Tree-Based-IDS, LCCDE, and MTH-IDS frameworks")
    print(Fore.CYAN + Style.BRIGHT + "=" * 80 + Style.RESET_ALL)
    print()

def print_section_header(title):
    print(Fore.CYAN + Style.BRIGHT + "\n" + "─" * 60)
    print(f"  {title}")
    print("─" * 60 + Style.RESET_ALL)

def validate_input(prompt, default_value, min_value=None, max_value=None):
    while True:
        colored_prompt = Fore.YELLOW + prompt + Style.RESET_ALL
        user_input = input(colored_prompt).strip()
        
        if not user_input:
            return default_value
        
        try:
            value = int(user_input)
            
            if min_value is not None and value < min_value:
                print(Fore.RED + f"Error: Value must be at least {min_value}" + Style.RESET_ALL)
                continue
            
            if max_value is not None and value > max_value:
                print(Fore.RED + f"Error: Value must be at most {max_value}" + Style.RESET_ALL)
                continue
            
            return value
            
        except ValueError:
            print(Fore.RED + "Error: Please enter a valid integer" + Style.RESET_ALL)

def get_threat_level():    
    threat_levels = {
        1: {"name": "Low", "attack_percentage": 10, "description": "Minimal Threat Simulation"},
        2: {"name": "Medium", "attack_percentage": 37, "description": "Moderate Threat Simulation"},
        3: {"name": "High", "attack_percentage": 66, "description": "High Threat Simulation"},
        4: {"name": "Critical", "attack_percentage": 95, "description": "Critical Threat Simulation"}
    }
    
    print(Fore.CYAN + "Available threat levels:" + Style.RESET_ALL)
    threat_table = []
    for level, info in threat_levels.items():
        threat_table.append([level, info["name"], f"{info['attack_percentage']}%", info["description"]])
    
    print(tabulate(threat_table, headers=["Option", "Level", "Attack %", "Description"], tablefmt="grid"))
    print()
    
    while True:
        try:
            choice = input(Fore.YELLOW + "Select threat level (1-4, default 2 for Medium): " + Style.RESET_ALL).strip()
            
            if not choice:
                choice = 2
            else:
                choice = int(choice)
            
            if choice in threat_levels:
                selected = threat_levels[choice]
                print(Fore.GREEN + f"Selected: {selected['name']} threat level ({selected['attack_percentage']}% attack packets)" + Style.RESET_ALL)
                return selected["attack_percentage"], selected["name"]
            else:
                print(Fore.RED + "Error: Please select a valid option (1-4)" + Style.RESET_ALL)
                
        except ValueError:
            print(Fore.RED + "Error: Please enter a valid number" + Style.RESET_ALL)

def get_user_config():
    print_section_header("Configuration Settings")
    
    attack_percentage, threat_level_name = get_threat_level()
    
    duration = validate_input(
        f"Enter attack duration in seconds (default {DEFAULT_DURATION}): ",
        DEFAULT_DURATION,
        min_value=1,        max_value=3600
    )
    
    min_packets = validate_input(
        f"Enter minimum packets per attack (default {MIN_PACKETS_PER_ATTACK}): ",
        MIN_PACKETS_PER_ATTACK,
        min_value=100,
        max_value=10000
    )    
    
    suspicious_count = validate_input(
        f"Enter number of suspicious IPs ({MIN_SUSPICIOUS_IPS}-{MAX_SUSPICIOUS_IPS}, default {MIN_SUSPICIOUS_IPS}): ",
        MIN_SUSPICIOUS_IPS,
        min_value=MIN_SUSPICIOUS_IPS,
        max_value=MAX_SUSPICIOUS_IPS
    )
    
    total_count = validate_input(
        f"Enter total number of IPs ({MIN_TOTAL_IPS}-{MAX_TOTAL_IPS}, default {MIN_TOTAL_IPS}): ",
        MIN_TOTAL_IPS,
        min_value=MIN_TOTAL_IPS,
        max_value=MAX_TOTAL_IPS
    )
    
    if suspicious_count >= total_count * 0.8:
        total_count = max(total_count, int(suspicious_count * 1.5))
        print(Fore.YELLOW + f"Auto-adjusted total IPs to {total_count} for better distribution" + Style.RESET_ALL)
    
    print()
    print(Fore.GREEN + "Configuration Summary:" + Style.RESET_ALL)
    config_table = [
        ["Threat Level", f"{threat_level_name} ({attack_percentage}% attack packets)"],
        ["Duration", f"{duration} seconds"],
        ["Min packets per attack", f"{min_packets:,}"],
        ["Suspicious IPs", f"{suspicious_count}"],
        ["Total IPs", f"{total_count}"],
        ["Expected total packets", f"{min_packets * 8:,}+"]
    ]
    print(tabulate(config_table, headers=["Setting", "Value"], tablefmt="grid"))
    print()
    
    return duration, min_packets, suspicious_count, total_count, attack_percentage, threat_level_name

def generate_ip_pools(suspicious_count, total_count):
    all_ips = set()
    
    while len(all_ips) < total_count:
        ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
        all_ips.add(ip)
    
    all_ips_list = list(all_ips)
    suspicious_ips = random.sample(all_ips_list, suspicious_count)
    normal_ips = [ip for ip in all_ips_list if ip not in suspicious_ips]
    
    return suspicious_ips, normal_ips

def get_source_ip(suspicious_ips, normal_ips, make_suspicious=False):
    if make_suspicious and random.random() < 0.7:
        return random.choice(suspicious_ips)
    elif random.random() < 0.4:
        return random.choice(suspicious_ips)
    else:
        return random.choice(normal_ips)

def get_network_interfaces():
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                interfaces.append((interface, addr.address))
    return interfaces

def select_interface():
    interfaces = get_network_interfaces()
    if not interfaces:
        print(Fore.RED + "No network interfaces with IP addresses found." + Style.RESET_ALL)
        return None, None
    
    print(Fore.CYAN + "Available network interfaces:" + Style.RESET_ALL)
    interface_table = []
    for i, (name, ip) in enumerate(interfaces, 1):
        interface_table.append([i, name, ip])
    
    print(tabulate(interface_table, headers=["#", "Interface Name", "IP Address"], tablefmt="grid"))
    
    while True:
        try:
            colored_prompt = Fore.YELLOW + "Select interface (number): " + Style.RESET_ALL
            choice = int(input(colored_prompt)) - 1
            if 0 <= choice < len(interfaces):
                selected = interfaces[choice]
                print(Fore.GREEN + f"[OK] Selected: {selected[0]} ({selected[1]})" + Style.RESET_ALL)
                return selected
            else:
                print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)
        except ValueError:
            print(Fore.RED + "Please enter a valid number." + Style.RESET_ALL)

def generate_dos_hulk_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 8080, 8443])
        
        payload = f"GET /{random.choice(['index.html', 'login.php', 'admin', 'api/data'])}?{random.randint(1000, 9999)} HTTP/1.1\r\n"
        payload += f"Host: {target_ip}\r\n"
        payload += f"User-Agent: {random.choice(user_agents)}\r\n"
        payload += "Connection: keep-alive\r\n\r\n"
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def generate_dos_goldeneye_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443])
        
        payload = f"GET /{random.choice(['', 'index.html', 'search'])}?q={'A' * random.randint(100, 1000)} HTTP/1.1\r\n"
        payload += f"Host: {target_ip}\r\n"
        payload += "User-Agent: GoldenEye\r\n"
        payload += "Connection: keep-alive\r\n\r\n"
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def generate_ftp_patator_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    usernames = ["admin", "user", "test", "ftp", "anonymous", "guest"]
    passwords = ["password", "123456", "admin", "test", "pass", "12345"]
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=21, flags="PA") / Raw(load=f"USER {username}\r\n")
        packets.append(pkt)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=21, flags="PA") / Raw(load=f"PASS {password}\r\n")
        packets.append(pkt)
    
    return packets

def generate_ssh_patator_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        
        ssh_banner = b"SSH-2.0-OpenSSH_" + str(random.randint(6, 8)).encode() + b"." + str(random.randint(0, 9)).encode()
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=22, flags="PA") / Raw(load=ssh_banner)
        packets.append(pkt)
    
    return packets

def generate_dos_slowloris_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        
        payload = f"GET /{random.choice(['', 'index.html'])} HTTP/1.1\r\n"
        payload += f"Host: {target_ip}\r\n"
        payload += f"X-a: {random.randint(1, 999999)}\r\n"
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=80, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def generate_dos_slowhttptest_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        
        form_data = "field1=" + "A" * random.randint(1000, 5000)
        payload = f"POST /upload HTTP/1.1\r\n"
        payload += f"Host: {target_ip}\r\n"
        payload += f"Content-Length: {len(form_data) + random.randint(100, 1000)}\r\n"
        payload += "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        payload += form_data
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=80, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def generate_bot_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    bot_commands = ["download", "update", "execute", "scan", "ddos", "keylog"]
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([6667, 6668, 6669, 8080])
        
        command = random.choice(bot_commands)
        payload = f":{random.choice(['bot', 'zombie'])}{random.randint(1000, 9999)} PRIVMSG #{command} :{command} {target_ip}\r\n"
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def generate_heartbleed_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    for _ in range(count):
        src_ip = get_source_ip(suspicious_ips, normal_ips, make_suspicious=True)
        src_port = random.randint(1024, 65535)
        
        heartbeat_payload = b"\x18\x03\x02\x00\x03\x01" + b"\x40\x00" + b"A" * random.randint(64, 16384)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=443, flags="PA") / Raw(load=heartbeat_payload)
        packets.append(pkt)
    
    return packets

def generate_benign_packets(target_ip, count, suspicious_ips, normal_ips):
    packets = []
    
    web_pages = ["", "index.html", "about.html", "contact.html", "products.html", "services.html"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    
    for _ in range(count):
        if random.random() < 0.7:
            src_ip = random.choice(normal_ips)
        else:
            src_ip = random.choice(suspicious_ips)
        
        src_port = random.randint(1024, 65535)
        
        traffic_type = random.choice(["web", "email", "dns", "ftp_data"])
        
        if traffic_type == "web":
            dst_port = random.choice([80, 443])
            page = random.choice(web_pages)
            user_agent = random.choice(user_agents)
            
            payload = f"GET /{page} HTTP/1.1\r\n"
            payload += f"Host: {target_ip}\r\n"
            payload += f"User-Agent: {user_agent}\r\n"
            payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            payload += "Accept-Language: en-US,en;q=0.5\r\n"
            payload += "Accept-Encoding: gzip, deflate\r\n"
            payload += "Connection: keep-alive\r\n\r\n"
            
        elif traffic_type == "email":
            dst_port = random.choice([25, 110, 143, 993, 995])
            if dst_port == 25: 
                payload = f"EHLO client.domain.com\r\n"
            elif dst_port in [110, 995]:
                payload = f"USER user@domain.com\r\n"
            else:
                payload = f"A001 LOGIN user@domain.com password\r\n"
                
        elif traffic_type == "dns":
            dst_port = 53
            payload = f"Query: {random.choice(['google.com', 'microsoft.com', 'github.com', 'stackoverflow.com'])}"
            
        else:
            dst_port = random.choice([20, 21])
            if dst_port == 21:
                payload = f"LIST\r\n"
            else:
                payload = f"Data transfer: file_{random.randint(1, 100)}.txt"
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(pkt)
    
    return packets

def main():
    print_header()
    
    duration, min_packets, suspicious_count, total_count, attack_percentage, threat_level_name = get_user_config()
    
    print_section_header("Network Interface Selection")
    
    interface_name, target_ip = select_interface()
    if not target_ip:
        print(Fore.RED + "No valid interface selected. Exiting." + Style.RESET_ALL)
        return
    
    print()
    print(Fore.GREEN + "Interface Configuration:" + Style.RESET_ALL)
    interface_table = [
        ["Interface", interface_name],
        ["Target IP", target_ip],
        ["Attack Duration", f"{duration} seconds"],
        ["Min Packets/Attack", f"{min_packets:,}"],
        ["Suspicious IPs", suspicious_count],
        ["Total Source IPs", total_count]
    ]
    print(tabulate(interface_table, headers=["Setting", "Value"], tablefmt="grid"))
    print()    
    print(Fore.CYAN + "Generating IP pools..." + Style.RESET_ALL)
    suspicious_ips, normal_ips = generate_ip_pools(suspicious_count, total_count)
    print(Fore.GREEN + f"[OK] Generated {len(suspicious_ips)} suspicious IPs and {len(normal_ips)} normal IPs" + Style.RESET_ALL)
    
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    output_file = os.path.join(output_dir, f"{uuid.uuid4()}.pcap")
    
    attack_types = [
        ("DoS Hulk", generate_dos_hulk_packets),
        ("DoS GoldenEye", generate_dos_goldeneye_packets),
        ("FTP-Patator", generate_ftp_patator_packets),
        ("SSH-Patator", generate_ssh_patator_packets),
        ("DoS Slowloris", generate_dos_slowloris_packets),        
        ("DoS Slowhttptest", generate_dos_slowhttptest_packets),
        ("Bot", generate_bot_packets),
        ("Heartbleed", generate_heartbleed_packets)
    ]
    
    all_packets = []
    attack_packet_counts = {}
    packet_details = []
    
    print_section_header("Generating Attack Packets")
    
    total_estimated_packets = min_packets * len(attack_types)
    target_attack_packets = int(total_estimated_packets * (attack_percentage / 100.0))
    target_benign_packets = total_estimated_packets - target_attack_packets
    
    print(Fore.CYAN + f"Threat Level: {threat_level_name} ({attack_percentage}%)" + Style.RESET_ALL)
    print(Fore.CYAN + f"Target Distribution: {target_attack_packets:,} attack packets, {target_benign_packets:,} benign packets" + Style.RESET_ALL)
    print()
    
    attack_packets_per_type = target_attack_packets // len(attack_types)
    remaining_attack_packets = target_attack_packets % len(attack_types)
    
    for i, (attack_name, generator) in enumerate(attack_types):
        count = attack_packets_per_type
        if i < remaining_attack_packets:
            count += 1
            
        if count > 0:
            print(Fore.YELLOW + f"Generating {count:,} {attack_name} packets..." + Style.RESET_ALL)
            packets = generator(target_ip, count, suspicious_ips, normal_ips)
            
            attack_packet_counts[attack_name] = len(packets)
            
            for packet in packets:
                packet.time = time.time() + random.uniform(0, duration)
                
                packet_info = {
                    'packet_id': len(packet_details) + 1,
                    'attack_type': attack_name,
                    'timestamp': packet.time,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'src_port': packet[TCP].sport if TCP in packet else None,
                    'dst_port': packet[TCP].dport if TCP in packet else None,
                    'protocol': 'TCP' if TCP in packet else 'IP',
                    'packet_size': len(packet),
                    'is_suspicious_src': packet[IP].src in suspicious_ips,
                    'payload_size': len(packet[Raw].load) if Raw in packet else 0
                }
                packet_details.append(packet_info)
            
            all_packets.extend(packets)
            print(Fore.GREEN + f"[OK] Generated {len(packets):,} {attack_name} packets" + Style.RESET_ALL)
        else:
            print(Fore.GRAY + f"Skipping {attack_name} (threat level too low)" + Style.RESET_ALL)
            attack_packet_counts[attack_name] = 0
    
    if target_benign_packets > 0:
        print()
        print(Fore.YELLOW + f"Generating {target_benign_packets:,} benign traffic packets..." + Style.RESET_ALL)
        benign_packets = generate_benign_packets(target_ip, target_benign_packets, suspicious_ips, normal_ips)
        
        for packet in benign_packets:
            packet.time = time.time() + random.uniform(0, duration)
            
            packet_info = {
                'packet_id': len(packet_details) + 1,
                'attack_type': 'BENIGN',
                'timestamp': packet.time,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'src_port': packet[TCP].sport if TCP in packet else None,
                'dst_port': packet[TCP].dport if TCP in packet else None,
                'protocol': 'TCP' if TCP in packet else 'IP',
                'packet_size': len(packet),
                'is_suspicious_src': packet[IP].src in suspicious_ips,
                'payload_size': len(packet[Raw].load) if Raw in packet else 0
            }
            packet_details.append(packet_info)
        
        all_packets.extend(benign_packets)
        attack_packet_counts['BENIGN'] = len(benign_packets)
        print(Fore.GREEN + f"[OK] Generated {len(benign_packets):,} benign packets" + Style.RESET_ALL)

    all_packets.sort(key=lambda x: x.time)    
    print_section_header("Saving Results")
    print(Fore.CYAN + f"Saving to: {output_file}" + Style.RESET_ALL)

    wrpcap(output_file, all_packets)
    
    file_uuid = os.path.splitext(os.path.basename(output_file))[0]
    file_hash = calculate_file_hash(output_file)
    
    appdata_dir = get_intrusion_x_appdata_dir()
    
    csv_file = os.path.join(appdata_dir, f"{file_uuid}_packet_details.csv")
    packet_df = pd.DataFrame(packet_details)
    packet_df.to_csv(csv_file, index=False)
    
    comprehensive_metadata = {
        "uuid": file_uuid,
        "file_hash": file_hash,
        "generation_timestamp": time.time(),
        "pcap_file_path": output_file,
        "csv_file_path": csv_file,        "simulation_config": {
            "duration": duration,
            "min_packets": min_packets,
            "suspicious_count": suspicious_count,
            "total_count": total_count,
            "target_ip": target_ip,
            "interface": interface_name,
            "threat_level": threat_level_name,
            "attack_percentage": attack_percentage
        },
        "network_data": {
            "suspicious_ips": suspicious_ips,
            "normal_ips": normal_ips,
            "total_packets": len(all_packets),
            "attack_types": [name for name, _ in attack_types]
        },
        "attack_statistics": {
            "attack_packet_counts": attack_packet_counts,
            "attack_percentages": {
                attack: (count / len(all_packets)) * 100 
                for attack, count in attack_packet_counts.items()
            }
        },
        "packet_summary": {
            "total_packets": len(all_packets),
            "csv_records": len(packet_details),
            "unique_src_ips": len(set(detail['src_ip'] for detail in packet_details)),
            "suspicious_packet_count": sum(1 for detail in packet_details if detail['is_suspicious_src']),
            "normal_packet_count": sum(1 for detail in packet_details if not detail['is_suspicious_src'])
        }
    }

    json_file = os.path.join(appdata_dir, f"{file_uuid}_metadata.json")
    with open(json_file, 'w') as f:
        json.dump(comprehensive_metadata, f, indent=2)
    
    store_simulation_metadata(file_uuid, comprehensive_metadata)
    
    print(Fore.GREEN + f"[OK] PCAP file generated: {output_file}" + Style.RESET_ALL)
    print(Fore.GREEN + f"[OK] Total packets: {len(all_packets)}" + Style.RESET_ALL)
    
    ip_stats = {} 
    for packet in all_packets:
        src_ip = packet[IP].src
        ip_stats[src_ip] = ip_stats.get(src_ip, 0) + 1
    
    suspicious_packets = sum(count for ip, count in ip_stats.items() if ip in suspicious_ips)
    normal_packets = len(all_packets) - suspicious_packets
    print_section_header("Simulation Results")
    
    results_table = [
        ["Total Packets Generated", f"{len(all_packets):,}"],
        ["PCAP File", output_file],
        ["Duration", f"{duration} seconds"],
        ["Suspicious IPs", f"{len(suspicious_ips)}"],
        ["Normal IPs", f"{len(normal_ips)}"],
        ["Packets from Suspicious IPs", f"{suspicious_packets:,} ({suspicious_packets/len(all_packets)*100:.1f}%)"],
        ["Packets from Normal IPs", f"{normal_packets:,} ({normal_packets/len(all_packets)*100:.1f}%)"]
    ]
    print(tabulate(results_table, headers=["Metric", "Value"], tablefmt="grid"))
    
    print_section_header("Attack Type Distribution")
    
    attack_distribution_table = []
    for attack_type, count in attack_packet_counts.items():
        percentage = (count / len(all_packets)) * 100
        attack_distribution_table.append([attack_type, f"{count:,}", f"{percentage:.1f}%"])
    
    print(tabulate(attack_distribution_table, headers=["Attack Type", "Packet Count", "% of Total"], tablefmt="grid"))
    
    print_section_header("Top 15 Most Active Source IPs")
    
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:15]
    ip_table = []
    for i, (ip, count) in enumerate(sorted_ips, 1):
        status = "[SUSPICIOUS]" if ip in suspicious_ips else "[NORMAL]"
        percentage = f"{count/len(all_packets)*100:.1f}%"
        ip_table.append([i, ip, f"{count:,}", percentage, status])
    
    print(tabulate(ip_table, headers=["Rank", "IP Address", "Packets", "% of Total", "Status"], tablefmt="grid"))
    print_section_header("Suspicious IP List")  
    suspicious_table = [[i+1, ip] for i, ip in enumerate(suspicious_ips)]
    print(tabulate(suspicious_table, headers=["#", "Suspicious IP"], tablefmt="grid"))
    
    print()
    print(Fore.GREEN + Style.BRIGHT + "*** Network Traffic Simulation Complete! ***" + Style.RESET_ALL)
    print(Fore.CYAN + f"PCAP file saved to: {output_file}" + Style.RESET_ALL)
    print(Fore.YELLOW + "This file can now be used to test IDS frameworks!" + Style.RESET_ALL)
    print()

if __name__ == "__main__":
    main()