#!/usr/bin/env python3

import sys
import time
import subprocess

def main():
    display_banner()
    time.sleep(1)
    print("Type 'help' for a list of commands or 'exit' to quit")
    
    while True:
        command = input("\n> ").strip().lower()
        
        if command == "exit":
            print("Exiting application...")
            break
        elif command == "help":
            display_help()
        elif command == "scan":
            wifi_scan()
        elif command == "monitor":
            wifi_monitor_mode()
        elif command == "capture":
            start_wifi_capture()
        elif command == "interfaces":
            show_interfaces()
        elif command == "deauth":
            run_deauth()
        else:
            print(f"Command '{command}' not implemented yet")

def display_banner():
    print(r"""
 _____       _                _   _ _ _                   
/  __ \     | |              | \ | (_) |                  
| /  \/_   _| |__   ___ _ __ |  \| |_| |___  ___ _ __     
| |   | | | | '_ \ / _ \ '__|| . ` | | / __|/ _ \ '_ \    
| \__/\ |_| | |_) |  __/ |   | |\  | | \__ \  __/ | | |   
 \____/\__, |_.__/ \___|_|   \_| \_/_|_|___/\___|_| |_|   
        __/ |                                             
       |___/                                              
 _    _ _  __ _   _____                                          _     
| |  | (_)/ _(_) /  __ \                                        | |    
| |  | |_| |_ _  | /  \/ ___  _ __ ___  _ __ ___   __ _ _ __   __| |___ 
| |/\| | |  _| | | |    / _ \| '_ ` _ \| '_ ` _ \ / _` | '_ \ / _` / __|
\  /\  / | | | | | \__/\ (_) | | | | | | | | | | | (_| | | | | (_| \__ \
 \/  \/|_|_| |_|  \____/\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|\__,_|___/
                                                                    
    """)
    time.sleep(1)
    print("CyberNilsen's Application for WiFi Kali Commands")
    print("===============================================")

def display_help():
    print("\nAvailable commands:")
    print("  help      - Display this help message")
    print("  scan      - Scan for wireless networks")
    print("  monitor   - Put wireless interface in monitor mode")
    print("  capture   - Capture wireless packets")
    print("  interfaces- Show wireless interfaces")
    print("  deauth    - Send deauthentication packets")
    print("  exit      - Exit the application")

def wifi_scan():
    print("\nScanning for wireless networks...")
    print("Command: iwlist wlan0 scan")
    
    try:
         subprocess.run(["sudo", "iwlist", "wlan0", "scan"], check=True)
    except subprocess.CalledProcessError:
         print("Error running scan command. Make sure you have the right permissions.")
    print("Scan complete!")

def wifi_monitor_mode():
    print("\nPutting wireless interface in monitor mode...")
    print("Command: airmon-ng start wlan0")
    try:
         subprocess.run(["sudo", "airmon-ng", "start", "wlan0"], check=True)
    except subprocess.CalledProcessError:
         print("Error setting monitor mode. Check your interface name and permissions.")
    print("Monitor mode enabled!")

def start_wifi_capture():
    print("\nStarting wireless packet capture...")
    print("Command: airodump-ng wlan0mon")
    try:
         subprocess.run(["sudo", "airodump-ng", "wlan0mon"], check=True)
    except subprocess.CalledProcessError:
         print("Error starting capture. Make sure interface is in monitor mode.")
    print("Packet capture started!")

def show_interfaces():
    print("\nShowing wireless interfaces...")
    print("Command: iwconfig")
    
    try:
        subprocess.run(["iwconfig"], check=True)
    except subprocess.CalledProcessError:
       print("Error fetching wireless interfaces.")
    print("Interfaces listed!")

def run_deauth():
    print("\nSending deauthentication packets...")
    print("Command: aireplay-ng --deauth 0 -a [AP MAC] wlan0mon")
    ap_mac = input("Enter AP MAC address: ")
    try:
         subprocess.run(["sudo", "aireplay-ng", "--deauth", "0", "-a", ap_mac, "wlan0mon"], check=True)
    except subprocess.CalledProcessError:
         print("Error sending deauth packets.")
    print("Deauth attack launched!")

if __name__ == "__main__":
    main()