import sys
import time

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
    print("  help  - Display this help message")
    print("  exit  - Exit the application")

if __name__ == "__main__":
    main()