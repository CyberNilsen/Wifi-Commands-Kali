# CyberNilsen's WiFi Penetration Testing Toolkit

An advanced command-line utility built in Python that simplifies WiFi penetration testing operations in Kali Linux.

> ⚠️ This tool is for **educational purposes** and **authorized penetration testing** only.

**WiFi adapter used:** `AWUS036ACH` — supports monitor mode and packet injection.

![Wifi Toolkit](https://github.com/user-attachments/assets/a056ea41-fb93-4da9-a8f1-b308a4be3c61)


---

## 🚀 Features

- 📶 **Interface Management** — Easily switch between monitor and managed modes
- 🔍 **Network Discovery** — Scan and identify nearby wireless networks with details
- 📦 **Packet Capture** — Monitor and analyze wireless traffic
- 🔐 **WPA Handshake** — Capture and crack WPA/WPA2 handshakes
- 📡 **Deauthentication** — Send deauth packets to target devices
- 🔑 **WPS Testing** — Check for WPS vulnerabilities and perform PIN attacks
- 📱 **Evil Twin** — Create rogue access points for security testing
- 🕵️ **Packet Sniffing** — Analyze network traffic for credentials and data
- 💻 **User-Friendly CLI** — Simple, intuitive command interface

---

## 📋 Requirements

- Kali Linux (or similar penetration testing distribution)
- Root privileges
- Python 3.x
- Wireless adapter supporting monitor mode (e.g., `AWUS036ACH`)
- Required dependencies:
  - terminaltables

---

## 📦 Installation

### Install from GitHub

```bash
git clone https://github.com/CyberNilsen/Wifi-Commands-Kali.git
cd Wifi-Commands-Kali
```

### Make the script executable

```bash
chmod +x Wifi-Commands-Kali.py
```

---

### 💻 Usage

Run the tool with root privileges:  

```bash
sudo ./Wifi-Commands-Kali.py
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

> Developed with curiosity and passion by Andreas ([CyberNilsen](https://github.com/CyberNilsen))
