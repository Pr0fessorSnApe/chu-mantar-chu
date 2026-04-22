# Chu-Mantar-Chu: High-Performance WPA2/WPA3 Security Auditor

**Chu-Mantar-Chu** is a high-performance, automated Bash-based security auditing tool designed for rapid WPA2/WPA3 password recovery. By integrating industry-standard tools like **Aircrack-ng**, **John the Ripper (Jumbo)**, and **Hashcat**, it streamlines the process of handshake capture and multi-stage cracking using both GPU and CPU acceleration.

---

## 🚀 Key Features

*   **Automated Workflow:** From monitor mode setup to final password recovery, the entire process is automated for maximum efficiency.
*   **Multi-Engine Cracking:** Utilizes **Hashcat** for GPU-accelerated attacks and **John the Ripper** for sophisticated rule-based CPU attacks.
*   **Intelligent Dependency Management:** Automatically detects and installs missing dependencies (Aircrack-ng, Hashcat, John, hcxtools).
*   **High-Speed Handshake Capture:** Employs optimized deauthentication floods to ensure rapid 4-way handshake acquisition.
*   **Format Versatility:** Automatically converts captures into `.hccapx` and `.hc22000` formats for compatibility with modern cracking engines.

---

## 📋 Prerequisites

The script is designed for **Linux-based systems** (optimized for Kali Linux, Parrot OS, or Ubuntu).

*   **Root Privileges:** Required for wireless interface manipulation.
*   **Wireless Interface:** A network card supporting **Monitor Mode** and **Packet Injection**.
*   **Hardware Acceleration:** NVIDIA/AMD GPU recommended for maximum cracking speed.

---

## 🛠️ Installation & Usage

### 1. Clone and Prepare
```bash
git clone https://github.com/your-repo/chu-mantar-chu.git
cd chu-mantar-chu
chmod +x chu-mantar-chu.sh
```

### 2. Execute the Auditor
Run the script with sudo privileges:
```bash
sudo ./chu-mantar-chu.sh
```

### 3. Follow the Prompts
*   Select your wireless interface (default: `wlan0`).
*   Specify a wordlist path (default: `/usr/share/wordlists/rockyou.txt`).
*   Select the target network from the automated scan results.

---

## ⚙️ Technical Architecture

| Phase | Description | Tooling |
| :--- | :--- | :--- |
| **Reconnaissance** | Automated network scanning and target identification. | `airodump-ng` |
| **Acquisition** | Targeted deauthentication and handshake capture. | `aireplay-ng`, `airodump-ng` |
| **Processing** | Cleaning and converting captures to hash formats. | `wpaclean`, `hcxpcapngtool` |
| **Recovery (GPU)** | High-speed dictionary attack (Phase 1). | `hashcat` |
| **Recovery (CPU)** | Rule-based and fork-optimized attacks (Phase 2 & 3). | `john` |

---

## ⚖️ Legal Disclaimer

**For educational and authorized security testing purposes only.** 

The use of this tool against networks without explicit permission is illegal. The developers assume no liability for misuse or damage caused by this program. Users are responsible for complying with all local, state, and federal laws regarding cybersecurity and privacy.

---

*“Kaam krda pata lgda aye!”* — **Experience the speed of automated security auditing.**
