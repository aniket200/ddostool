# 🛡️ DoS Attack Protection Tool

A Python-based tool to **detect and mitigate Denial of Service (DoS) attacks** in real time using packet sniffing and rate-limiting techniques.

---

## 🚀 Description

This project monitors network traffic and detects malicious patterns by analyzing incoming packets. It identifies and temporarily blocks IP addresses that exceed a defined request threshold within a specific time window.

---

## 🛠️ Technologies Used

- **Python 3.6+**
- **Scapy** - for packet sniffing and network analysis
- **VS Code / Any IDE**

---

## 📦 Installation

### 1. ✅ Install Python

Download and install Python from the official site:  
🔗 [https://www.python.org/downloads](https://www.python.org/downloads)

Make sure to check the box **"Add Python to PATH"** during installation.

---

### 2. ✅ Install Required Python Libraries

Open your terminal (in VS Code or command prompt) and run:

```bash
pip install scapy

git clone https://github.com/aniket200/ddostool.git
cd ddostool

python ddos.py
