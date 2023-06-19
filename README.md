# Yet Another DNS Exfiltration

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/release/python-382/)

Welcome to the "Yet Another DNS Exfiltration" repository! :smiley:
<p align="center">
  <img src="https://github.com/aherd2985/yade/raw/main/yade.png" alt="Yet Another DNS Exfiltration" width="400">
</p>

# About

Are you tired of ordinary data exfiltration methods? Looking to add a touch of intrigue and sophistication to your hacking adventures? Look no further! "Yet Another DNS Exfiltration" is here to fulfill all your clandestine communication needs.

This Python script automates data exfiltration through DNS requests. Harnessing the covert powers of the Domain Name System, you can now secretly transfer sensitive information without raising any eyebrows. Shhh, don't tell anyone!

# Features

+ Seamless data exfiltration using DNS requests :skull:
+ Customizable domain name for extra stealth :sunglasses:
+ Customizable DNS resolver for extra stealth :japanese_ogre:
+ Customizable DNS request types for extra stealth :suspect:
+ Random DNS request type mode for extra stealth :see_no_evil:
+ Easy to customize encoding for extra stealth :eyes:
+ Simple and intuitive command-line interface (because hackers need user-friendly tools too) 🖥️

# Prerequisites

+ Python 3.8 or above
+ A sneaky mind and mischievous intentions 😉

# Installation

Clone the repository:

    git clone https://github.com/aherd2985/yade.git

Navigate to the project directory:

    cd yade

# Usage

Run the script:

    python3 yade.py

Run a tool to capture the DNS requests on the targeted server. Any tool for packet captures will work, such as tcpdump, WireShark, tshark, or NetworkMiner.

    # -i == Interface switch
    # port == Filter packets by port selection
    # -w == Write packet captures to file
    sudo tcpdump -i any port 53 -w test.pcap

Sit back, relax, and watch your data gracefully slip away through the DNS requests. Goodbye, secrets! 👋

# Disclaimer

# ⚠️ Warning
This repository is for educational and entertainment purposes only. Misuse of the code or engaging in illegal activities is strictly discouraged. The author and contributors are not liable for any misuse or damage caused by this project. Use it responsibly and ethically.

# Contribution

If you stumble upon any bugs or have suggestions for improvement, we would love to hear from you! Feel free to open an issue or submit a pull request. Let's make this sneaky tool even better together.

Ideas:
+ Add packet number and verify data packets
+ Add file name for multi-file
+ Add multiple "labels" of 63 characters or less of Subdomains to add more data in requests and limit calls 

# Acknowledgments

Special thanks to PacketWhisper! I shamelessly stole code from there

    https://github.com/TryCatchHCF/PacketWhisper
  
