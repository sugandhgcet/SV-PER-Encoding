# SV-PER-Simulator: IEC 61850-9-2 Sampled Values Compression

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.4.5-green.svg)](https://scapy.net/)

## Overview

**SV-PER-Simulator** is a Python-based research tool developed to demonstrate and analyze the compression of IEC 61850-9-2 Sampled Values (SV) traffic using **Packed Encoding Rules (PER)**.

Standard SV communication relies on ASN.1 Basic Encoding Rules (BER), which adds significant overhead via Tag-Length-Value (TLV) triplets. This simulator implements a custom PER-based encoding scheme to strip redundant headers, demonstrating potential bandwidth savings and latency reduction in Digital Substation networks.

### Key Features
* **Dual-Mode Generation:** Generate standard **BER-encoded** (ISO/IEC 8825-1) and compressed **PER-encoded** (ISO/IEC 8825-2) SV frames.
* **Scapy Integration:** Uses custom Scapy layers for packet manipulation and raw socket injection.
* **Compression Analysis:** Tools to calculate compression ratios and throughput savings.
* **PCAP Replay:** Ability to read standard SV `.pcap` files and re-transmit them as compressed PER streams.

## Theoretical Background

In legacy IEC 61850-9-2 LE (Light Edition), the Application Protocol Data Unit (APDU) is BER encoded.
* **BER (Basic Encoding Rules):** Self-describing format. Every field requires `Tag | Length | Value`.
* **PER (Packed Encoding Rules):** Relies on a pre-shared schema. Removes Tags and Lengths for known constraints.

This tool targets fixed-length fields (e.g., `smpCnt`, `confRev`) and removes their overhead to minimize frame size.

## Installation

### Prerequisites
* Python 3.8 or higher
* libpcap (for Scapy functionality)
* Root/Administrator privileges (required for sending raw Ethernet frames)

### Setup
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/SV-PER-Simulator.git](https://github.com/your-username/SV-PER-Simulator.git)
    cd SV-PER-Simulator
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### 1. Packet Generation
Run the generator script to start multicasting SV packets. You must specify the network interface.

**Generate Standard SV (BER):**
```bash
sudo python3 sv_gen.py --interface eth0 --mode ber --rate 4000
