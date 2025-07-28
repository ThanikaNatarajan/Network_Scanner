# Network Scanner

A simple command-line tool for network scanning using ARP requests and TCP SYN (port) scans, built with Python and [Scapy](https://scapy.net/).

## Features

- **ARP Scan:** Discover live hosts on your local network using ARP requests.
- **TCP SYN Scan:** Scan specified ports or a range of ports on a target host using SYN packets to detect open TCP ports.

## Requirements

- Python 3.6 or higher
- [Scapy](https://pypi.org/project/scapy/)

## Installation

1. **Install Python:**  
   Download and install the latest version of Python from [python.org](https://www.python.org/downloads/).

2. **Install Scapy:**  
   Open your terminal or command prompt and run:
   ```sh
   python -m pip install scapy
   ```

## Usage

Run the script from your terminal:

```sh
python network_scanner.py <COMMAND> [options]
```

### ARP Scan

Scan an IP address or a range of IPs on your local network using ARP:

```sh
python network_scanner.py ARP <IP or CIDR>
```

**Examples:**
```sh
python network_scanner.py ARP 192.168.1.1
python network_scanner.py ARP 192.168.1.1/24
```

### TCP SYN Scan

Scan one or more specific ports on a target host:

```sh
python network_scanner.py TCP <IP or HOSTNAME> <PORTS...>
```

**Example:**
```sh
python network_scanner.py TCP 192.168.1.10 22 80 443
```

Scan a range of ports using the `--range` option:

```sh
python network_scanner.py TCP <IP or HOSTNAME> <LOW_PORT> <HIGH_PORT> --range
```

**Example:**
```sh
python network_scanner.py TCP 192.168.1.10 20 25 --range
```

## Output

- **ARP Scan:**  
  Prints each discovered device as `<IP> ==> <MAC>`.

- **TCP SYN Scan:**  
  Prints each open port as `Port <PORT> is open.`

## Example

```sh
python network_scanner.py ARP 192.168.1.1/24
# Output:
# 192.168.1.1 ==> aa:bb:cc:dd:ee:ff
# 192.168.1.2 ==> ff:ee:dd:cc:bb:aa

python network_scanner.py TCP 192.168.1.10 22 80
# Output:
# Port 22 is open.
# Port 80 is open.
```

## Notes

- **Run as Administrator or with sudo:**  
  Scapy requires elevated privileges for sending raw packets. On Windows, run your terminal as Administrator. On Linux/macOS, use `sudo`.
- **For educational and authorized use only.**

## License

MIT License

---

**Author:** ThanikaNatarajan