# 🔥 Firewall Project

A basic firewall implementation built with Python that demonstrates packet filtering based on custom rules. This project is educational and designed to help understand how firewalls work at a fundamental level.

## 📌 Features

- Packet capturing and inspection
- Custom filtering rules (e.g., IP, port, protocol)
- Logging of dropped/allowed packets
- Command-line interface for interaction
- Extendable and modular Python code

## 🧰 Technologies Used

- Python 3
- `scapy` for packet sniffing and manipulation
- `argparse` for CLI support
- `logging` for activity tracking

## 🚀 Getting Started

### Prerequisites

- Python 3.7+
- Admin/root privileges to sniff network packets
- Install dependencies:

```bash
pip install -r requirements.txt
```

### Run the Firewall

```bash
sudo python firewall.py
```

Use `--help` to see available options:

```bash
python firewall.py --help
```

## ⚙️ Example Usage

```bash
sudo python firewall.py --block-ip 192.168.0.100 --log blocked_packets.log
```

## 📝 Rules Engine

The firewall allows blocking based on:

- Specific IP addresses
- Port numbers
- Protocol types (TCP, UDP, ICMP)

You can define your rules in a configuration file or directly via command-line arguments (based on the implementation).

## 📂 Project Structure

```
firewall-project/
├── firewall.py           # Main firewall logic
├── rules.py              # Rule engine (if applicable)
├── utils.py              # Helper functions
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

## 🛡️ Disclaimer

This firewall is meant for **educational purposes only**. It is not production-ready and should not be used as a primary firewall in secure environments.

## 🙋‍♂️ Author

**Allampati Venkata Surendra Reddy**  
[GitHub Profile](https://github.com/suri9515)

---

Feel free to ⭐ this repo if you find it useful!

