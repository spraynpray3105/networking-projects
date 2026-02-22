# networking-projects

A collection of networking-related projects for learning, experimentation, and practical use. This repository is intended to help explore core networking concepts, tools, and utilities through hands-on Python programming.

## Projects

### SniffThis (`main.py`)

**SniffThis** is a simple, yet powerful, network packet sniffer implemented in Python. It allows you to capture, analyze, and display network packets traversing your system's interfaces. You can use SniffThis to understand traffic patterns, debug networking issues, or for educational purposes in learning about raw socket programming and network protocols.

#### Features

- Capture live network packets from a chosen interface
- Display protocol headers and payload information
- Basic filtering capability (e.g., filter by protocol or port)
- Lightweight, easy to run and customize

#### Usage

1. Clone the repository:
   ```sh
   git clone https://github.com/spraynpray3105/networking-projects.git
   cd networking-projects
   ```

2. Run `main.py` (ensure you have Python 3 installed):
   ```sh
   python3 main.py
   ```

   *You may need administrative privileges to capture raw packets (e.g., use `sudo`).*

3. Follow any on-screen instructions to start sniffing traffic.

#### Notes

- **For educational and authorized use only.** Please ensure you have permission to monitor network traffic on the network you are using.
- The script is intended for learning and personal use — not for malicious purposes.

---

## License

Distributed under the GNU 3.0 License. See [LICENSE](LICENSE) for more information.

## Contributing

Contributions, suggestions, and ideas are welcome! Please open an issue or submit a pull request.

```
