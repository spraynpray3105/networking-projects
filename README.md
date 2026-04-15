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

### Security Dashboard Builder (`dashboard_builder/`)

A drag-and-drop web app that helps users design a customizable security dashboard quickly, then export configuration and a deployment bundle for local infrastructure.

#### Highlights

- Drag/drop dashboard widgets and reorder them visually
- Widget-level configuration via GUI
- Connection management via GUI (SIEM/API/Database/Webhook)
- Import/export full configuration as JSON
- Download a deployment bundle with `docker-compose.yml`
- Theme picker (Red/Black, Midnight Blue, Matrix Green, Clean Light)

#### Quick start

```sh
cd dashboard_builder
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8000`.

---

## License

Distributed under the GNU 3.0 License. See [LICENSE](LICENSE) for more information.

## Contributing

Contributions, suggestions, and ideas are welcome! Please open an issue or submit a pull request.

```
