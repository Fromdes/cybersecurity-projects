# Kali Linux Setup Guide

Everything you need to run any project in this portfolio on a fresh Kali Linux installation.

---

## 1. System Update

```bash
sudo apt update && sudo apt full-upgrade -y
```

---

## 2. Python 3.11+

Kali ships with Python 3.11+. Verify:

```bash
python3 --version   # should be 3.11.x or higher
```

If not:

```bash
sudo apt install -y python3.11 python3.11-venv python3.11-dev
```

---

## 3. System-Level Dependencies

Some projects require C libraries:

```bash
sudo apt install -y \
    libssl-dev libffi-dev \
    libpcap-dev \
    libmagic1 \
    yara \
    tshark \
    tcpdump \
    nmap \
    auditd \
    inotify-tools \
    git curl wget
```

---

## 4. Clone and Install Dev Tools

```bash
git clone https://github.com/YOUR_USERNAME/cybersecurity-projects.git
cd cybersecurity-projects

# Create a global dev virtualenv (optional but recommended)
python3 -m venv .venv-dev
source .venv-dev/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
```

---

## 5. Running a Specific Project

Each project is self-contained. Example for project 08 (AES-256-GCM Encryptor):

```bash
cd 01-beginner/08-aes256-gcm-encryptor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m src.project_08 --help
```

---

## 6. Privileges

Some projects need elevated privileges:

| Capability | Needed by | How |
|-----------|-----------|-----|
| Raw packet capture | 58-pcap-analyzer, 69-wifi-deauth-detector, 70-arp-spoofing-detector | `sudo python -m ...` or set capabilities |
| auditd access | 61-auditd-log-parser | `sudo` or `adm` group |
| inotify limits | 78-real-time-fim | May need to raise `fs.inotify.max_user_watches` |
| Port < 1024 | 63-ssh-honeypot, 64-http-honeypot | `sudo` or `CAP_NET_BIND_SERVICE` |

To raise inotify watches:

```bash
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

To grant raw packet access without sudo:

```bash
sudo setcap cap_net_raw+eip $(which python3)
```

---

## 7. Running Quality Checks

From the repo root:

```bash
make lint      # ruff + mypy
make test      # pytest --cov
make security  # bandit
make all       # everything
```

---

## 8. Troubleshooting

**`scapy` requires root for raw sockets** — run with `sudo` or use packet capture files.

**`yara-python` build fails** — install `libyara-dev`: `sudo apt install libyara-dev`

**`pefile` / `oletools` on large samples** — process files in a VM snapshot; never run untrusted executables directly.

**`volatility3` profile not found** — download the appropriate symbol table from the Volatility Foundation GitHub.
