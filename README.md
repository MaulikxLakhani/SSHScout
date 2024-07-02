# SSHScout - SSH Banner Grabber

## 📜 Description

SSHScout is a lightweight, efficient tool designed to identify servers running SSH. Designed to be your go-to tool for SSH banner grabbing, combining speed, accuracy, and ease of use. This script facilitates rapid scanning of multiple IP addresses, domain names, and CIDR network ranges to detect SSH server version and banner. Whether you're managing a large network or conducting a targeted security audit, SSHPeek provides the critical information you need to keep your systems secure and up-to-date.

## 🌟 Features

- **Rapid Scanning**: Quickly scan multiple IP addresses, domain names, and CIDR ranges for the CVE-2024-6387 vulnerability.
- **Banner Retrieval**: Efficiently retrieves SSH banners without authentication.
- **Multi-threading**: Uses threading for concurrent checks, significantly reducing scan times.
- **Detailed Output**: Provides clear, emoji-coded output summarizing scan results.
- **Port Check**: Identifies closed ports and provides a summary of non-responsive hosts.

## 🚀 Usage

```bash
python SSHScout.py <targets> [--port PORT]
```

### Examples

#### Single IP

```bash
python SSHScout.py 192.168.1.1
```

#### Multiple IPs and Domains

```bash
python SSHScout.py 192.168.1.1 example.com 192.168.1.2
```

#### CIDR Range

```bash
python SSHScout.py 192.168.1.0/24
```

#### With Custom Port

```bash
python SSHScout.py 192.168.1.1 example.com --port 2222
```

### Output

The script will provide a summary of the scanned targets:

* 🚨 Vulnerable: Servers running a vulnerable version of OpenSSH.
* 🛡️ Not Vulnerable: Servers running a non-vulnerable version of OpenSSH.
* 🔒 Closed Ports: Count of servers with port 22 (or specified port) closed.
* 📊 Total Scanned: Total number of targets scanned.

```text
🛡️ Servers not vulnerable: 1

   [+] Server at 157.90.125.31 (running SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11)

🚨 Servers likely vulnerable: 2

   [+] Server at 4.231.170.121 (running SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10)
   [+] Server at 4.231.170.122 (running SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2)

🔒 Servers with port 22 closed: 254

📊 Total scanned targets: 257
```

## 📚 References
[Qualys Blog on regreSSHion Vulnerability](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server)
