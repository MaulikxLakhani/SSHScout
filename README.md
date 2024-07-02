# SSHScout - SSH Banner Grab and Vulnerability Check

## 📜 Description

SSHScout is a lightweight, efficient tool designed to identify servers running SSH. Designed to be your go-to tool for SSH banner grabbing, combining speed, accuracy, and ease of use. This script facilitates rapid scanning of multiple IP addresses, domain names, and CIDR network ranges to detect SSH server version and banner. Whether you're managing a large network or conducting a targeted security audit, SSHScout provides the critical information you need to keep your systems secure and up-to-date.

## 🌟 Features

- **Port Check**: Identifies closed ports and provides a summary of non-responsive hosts.
- **Banner Retrieval**: Efficiently retrieves SSH banners without authentication.
- **Vulnerability Check**: Scan multiple IP addresses, domain names for the CVE-2024-6387 and other vulnerabilities.
- **Multi-threading**: Uses threading for concurrent checks, significantly reducing scan times.
- **Detailed Output**: Provides clear output summarizing scan results.

## 🚀 Usage

```bash
python SSHScout.py <targets>
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

### Output

The script will provide a summary of the scanned targets:

* 🚨 Vulnerable: Servers running a vulnerable version of OpenSSH.
* 🛡️ Not Vulnerable: Servers running a non-vulnerable version of OpenSSH.
* 🔒 Closed Ports: Count of servers with port 22 closed.

## 📚 References
[Qualys Blog on regreSSHion Vulnerability](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server)
