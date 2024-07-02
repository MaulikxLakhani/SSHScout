import csv
import socket
import argparse
import threading
from tabulate import tabulate

# Comprehensive CVE dictionary for OpenSSH
CVE_DICT = {
    "OpenSSH_3.9p1": ["CVE-2006-4924"],
    "OpenSSH_4.2p1": ["CVE-2006-4924"],
    "OpenSSH_4.3p2": ["CVE-2006-5229"],
    "OpenSSH_5.1p1": ["CVE-2008-4109"],
    "OpenSSH_5.2p1": ["CVE-2010-4478"],
    "OpenSSH_5.3p1": ["CVE-2010-4478"],
    "OpenSSH_5.6p1": ["CVE-2010-4755"],
    "OpenSSH_5.8p1": ["CVE-2011-5000"],
    "OpenSSH_6.2p2": ["CVE-2013-4548"],
    "OpenSSH_6.6.1": ["CVE-2014-2532"],
    "OpenSSH_6.7p1": ["CVE-2014-1692"],
    "OpenSSH_6.9p1": ["CVE-2015-6563", "CVE-2015-6564"],
    "OpenSSH_7.1p2": ["CVE-2015-8325"],
    "OpenSSH_7.2p2": ["CVE-2016-0777", "CVE-2016-0778"],
    "OpenSSH_7.3p1": ["CVE-2016-6210"],
    "OpenSSH_7.4": ["CVE-2016-8858", "CVE-2017-15906"],
    "OpenSSH_7.5": ["CVE-2017-15906"],
    "OpenSSH_7.6": ["CVE-2018-15473"],
    "OpenSSH_7.7": ["CVE-2018-15473"],
    "OpenSSH_7.9": ["CVE-2018-20685"],
    "OpenSSH_8.0": ["CVE-2019-6111", "CVE-2020-14145"],
    "OpenSSH_8.1": ["CVE-2019-6111", "CVE-2020-14145"],
    "OpenSSH_8.2": ["CVE-2020-14145"],
    "OpenSSH_8.3": ["CVE-2020-15778"],
    "OpenSSH_8.4": ["CVE-2020-15778"],
    "OpenSSH_8.5": ["CVE-2021-28041", "CVE-2024-6387"],
    "OpenSSH_8.6": ["CVE-2021-28041", "CVE-2024-6387"],
    "OpenSSH_8.7": ["CVE-2021-41617", "CVE-2024-6387"],
    "OpenSSH_8.8": ["CVE-2021-41617", "CVE-2024-6387"],
    "OpenSSH_8.9": ["CVE-2022-2068", "CVE-2024-6387"],
    "OpenSSH_9.0": ["CVE-2022-2068", "CVE-2024-6387"],
    "OpenSSH_9.1": ["CVE-2023-28531", "CVE-2024-6387"],
    "OpenSSH_9.2": ["CVE-2023-28531", "CVE-2024-6387"],
}


def is_valid_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def get_ssh_banner(ip, port=22, timeout=5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception as e:
        return str(e)


def check_cve(banner):
    for key in CVE_DICT:
        if key in banner:
            return ", ".join(CVE_DICT[key])
    return "No known CVEs"


def process_host(host, results):
    if is_valid_domain(host) or is_valid_ip(host):
        banner = get_ssh_banner(host)
        cve = check_cve(banner)
        results.append([host, banner, cve])
    else:
        results.append([host, "Invalid domain or IP address", "N/A"])


def main():
    parser = argparse.ArgumentParser(description="SSH Banner Grabber with CVE Checking")
    parser.add_argument('hosts', metavar='H', type=str, nargs='+',
                        help='List of domain names or IP addresses')
    args = parser.parse_args()

    results = []
    threads = []

    for host in args.hosts:
        thread = threading.Thread(target=process_host, args=(host, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Print results using tabulate with "grid" format
    print(tabulate(results, headers=["Domain/IP", "SSH Banner", "CVE"], tablefmt="pretty"))

    # Write results to result.csv
    with open('result.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Domain/IP", "SSH Banner", "CVE"])
        writer.writerows(results)


if __name__ == "__main__":
    main()
