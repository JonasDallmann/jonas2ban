import os

def clear():
    subprocess.run("clear")


def check_and_install_dependencies():
    try:
        import colorama
    except ImportError:
        print(f"[ERROR] colorama module not found. Installing...")
        subprocess.run("pip install colorama", shell=True)
    try:
        import requests
    except ImportError:
        print(f"[ERROR] requests module not found. Installing...")
        subprocess.run("pip install requests", shell=True)
        import requests
    try:
        import subprocess
    except ImportError:
        print(f"[ERROR] subprocess module not found. Installing...")
        subprocess.run("pip install subprocess", shell=True)


def check_and_install_iptables():
    try:
        subprocess.run(["iptables", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} iptables not found. Installing...")
        install_iptables()
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error checking for iptables: {e}")
        install_iptables()

def create_and_enable_systemd_service():
    service_path = "/etc/systemd/system/jonas2ban.service"
    script_path = "/opt/jonas2ban/main.py"
    working_directory = "/opt/jonas2ban"

    if subprocess.run(["systemctl", "is-enabled", "jonas2ban"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
        return

    service_content = f"""
[Unit]
Description=Jonas2Ban Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 {script_path}
Restart=always
User=root
Group=root
WorkingDirectory={working_directory}

[Install]
WantedBy=multi-user.target
    """
    try:
        with open(service_path, "w") as service_file:
            service_file.write(service_content)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "jonas2ban"], check=True)
        subprocess.run(["systemctl", "start", "jonas2ban"], check=True)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error creating systemd service: {e}")


def get_formatted_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_own_hostname():
    return subprocess.run("hostname", shell=True, stdout=subprocess.PIPE).stdout.decode().strip()

def get_own_ip():
    return subprocess.run("hostname -I", shell=True, stdout=subprocess.PIPE).stdout.decode().strip()

def install_iptables():
    try: 
        subprocess.run("apt update && apt upgrade -y", shell=True)
        subprocess.run("apt-get install iptables", shell=True)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} IPTABLES installed")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to install IPTABLES: {e}")
        exit(1)

def check_and_install_rsyslog():
    try:
        subprocess.run(["rsyslogd", "-v"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} ryslog not found. Installing...")
        install_rsyslog()
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error checking for rsyslog: {e}")
        install_rsyslog()

def install_rsyslog():
    try:
        subprocess.run("apt update && apt install -y rsyslog", shell=True, check=True)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} rsyslog successfully installed")
        time.sleep(10)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error installing rsyslog: {e}")
        exit(1)


def monitor_logs():
    with open(CONFIG["log_file"], "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            process_line(line)

def process_line(line):
    formatted_time = get_formatted_time()
    match = re.search(CONFIG["regex"], line)
    if match:
        ip = match.group(1)
        if ip in banned_ips:
            return
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        print(f"[{formatted_time}] Failed attempt #{failed_attempts[ip]} from {ip}")

        if failed_attempts[ip] >= CONFIG["max_retries"]:
            ban_ip(ip)

def ban_ip(ip):
    formatted_time = get_formatted_time()
    hostname = get_own_hostname()
    hostip = get_own_ip()
    print(f"[{formatted_time}] Banning {ip}")
    send_to_discord("SSH Brute Force Detected", f"Executing Host: {hostname}\nExecuting IP: {hostip}\n\n**IP-Address:** {ip}\n**Time:** {formatted_time}\n**ASN:** {get_asn(ip)}", 15548997)
    command = CONFIG["action"].format(ip=ip)
    subprocess.run(command, shell=True)
    banned_ips[ip] = datetime.now() + timedelta(seconds=CONFIG["ban_time"])
    del failed_attempts[ip]

def unban_ips():
    while True:
        now = datetime.now()
        for ip, ban_time in list(banned_ips.items()):
            if now > ban_time:
                unban_ip(ip)
        time.sleep(10)

def unban_ip(ip):
    formatted_time = get_formatted_time()
    print(f"[{formatted_time}] Unbanning {ip}")
    command = f"iptables -D INPUT -s {ip} -j DROP"
    subprocess.run(command, shell=True)
    del banned_ips[ip]

def get_asn(ip):
    r = requests.get(f"https://ipinfo.io/{ip}/json")
    if r.status_code == 200:
        return r.json().get("org", "Unknown")
    return "Unknown"

def send_to_discord(title, message, color):
    embed = {
        "title": title,
        "description": message,
        "color": color
    }
    data = {"embeds": [embed]}
    requests.post(CONFIG["discord_webhook"], json=data)

if __name__ == "__main__":
    check_and_install_dependencies()
    from colorama import Fore, Style, init
    init()
    import re
    import time
    import subprocess
    import json
    from datetime import datetime, timedelta
    from threading import Thread
    import requests
    clear()

    with open("config.json", "r") as f:
        CONFIG = json.load(f)

    banned_ips = {}
    failed_attempts = {}

    print(f"{Fore.GREEN}Welcome to Jonas2Ban{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Dependencies installed")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Checking rsyslog")
    check_and_install_rsyslog()
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} rsyslog installed")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Checking IPTABLES")
    check_and_install_iptables()
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} IPTABLES installiert")

    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Creating and enabling SystemD service")
    create_and_enable_systemd_service()

    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Script is running in the background now. Check status with systemctl status jonas2ban.service")
    exit(0)
