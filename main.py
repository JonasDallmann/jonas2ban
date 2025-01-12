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
    match = re.search(CONFIG["regex"], line)
    if match:
        ip = match.group(1)
        if ip in banned_ips:
            return
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        print(f"[{datetime.now()}] Failed attempt #{failed_attempts[ip]} from {ip}")

        if failed_attempts[ip] >= CONFIG["max_retries"]:
            ban_ip(ip)

def ban_ip(ip):
    print(f"[{datetime.now()}] Banning {ip}")
    send_to_discord(f"IP-Address: {ip}\nTime: {datetime.now()}\nASN: {get_asn(ip)}")
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
    print(f"[{datetime.now()}] Unbanning {ip}")
    command = f"iptables -D INPUT -s {ip} -j DROP"
    subprocess.run(command, shell=True)
    del banned_ips[ip]

def get_asn(ip):
    command = f"whois {ip}"
    output = subprocess.run(command, shell=True, capture_output=True)
    return output.stdout.decode("utf-8")

def send_to_discord(message):
    embed = {
        "title": "[NEW DETECTION] SSH Brute Force Detected",
        "description": message,
        "color": 16711680
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
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Checking IPTABLES")
    check_and_install_iptables()
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} IPTABLES installed")
    log_thread = Thread(target=monitor_logs)
    unban_thread = Thread(target=unban_ips)
    try:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting Log Monitor")
        log_thread.start()
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Log Monitor started")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error starting Log Monitor: {e}")
        exit(1)
    try:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Starting Unban Monitor")
        unban_thread.start()
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Unban Monitor started")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error starting Unban Monitor: {e}")
        exit(1)
