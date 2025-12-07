import random
from datetime import datetime, timedelta

def generate_firewall_logs(filename, num_entries=20):
    """Генерирует безопасные примеры логов файрвола"""
    with open(filename, 'w') as f:
        for i in range(num_entries):
            timestamp = (datetime.now() - timedelta(minutes=i)).isoformat()
            src_ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
            protocol = random.choice(['TCP', 'UDP'])
            port = random.choice([80, 443, 22, 53, 3389, 4444, 5555])
            action = random.choice(['ALLOW', 'DENY', 'BLOCK'])
            
            if port in [4444, 5555]:  # Делаем некоторые порты подозрительными
                action = 'BLOCK'
            
            f.write(f"{timestamp} {src_ip} {protocol} {port} {action}\n")

def generate_proxy_logs(filename, num_entries=15):
    """Генерирует безопасные примеры логов прокси"""
    domains = ['google.com', 'youtube.com', 'github.com', 
               'malicious-test-example.com', 'phishing-test-example.net']
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            ip = f"10.0.{random.randint(1,5)}.{random.randint(100,200)}"
            time_str = (datetime.now() - timedelta(minutes=i)).strftime('%d/%b/%Y:%H:%M:%S %z')
            domain = random.choice(domains)
            method = random.choice(['GET', 'POST'])
            status = random.choice([200, 302, 403, 404, 500])
            
            f.write(f'{ip} - - [{time_str}] "{method} http://{domain}/path HTTP/1.1" {status}\n')

if __name__ == "__main__":
    print("[*] Генерирую примеры логов...")
    generate_firewall_logs("sample_logs/firewall_sample.log")
    generate_proxy_logs("sample_logs/proxy_sample.log")
    print("[+] Готово! Запустите: python log_analyzer.py")
