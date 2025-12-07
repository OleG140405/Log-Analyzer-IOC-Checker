"""
Simple Log Analyzer for SOC L1 Analyst
Анализирует логи файрвола и прокси, ищет подозрительную активность
"""

import re
from datetime import datetime
import ipaddress
from collections import Counter

class SimpleLogAnalyzer:
    """Простой анализатор логов для начинающего SOC-аналитика"""
    
    def __init__(self):
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.top_sources = Counter()
        self.top_destinations = Counter()
        
    def parse_firewall_log(self, log_file):
        """Парсинг логов файрвола в формате: время IP протокол порт действие"""
        print(f"[*] Анализирую файрволл логи: {log_file}")
        
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Простой парсинг
                parts = line.split()
                if len(parts) >= 5:
                    timestamp = parts[0]
                    src_ip = parts[1]
                    protocol = parts[2]
                    dst_port = parts[3]
                    action = parts[4]
                    
                    # Собираем статистику
                    self.top_sources[src_ip] += 1
                    self.top_destinations[dst_port] += 1
                    
                    # Ищем подозрительное
                    if action == "BLOCK":
                        self.blocked_ips.add(src_ip)
                    
                    # Подозрительные порты (пример)
                    if dst_port in ["4444", "5555", "6666", "7777", "8080"]:
                        self.suspicious_ips.add(src_ip)
                        
                        print(f"[!] Подозрительное соединение: {src_ip} -> порт {dst_port}")
        
        print(f"[+] Найдено {len(self.blocked_ips)} заблокированных IP")
        print(f"[+] Найдено {len(self.suspicious_ips)} подозрительных IP")
    
    def parse_proxy_log(self, log_file):
        """Парсинг логов прокси"""
        print(f"\n[*] Анализирую прокси логи: {log_file}")
        
        malicious_domains = [
            "malicious.com", "evil.org", "bad-site.net",
            "phishing", "cryptominer", "exploit"
        ]
        
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip().lower()
                
                # Ищем доступ к подозрительным доменам
                for bad_domain in malicious_domains:
                    if bad_domain in line:
                        # Извлекаем IP пользователя (упрощенно)
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        if ip_match:
                            user_ip = ip_match.group()
                            self.suspicious_ips.add(user_ip)
                            print(f"[!] Доступ к подозрительному домену: {user_ip} -> {bad_domain}")
                        break
    
    def check_private_ips(self, ip_list):
        """Проверяет, есть ли среди IP приватные адреса"""
        print("\n[*] Проверка на приватные IP адреса...")
        
        private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16')
        ]
        
        for ip in ip_list:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for network in private_ranges:
                    if ip_obj in network:
                        print(f"[!] Найден приватный IP в логах: {ip}")
                        break
            except:
                continue
    
    def generate_report(self, output_file="analysis_report.txt"):
        """Генерирует простой отчет"""
        print(f"\n[*] Генерирую отчет: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("="*50 + "\n")
            f.write("ОТЧЕТ АНАЛИЗА ЛОГОВ\n")
            f.write(f"Время анализа: {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            
            f.write("1. СТАТИСТИКА:\n")
            f.write(f"- Всего заблокированных IP: {len(self.blocked_ips)}\n")
            f.write(f"- Подозрительных IP: {len(self.suspicious_ips)}\n\n")
            
            f.write("2. ТОП-5 ИСТОЧНИКОВ ПО КОЛИЧЕСТВУ СОЕДИНЕНИЙ:\n")
            for ip, count in self.top_sources.most_common(5):
                f.write(f"  {ip}: {count} соединений\n")
            f.write("\n")
            
            f.write("3. ТОП-5 ЦЕЛЕВЫХ ПОРТОВ:\n")
            for port, count in self.top_destinations.most_common(5):
                f.write(f"  Порт {port}: {count} обращений\n")
            f.write("\n")
            
            if self.suspicious_ips:
                f.write("4. ПОДОЗРИТЕЛЬНЫЕ IP АДРЕСА:\n")
                for ip in sorted(self.suspicious_ips):
                    f.write(f"  - {ip}\n")
            
            if self.blocked_ips:
                f.write("\n5. ЗАБЛОКИРОВАННЫЕ IP:\n")
                for ip in sorted(self.blocked_ips):
                    f.write(f"  - {ip}\n")
        
        print(f"[+] Отчет сохранен в {output_file}")


def main():
    """Главная функция"""
    print("="*50)
    print("SIMPLE LOG ANALYZER v1.0")
    print("Для начинающего SOC аналитика")
    print("="*50)
    
    analyzer = SimpleLogAnalyzer()
    
    # Пример использования
    try:
        analyzer.parse_firewall_log("sample_logs/firewall_sample.log")
        analyzer.parse_proxy_log("sample_logs/proxy_sample.log")
        
        # Проверяем все найденные IP
        all_ips = list(analyzer.top_sources.keys())
        analyzer.check_private_ips(all_ips)
        
        # Генерируем отчет
        analyzer.generate_report()
        
    except FileNotFoundError as e:
        print(f"[ERROR] Файл не найден: {e}")
        print("Создайте папку sample_logs с тестовыми логами")
        
        # Создаем пример лога для демонстрации
        with open("sample_logs/firewall_sample.log", "w") as f:
            f.write("2024-01-15T10:30:00 192.168.1.100 TCP 80 ALLOW\n")
            f.write("2024-01-15T10:31:00 10.0.0.5 TCP 443 ALLOW\n")
            f.write("2024-01-15T10:32:00 93.184.216.34 TCP 4444 BLOCK\n")
            f.write("2024-01-15T10:33:00 8.8.8.8 UDP 53 ALLOW\n")
        
        print("[+] Создан пример лога. Запустите скрипт снова.")


if __name__ == "__main__":
    main()
