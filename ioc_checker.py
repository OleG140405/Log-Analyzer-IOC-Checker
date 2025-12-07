"""
Simple IOC Checker - проверка индикаторов компрометации
"""

import requests
import time

class SimpleIOCChecker:
    """Проверяет IoC через публичные API (бесплатные лимиты)"""
    
    @staticmethod
    def check_ip(ip_address):
        """Проверка IP адреса"""
        print(f"[*] Проверяем IP: {ip_address}")
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   Страна: {data.get('country', 'N/A')}")
                print(f"   Провайдер: {data.get('org', 'N/A')}")
                print(f"   Город: {data.get('city', 'N/A')}")
                
                # Проверяем, не является ли IP приватным
                if ip_address.startswith(('10.', '172.', '192.168.')):
                    print("   [!] Это приватный IP адрес")
                    
            else:
                print("   Не удалось получить информацию")
                
        except Exception as e:
            print(f"   Ошибка: {e}")
    
    @staticmethod
    def check_domain(domain):
        """Проверка домена"""
        print(f"[*] Проверяем домен: {domain}")
        
        # Проверяем на наличие ключевых слов
        suspicious_keywords = ['malware', 'phish', 'exploit', 'hack', 'crypt']
        
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                print(f"   [!] Содержит подозрительное слово: '{keyword}'")
    
    @staticmethod
    def check_hash(file_hash):
        """Проверка хэша файла"""
        print(f"[*] Проверяем хэш: {file_hash}")
        
        # Проверяем формат
        if len(file_hash) == 32:
            print("   Тип: MD5")
        elif len(file_hash) == 40:
            print("   Тип: SHA1")
        elif len(file_hash) == 64:
            print("   Тип: SHA256")
        else:
            print("   Неизвестный формат хэша")
            
        # Для реальной проверки нужен API VirusTotal/Hybrid-Analysis


def main():
    """Демонстрация работы"""
    print("="*50)
    print("SIMPLE IOC CHECKER")
    print("="*50)
    
    checker = SimpleIOCChecker()
    
    # Пример проверки
    test_indicators = [
        ("IP", "8.8.8.8"),
        ("IP", "192.168.1.1"),
        ("Domain", "google.com"),
        ("Domain", "malware-test-site.com"),
        ("Hash", "d41d8cd98f00b204e9800998ecf8427e")
    ]
    
    for ioc_type, value in test_indicators:
        if ioc_type == "IP":
            checker.check_ip(value)
        elif ioc_type == "Domain":
            checker.check_domain(value)
        elif ioc_type == "Hash":
            checker.check_hash(value)
        
        print()  # Пустая строка между проверками
        time.sleep(1)  # Чтобы не превысить лимиты API


if __name__ == "__main__":
    main()
