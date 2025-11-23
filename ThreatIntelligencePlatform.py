#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THREAT INTELLIGENCE PLATFORM - SİBER İSTİHBARAT PLATFORMU
Profesyonel tehdit analizi ve istihbarat toplama aracı
"""

import requests
import json
import socket
import hashlib
import time
from datetime import datetime
import os
import sys
import base64
from urllib.parse import urlparse
import sqlite3

# Renkler
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ThreatIntelligence:
    """Threat Intelligence Platform Ana Sınıfı"""
    
    def __init__(self):
        # API Keys (Kullanıcı dolduracak)
        self.api_keys = {
            'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',
            'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY',
            'ipgeolocation': 'YOUR_IPGEOLOCATION_API_KEY',
        }
        
        self.session = requests.Session()
        self.results = {}
        self.db_file = 'threat_intel.db'
        
        # Veritabanı başlat
        self.init_database()
    
    def init_database(self):
        """SQLite veritabanını başlat"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Tablo oluştur
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                target_type TEXT,
                threat_score INTEGER,
                results TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_to_database(self, target, target_type, threat_score, results):
        """Sonuçları veritabanına kaydet"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO investigations (timestamp, target, target_type, threat_score, results)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), target, target_type, threat_score, json.dumps(results)))
        
        conn.commit()
        conn.close()
    
    def banner(self):
        """ASCII Banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██╗███╗   ██╗   ║
║    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║████╗  ██║   ║
║       ██║   ███████║██████╔╝█████╗  ███████║   ██║       ██║██╔██╗ ██║   ║
║       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██║██║╚██╗██║   ║
║       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║██║ ╚████║   ║
║       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝╚═╝  ╚═══╝   ║
║                                                                            ║
║              THREAT INTELLIGENCE PLATFORM v2.0                             ║
║              Profesyonel Siber İstihbarat Aracı                           ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
    
    def check_api_keys(self):
        """API anahtarlarını kontrol et"""
        print(f"\n{Colors.YELLOW}[*] API anahtarları kontrol ediliyor...{Colors.END}")
        
        missing_keys = []
        for service, key in self.api_keys.items():
            if key == f'YOUR_{service.upper()}_API_KEY':
                missing_keys.append(service)
        
        if missing_keys:
            print(f"\n{Colors.RED}[!] Eksik API anahtarları:{Colors.END}")
            for service in missing_keys:
                print(f"    • {service}")
            print(f"\n{Colors.YELLOW}API anahtarları olmadan demo modda çalışılacak.{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}[+] Tüm API anahtarları mevcut!{Colors.END}")
        return True
    
    def get_ip_geolocation(self, ip):
        """IP geolocation bilgisi"""
        print(f"\n{Colors.BLUE}[*] IP Geolocation analizi yapılıyor...{Colors.END}")
        
        try:
            # Ücretsiz ipapi.co kullan (API key gerektirmiyor)
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    'ip': data.get('ip'),
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('org'),
                    'asn': data.get('asn')
                }
                
                print(f"{Colors.GREEN}[+] Lokasyon: {result['city']}, {result['country']}{Colors.END}")
                print(f"{Colors.GREEN}[+] ISP: {result['isp']}{Colors.END}")
                
                return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Geolocation hatası: {e}{Colors.END}")
        
        return None
    
    def check_virustotal_ip(self, ip):
        """VirusTotal IP analizi"""
        print(f"\n{Colors.BLUE}[*] VirusTotal IP analizi yapılıyor...{Colors.END}")
        
        if self.api_keys['virustotal'] == 'YOUR_VIRUSTOTAL_API_KEY':
            print(f"{Colors.YELLOW}[!] VirusTotal API key yok, demo veri gösteriliyor...{Colors.END}")
            return {
                'detected': 'N/A',
                'score': 'API Key Required',
                'votes': {'malicious': 0, 'harmless': 0}
            }
        
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.api_keys['virustotal']}
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                result = {
                    'detected': stats.get('malicious', 0) > 0,
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'clean_count': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
                
                if result['malicious_count'] > 0:
                    print(f"{Colors.RED}[!] Zararlı olarak işaretlendi: {result['malicious_count']} vendor{Colors.END}")
                else:
                    print(f"{Colors.GREEN}[+] Temiz görünüyor{Colors.END}")
                
                return result
                
        except Exception as e:
            print(f"{Colors.RED}[!] VirusTotal hatası: {e}{Colors.END}")
        
        return None
    
    def check_abuseipdb(self, ip):
        """AbuseIPDB kötüye kullanım kontrolü"""
        print(f"\n{Colors.BLUE}[*] AbuseIPDB kötüye kullanım kontrolü...{Colors.END}")
        
        if self.api_keys['abuseipdb'] == 'YOUR_ABUSEIPDB_API_KEY':
            print(f"{Colors.YELLOW}[!] AbuseIPDB API key yok, demo veri gösteriliyor...{Colors.END}")
            return {
                'abuse_score': 'N/A',
                'reports': 'API Key Required'
            }
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()['data']
                
                result = {
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'usage_type': data.get('usageType')
                }
                
                if result['abuse_score'] > 50:
                    print(f"{Colors.RED}[!] Yüksek kötüye kullanım skoru: {result['abuse_score']}%{Colors.END}")
                elif result['abuse_score'] > 0:
                    print(f"{Colors.YELLOW}[!] Düşük kötüye kullanım skoru: {result['abuse_score']}%{Colors.END}")
                else:
                    print(f"{Colors.GREEN}[+] Kötüye kullanım raporu yok{Colors.END}")
                
                return result
                
        except Exception as e:
            print(f"{Colors.RED}[!] AbuseIPDB hatası: {e}{Colors.END}")
        
        return None
    
    def check_open_ports(self, ip):
        """Yaygın portları kontrol et"""
        print(f"\n{Colors.BLUE}[*] Açık port taraması yapılıyor...{Colors.END}")
        
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt'
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    open_ports.append({'port': port, 'service': service})
                    print(f"{Colors.GREEN}[+] Port {port} açık ({service}){Colors.END}")
                
                sock.close()
                
            except Exception:
                continue
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!] Açık port bulunamadı (firewall olabilir){Colors.END}")
        
        return open_ports
    
    def get_dns_records(self, domain):
        """DNS kayıtlarını al"""
        print(f"\n{Colors.BLUE}[*] DNS kayıtları alınıyor...{Colors.END}")
        
        records = {}
        
        try:
            # A kaydı
            import socket
            ip = socket.gethostbyname(domain)
            records['A'] = ip
            print(f"{Colors.GREEN}[+] A Record: {ip}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] DNS çözümleme hatası: {e}{Colors.END}")
        
        return records
    
    def calculate_threat_score(self, results):
        """Tehdit skorunu hesapla (0-100)"""
        print(f"\n{Colors.BLUE}[*] Tehdit skoru hesaplanıyor...{Colors.END}")
        
        score = 0
        factors = []
        
        # VirusTotal analizi
        if results.get('virustotal'):
            vt = results['virustotal']
            if isinstance(vt.get('malicious_count'), int):
                if vt['malicious_count'] > 5:
                    score += 40
                    factors.append('VirusTotal: Çok sayıda zararlı tespit')
                elif vt['malicious_count'] > 0:
                    score += 20
                    factors.append('VirusTotal: Zararlı tespit')
        
        # AbuseIPDB analizi
        if results.get('abuseipdb'):
            abuse = results['abuseipdb']
            if isinstance(abuse.get('abuse_score'), (int, float)):
                if abuse['abuse_score'] > 75:
                    score += 30
                    factors.append('AbuseIPDB: Yüksek kötüye kullanım')
                elif abuse['abuse_score'] > 25:
                    score += 15
                    factors.append('AbuseIPDB: Orta kötüye kullanım')
        
        # Açık portlar
        if results.get('open_ports'):
            port_count = len(results['open_ports'])
            if port_count > 5:
                score += 15
                factors.append(f'Çok sayıda açık port ({port_count})')
            elif port_count > 0:
                score += 5
        
        # Risk seviyesi
        if score >= 70:
            risk_level = f"{Colors.RED}KRİTİK{Colors.END}"
        elif score >= 40:
            risk_level = f"{Colors.YELLOW}YÜKSEK{Colors.END}"
        elif score >= 20:
            risk_level = f"{Colors.YELLOW}ORTA{Colors.END}"
        else:
            risk_level = f"{Colors.GREEN}DÜŞÜK{Colors.END}"
        
        print(f"\n{Colors.BOLD}Tehdit Skoru: {score}/100{Colors.END}")
        print(f"{Colors.BOLD}Risk Seviyesi: {risk_level}{Colors.END}")
        
        if factors:
            print(f"\n{Colors.YELLOW}Risk Faktörleri:{Colors.END}")
            for factor in factors:
                print(f"  • {factor}")
        
        return score, risk_level, factors
    
    def analyze_ip(self, ip):
        """IP adresini kapsamlı analiz et"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}IP Adresi Analizi: {ip}{Colors.END}")
        print(f"{Colors.HEADER}{'='*80}{Colors.END}")
        
        results = {
            'target': ip,
            'target_type': 'IP',
            'timestamp': datetime.now().isoformat()
        }
        
        # Analizleri yap
        results['geolocation'] = self.get_ip_geolocation(ip)
        time.sleep(1)
        
        results['virustotal'] = self.check_virustotal_ip(ip)
        time.sleep(1)
        
        results['abuseipdb'] = self.check_abuseipdb(ip)
        time.sleep(1)
        
        results['open_ports'] = self.check_open_ports(ip)
        
        # Tehdit skoru
        threat_score, risk_level, factors = self.calculate_threat_score(results)
        results['threat_score'] = threat_score
        results['risk_level'] = risk_level
        results['risk_factors'] = factors
        
        # Veritabanına kaydet
        self.save_to_database(ip, 'IP', threat_score, results)
        
        return results
    
    def analyze_domain(self, domain):
        """Domain adresini analiz et"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}Domain Analizi: {domain}{Colors.END}")
        print(f"{Colors.HEADER}{'='*80}{Colors.END}")
        
        results = {
            'target': domain,
            'target_type': 'Domain',
            'timestamp': datetime.now().isoformat()
        }
        
        # DNS kayıtları
        results['dns'] = self.get_dns_records(domain)
        
        # IP'ye çevir ve analiz et
        if results['dns'].get('A'):
            ip = results['dns']['A']
            print(f"\n{Colors.CYAN}[*] Domain IP'si: {ip}{Colors.END}")
            
            results['ip_analysis'] = self.analyze_ip(ip)
        
        return results
    
    def generate_report(self, results):
        """Detaylı rapor oluştur"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}DETAYLI RAPOR{Colors.END}")
        print(f"{Colors.HEADER}{'='*80}{Colors.END}\n")
        
        # JSON dosyası olarak kaydet
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_intel_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False, default=str)
            
            print(f"{Colors.GREEN}[+] Rapor kaydedildi: {filename}{Colors.END}")
            print(f"{Colors.GREEN}[+] Veritabanı güncellendi: {self.db_file}{Colors.END}\n")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Rapor kaydetme hatası: {e}{Colors.END}")
    
    def show_menu(self):
        """Ana menü"""
        menu = f"""
{Colors.CYAN}╔════════════════════════════════════════════════════════════╗
║                      ANA MENÜ                              ║
╠════════════════════════════════════════════════════════════╣
║  1. IP Adresi Analizi                                      ║
║  2. Domain Analizi                                         ║
║  3. Geçmiş Kayıtları Görüntüle                            ║
║  4. API Anahtarlarını Güncelle                            ║
║  5. Çıkış                                                  ║
╚════════════════════════════════════════════════════════════╝{Colors.END}
        """
        print(menu)
    
    def run(self):
        """Ana program döngüsü"""
        self.banner()
        self.check_api_keys()
        
        while True:
            self.show_menu()
            
            choice = input(f"\n{Colors.BLUE}Seçiminiz: {Colors.END}").strip()
            
            if choice == '1':
                ip = input(f"{Colors.BLUE}IP adresi girin: {Colors.END}").strip()
                if ip:
                    results = self.analyze_ip(ip)
                    self.generate_report(results)
                    input(f"\n{Colors.YELLOW}Devam etmek için Enter'a basın...{Colors.END}")
            
            elif choice == '2':
                domain = input(f"{Colors.BLUE}Domain girin: {Colors.END}").strip()
                if domain:
                    results = self.analyze_domain(domain)
                    self.generate_report(results)
                    input(f"\n{Colors.YELLOW}Devam etmek için Enter'a basın...{Colors.END}")
            
            elif choice == '3':
                self.show_history()
                input(f"\n{Colors.YELLOW}Devam etmek için Enter'a basın...{Colors.END}")
            
            elif choice == '4':
                self.update_api_keys()
            
            elif choice == '5':
                print(f"\n{Colors.GREEN}Güvenli kalın! 🔒{Colors.END}\n")
                break
            
            else:
                print(f"{Colors.RED}[!] Geçersiz seçim!{Colors.END}")
    
    def show_history(self):
        """Geçmiş kayıtları göster"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}GEÇMİŞ ARAMALAR{Colors.END}")
        print(f"{Colors.HEADER}{'='*80}{Colors.END}\n")
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM investigations ORDER BY id DESC LIMIT 10')
        rows = cursor.fetchall()
        
        if rows:
            for row in rows:
                print(f"{Colors.CYAN}ID: {row[0]}{Colors.END}")
                print(f"Zaman: {row[1]}")
                print(f"Hedef: {row[2]} ({row[3]})")
                print(f"Tehdit Skoru: {row[4]}/100")
                print("-" * 80)
        else:
            print(f"{Colors.YELLOW}Henüz kayıt yok.{Colors.END}")
        
        conn.close()
    
    def update_api_keys(self):
        """API anahtarlarını güncelle"""
        print(f"\n{Colors.YELLOW}API Anahtarlarını Güncelle{Colors.END}")
        print(f"(Boş bırakmak için Enter'a basın)\n")
        
        vt = input("VirusTotal API Key: ").strip()
        if vt:
            self.api_keys['virustotal'] = vt
        
        abuse = input("AbuseIPDB API Key: ").strip()
        if abuse:
            self.api_keys['abuseipdb'] = abuse
        
        ipgeo = input("IPGeolocation API Key: ").strip()
        if ipgeo:
            self.api_keys['ipgeolocation'] = ipgeo
        
        print(f"\n{Colors.GREEN}[+] API anahtarları güncellendi!{Colors.END}")

def main():
    """Ana fonksiyon"""
    try:
        platform = ThreatIntelligence()
        platform.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Program kullanıcı tarafından durduruldu{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Kritik hata: {e}{Colors.END}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
