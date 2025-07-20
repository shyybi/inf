#!/usr/bin/env python3
"""
INF - Internet Never Forget
============================

Outil de visualisation de l'historique DNS
Affiche l'historique des résolutions DNS d'un domaine avec informations détaillées sur les IPs
"""

import sys
import json
import requests
import socket
from datetime import datetime
from ipwhois import IPWhois
import dns.resolver
import argparse
from typing import List, Dict, Optional
from colorama import init, Fore, Style

class DNSHistoryTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DNS-History-Tool/1.0'
        })
    
    def get_current_dns_records(self, domain: str) -> List[str]:
        """Récupère les enregistrements DNS actuels"""
        ips = []
        try:
            result = dns.resolver.resolve(domain, 'A')
            for rdata in result:
                ips.append(str(rdata))
        except Exception as e:
            print(f"Erreur lors de la résolution DNS: {e}")
        return ips
    
    def get_ip_info(self, ip: str) -> Dict:
        """Récupère les informations détaillées d'une IP"""
        info = {
            'ip': ip,
            'provider': 'Inconnu',
            'org': 'Inconnu',
            'country': 'Inconnu',
            'city': 'Inconnu',
            'asn': 'Inconnu'
        }
        
        try:
            obj = IPWhois(ip)
            whois_info = obj.lookup_rdap()
            
            if 'asn_description' in whois_info:
                info['provider'] = whois_info['asn_description']
            if 'asn' in whois_info:
                info['asn'] = f"AS{whois_info['asn']}"
            try:
                response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                    geo_data = response.json()
                    if geo_data.get('status') == 'success':
                        info['country'] = geo_data.get('country', 'Inconnu')
                        info['city'] = geo_data.get('city', 'Inconnu')
                        info['org'] = geo_data.get('org', info['provider'])
                        if not info['provider'] or info['provider'] == 'Inconnu':
                            info['provider'] = geo_data.get('isp', 'Inconnu')
            except:
                pass
                
        except Exception as e:
            print(f"Erreur lors de la récupération des infos IP {ip}: {e}")
        
        return info
    
    def get_dns_history_securitytrails(self, domain: str, api_key: str = None) -> List[Dict]:
        """Récupère l'historique DNS via SecurityTrails (nécessite une clé API)"""
        if not api_key:
            return []
        
        headers = {
            'APIKEY': api_key,
            'Content-Type': 'application/json'
        }
        
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                history = []
                
                for record in data.get('records', []):
                    for value in record.get('values', []):
                        history.append({
                            'ip': value.get('ip'),
                            'first_seen': record.get('first_seen'),
                            'last_seen': record.get('last_seen')
                        })
                
                return history
        except Exception as e:
            print(f"Erreur SecurityTrails: {e}")
        
        return []
    
    def get_dns_history_hackertarget(self, domain: str) -> List[Dict]:
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                history = []
                
                for line in lines:
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            hostname = parts[0].strip()
                            ip = parts[1].strip()
                            if hostname == domain or hostname.endswith(f".{domain}"):
                                history.append({
                                    'ip': ip,
                                    'source': 'hackertarget'
                                })
                
                return history
        except Exception as e:
            print(f"Erreur HackerTarget: {e}")
        
        return []
    
    def format_output(self, domain: str, records: List[Dict]):
        print(f"\n=== Historique DNS pour {domain} ===\n")
        
        if not records:
            print("Aucun enregistrement historique trouvé.")
            return
        
        sorted_records = sorted(records, 
                              key=lambda x: x.get('last_seen', x.get('first_seen', '9999-99-99')), 
                              reverse=True)
        
        for i, record in enumerate(sorted_records):
            ip = record['ip']
            ip_info = self.get_ip_info(ip)
            
            date_info = ""
            if 'last_seen' in record:
                date_info = record['last_seen']
            elif 'first_seen' in record:
                date_info = record['first_seen']
            else:
                date_info = "Date inconnue"
            
            print(f"{i:2d} : {ip:15s} - {ip_info['provider']:20s} - {ip_info['org']:25s} - {ip_info['country']:15s} - {date_info}")
    
    def analyze_domain(self, domain: str, api_key: str = None):
        print(f"Analyse de {domain}...")
        
        current_ips = self.get_current_dns_records(domain)
        all_records = []
        
        for ip in current_ips:
            all_records.append({
                'ip': ip,
                'last_seen': datetime.now().strftime('%Y-%m-%d'),
                'source': 'current'
            })
        
        if api_key:
            history = self.get_dns_history_securitytrails(domain, api_key)
            all_records.extend(history)
        
        hackertarget_history = self.get_dns_history_hackertarget(domain)
        all_records.extend(hackertarget_history)
        
        seen_ips = set()
        unique_records = []
        for record in all_records:
            if record['ip'] not in seen_ips:
                seen_ips.add(record['ip'])
                unique_records.append(record)
        
        self.format_output(domain, unique_records)

def main():
    init(autoreset=True)
    print(Fore.CYAN + r"""
         _____ _   _  _____   
        |_   _| \ | ||  ___| 
          | | |  \| || |_      
          | | | . ` ||  _|    
         _| |_| |\  || |     
         \___/\_| \_/\_|      
    """)
    print(Fore.YELLOW + "    INF - Internet Never Forget")
    print(Fore.YELLOW + "   Outil d'analyse historique DNS\n" + Style.RESET_ALL)
    
    parser = argparse.ArgumentParser(description="Outil d'analyse de l'historique DNS")
    parser.add_argument('domain', nargs='?', help='Domaine à analyser (ex: exemple.com)')
    parser.add_argument('--api-key', help='Clé API SecurityTrails (optionnel)')
    parser.add_argument('--api-key-file', help='Fichier contenant la clé API SecurityTrails (optionnel)')

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(0)

    api_key = args.api_key
    if args.api_key_file:
        try:
            with open(args.api_key_file, 'r') as f:
                api_key = f.read().strip()
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier de clé API: {e}")
            sys.exit(1)

    tool = DNSHistoryTool()
    tool.analyze_domain(args.domain, api_key)

if __name__ == "__main__":
    main()