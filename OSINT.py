import os
import sys
import time
import json
import requests
import logging
import argparse
import socket
import whois
import dns.resolver
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
import concurrent.futures
import csv
import ipaddress
import ssl
import random
import hashlib
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from fake_useragent import UserAgent

# Disabilita avvisi SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OSINTUltraPro:
    def __init__(self, config_file="config.json"):
        self.session = requests.Session()
        self.ua = UserAgent()
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Configurazione proxy (opzionale)
        self.proxies = None
        self.setup_proxies()
        
        # Configurazione logging avanzata
        self.setup_advanced_logging()
        
        self.config = self.load_config(config_file)
        self.results = {}
        self.threat_intel = {}
        self.rate_limit_delay = 1
        self.max_workers = 10

    def setup_advanced_logging(self):
        """Configura il sistema di logging avanzato"""
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        
        # Formattatore personalizzato
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        file_handler = logging.FileHandler('ms17_osint_advanced.log', encoding='utf-8')
        file_handler.setFormatter(formatter)
        
        # Stream handler
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        self.logger = logger

    def setup_proxies(self):
        """Configura proxy per anonimato"""
        proxy_configs = [
            {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'},
        ]
        
        for proxy in proxy_configs:
            try:
                test_response = requests.get('http://httpbin.org/ip', proxies=proxy, timeout=10)
                if test_response.status_code == 200:
                    self.proxies = proxy
                    self.session.proxies.update(proxy)
                    self.logger.info("Proxy configurato con successo")
                    break
            except:
                continue

    def load_config(self, config_file):
        """Carica la configurazione avanzata con validazione"""
        default_config = {
            "timeout": 30,
            "max_threads": 15,
            "deep_scan": True,
            "rate_limit_delay": 1,
            "user_agents_rotation": True,
            "tor_proxy": "socks5h://127.0.0.1:9050"
        }
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                default_config.update(user_config)
            
            # Validazione API keys
            api_services = {
                'virustotal_api_key': 'VirusTotal',
                'shodan_api_key': 'Shodan',
                'abuseipdb_api_key': 'AbuseIPDB',
                'hibp_api_key': 'HaveIBeenPwned',
                'hunter_api_key': 'Hunter.io',
                'unwiredlabs_api_key': 'UnwiredLabs GSM',
                'ipinfo_api_key': 'IPInfo.io',
                'alienvault_api_key': 'AlienVault OTX',
                'greynoise_api_key': 'GreyNoise',
                'whoxy_api_key': 'Whooxy',
                'securitytrails_api_key': 'SecurityTrails',
                'circl_api_user': 'CIRCL PDNS User',
                'circl_api_pass': 'CIRCL PDNS Pass',
                'leaklookup_api_key': 'Leak-Lookup',
                'dehashed_api_key': 'DeHashed',
                'dehashed_email': 'DeHashed Email'
            }
            
            for key, service in api_services.items():
                if key in default_config and default_config[key] and not default_config[key].startswith('TUO_'):
                    self.logger.info("API %s configurata", service)
                else:
                    self.logger.warning("API %s non configurata - Funzionalità limitate", service)
            
            return default_config
            
        except FileNotFoundError:
            self.logger.warning("File di configurazione non trovato. Usando configurazione di default.")
            return default_config
        except json.JSONDecodeError as e:
            self.logger.error("Errore nel file di configurazione: %s", e)
            return default_config

    def rotate_user_agent(self):
        """Ruota lo User-Agent per evitare detection"""
        if self.config.get('user_agents_rotation', True):
            self.session.headers['User-Agent'] = self.ua.random

    def validate_input(self, input_str: str, input_type: str) -> bool:
        """Validazione e sanitizzazione avanzata degli input"""
        try:
            if input_type == 'domain':
                pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
                if not re.match(pattern, input_str):
                    raise ValueError("Formato dominio non valido")
                reserved_domains = ['localhost', 'example.com', 'test.com']
                if input_str.lower() in reserved_domains:
                    raise ValueError("Dominio riservato")
                return True
                
            elif input_type == 'ip':
                ip_obj = ipaddress.ip_address(input_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                    raise ValueError("IP riservato o non routabile")
                return True
                
            elif input_type == 'email':
                pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,64}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$'
                if not re.match(pattern, input_str):
                    raise ValueError("Formato email non valido")
                if len(input_str) > 254:
                    raise ValueError("Email troppo lunga")
                return True
                
            elif input_type == 'username':
                if not re.match(r'^[a-zA-Z0-9_.-]{1,50}$', input_str):
                    raise ValueError("Username contiene caratteri non validi")
                return True
                
            elif input_type == 'gsm':
                if not re.match(r'^[\d,:-\s]+$', input_str):
                    raise ValueError("Formato dati GSM non valido")
                return True
                
            elif input_type == 'phone':
                pattern = r'^\+?[1-9]\d{1,14}$'
                if not re.match(pattern, input_str.replace(' ', '')):
                    raise ValueError("Formato numero telefono non valido")
                return True
                
        except ValueError as e:
            self.logger.error("Validazione input fallita: %s", e)
            return False
        except Exception as e:
            self.logger.error("Errore validazione input: %s", e)
            return False
        
        return False

    def safe_api_call(self, api_func, *args, max_retries=3, backoff_factor=2, **kwargs):
        """Esegue chiamate API con gestione errori avanzata, retry e backoff esponenziale"""
        for attempt in range(max_retries):
            try:
                self.rotate_user_agent()
                time.sleep(self.rate_limit_delay)
                
                result = api_func(*args, **kwargs)
                
                if isinstance(result, dict) and 'error' in result:
                    if 'rate limit' in result['error'].lower() or 'quota' in result['error'].lower():
                        wait_time = backoff_factor ** (attempt + 1) * 30
                        self.logger.warning("Rate limit raggiunto, attesa di %d secondi", wait_time)
                        time.sleep(wait_time)
                        continue
                
                return result
                
            except requests.exceptions.ConnectionError as e:
                self.logger.warning("Errore di connessione (tentativo %d/%d): %s", 
                                  attempt + 1, max_retries, e)
                if attempt == max_retries - 1:
                    return {"error": f"Connection error: {e}"}
                time.sleep(backoff_factor ** attempt)
                
            except requests.exceptions.Timeout as e:
                self.logger.warning("Timeout (tentativo %d/%d)", attempt + 1, max_retries)
                if attempt == max_retries - 1:
                    return {"error": "Request timeout"}
                time.sleep(backoff_factor ** attempt)
                
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else None
                if status_code == 429:
                    wait_time = backoff_factor ** (attempt + 1) * 30
                    self.logger.warning("HTTP 429 Rate limit, attesa di %d secondi", wait_time)
                    time.sleep(wait_time)
                    continue
                elif status_code == 401:
                    return {"error": "API key non valida o scaduta"}
                elif status_code == 403:
                    return {"error": "Accesso negato all'API"}
                elif status_code == 404:
                    return {"error": "Risorsa non trovata"}
                else:
                    self.logger.error("Errore HTTP %s: %s", str(status_code), e)
                    return {"error": f"HTTP error {status_code}"}
                    
            except Exception as e:
                self.logger.error("Errore imprevisto in API call (tentativo %d): %s", attempt + 1, e)
                if attempt == max_retries - 1:
                    return {"error": f"Unexpected error: {e}"}
                time.sleep(backoff_factor ** attempt)
        
        return {"error": "Numero massimo di tentativi raggiunto"}

    # === API INTEGRATIONS - TUTTE LE API IMPLEMENTATE ===
    
    # VirusTotal
    def virustotal_domain(self, domain):
        api_key = self.config.get('virustotal_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key VirusTotal non configurata"}
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore VirusTotal: {str(e)}"}

    def virustotal_ip(self, ip):
        api_key = self.config.get('virustotal_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key VirusTotal non configurata"}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore VirusTotal IP: {str(e)}"}

    # Shodan
    def shodan_ip_lookup(self, ip):
        api_key = self.config.get('shodan_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Shodan non configurata"}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Shodan: {str(e)}"}

    def shodan_domain(self, domain):
        api_key = self.config.get('shodan_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Shodan non configurata"}
        
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Shodan dominio: {str(e)}"}

    # AbuseIPDB
    def abuseipdb_check(self, ip):
        api_key = self.config.get('abuseipdb_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key AbuseIPDB non configurata"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
        }
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore AbuseIPDB: {str(e)}"}

    # Have I Been Pwned
    def hibp_breach_check(self, email):
        api_key = self.config.get('hibp_api_key')
        headers = {'hibp-api-key': api_key} if api_key and not api_key.startswith('TUO_') else {}
        headers['User-Agent'] = 'MS17-OSINT-3.0'
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    "breached": True,
                    "breach_count": len(breaches),
                    "breaches": breaches
                }
            elif response.status_code == 404:
                return {"breached": False, "breach_count": 0, "breaches": []}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}

    # Hunter.io
    def hunter_verify(self, email):
        api_key = self.config.get('hunter_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Hunter.io non configurata"}
        
        url = "https://api.hunter.io/v2/email-verifier"
        params = {'email': email, 'api_key': api_key}
        
        try:
            response = self.session.get(url, params=params, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Hunter.io: {str(e)}"}

    def hunter_domain_search(self, domain):
        api_key = self.config.get('hunter_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Hunter.io non configurata"}
        
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Hunter.io domain search: {str(e)}"}

    # UnwiredLabs GSM
    def unwiredlabs_gsm_geolocation(self, mcc, mnc, lac, cid, signal=None, additional_towers=None):
        api_key = self.config.get('unwiredlabs_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key UnwiredLabs non configurata"}
        
        url = "https://us1.unwiredlabs.com/v2/process.php"
        
        main_cell = {
            "mcc": mcc,
            "mnc": mnc,
            "lac": lac,
            "cid": cid
        }
        
        if signal is not None:
            main_cell["signal"] = signal
        
        payload = {
            "token": api_key,
            "radio": "gsm",
            "cells": [main_cell],
            "address": 1
        }
        
        if additional_towers and isinstance(additional_towers, list):
            payload["cells"].extend(additional_towers)
        
        try:
            response = self.session.post(url, json=payload, timeout=20)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('status') == 'ok':
                    return {
                        "status": "success",
                        "latitude": result.get('lat'),
                        "longitude": result.get('lon'),
                        "accuracy": result.get('accuracy'),
                        "address": result.get('address'),
                        "balance": result.get('balance'),
                    }
                else:
                    error_msg = result.get('message', 'Unknown error from UnwiredLabs')
                    return {"error": error_msg, "status": "error"}
            else:
                return {"error": f"HTTP error {response.status_code}"}
                
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    # IPInfo.io
    def ipinfo_lookup(self, ip):
        api_key = self.config.get('ipinfo_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key IPInfo.io non configurata"}
        
        url = f"https://ipinfo.io/{ip}/json?token={api_key}"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore IPInfo.io: {str(e)}"}

    # AlienVault OTX
    def alienvault_domain(self, domain):
        api_key = self.config.get('alienvault_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key AlienVault OTX non configurata"}
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore AlienVault OTX: {str(e)}"}

    def alienvault_ip(self, ip):
        api_key = self.config.get('alienvault_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key AlienVault OTX non configurata"}
        
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore AlienVault OTX IP: {str(e)}"}

    def alienvault_related(self, domain):
        api_key = self.config.get('alienvault_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key AlienVault OTX non configurata"}
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        headers = {'X-OTX-API-KEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore AlienVault OTX related: {str(e)}"}

    # GreyNoise
    def greynoise_ip(self, ip):
        api_key = self.config.get('greynoise_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key GreyNoise non configurata"}
        
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            'key': api_key,
            'User-Agent': 'MS17-OSINT/3.0'
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"status": "not_found", "message": "IP non trovato in GreyNoise"}
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore GreyNoise: {str(e)}"}

    # Whoxy
    def whoxy_whois(self, domain):
        api_key = self.config.get('whoxy_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Whoxy non configurata"}
        
        url = f"https://api.whoxy.com/?key={api_key}&whois={domain}"
        
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Whoxy: {str(e)}"}

    # SecurityTrails
    def securitytrails_domain(self, domain):
        api_key = self.config.get('securitytrails_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key SecurityTrails non configurata"}
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {'APIKEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore SecurityTrails: {str(e)}"}

    def securitytrails_subdomains(self, domain):
        api_key = self.config.get('securitytrails_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key SecurityTrails non configurata"}
        
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'APIKEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore SecurityTrails subdomains: {str(e)}"}

    def securitytrails_dns_history(self, domain, record_type="a"):
        api_key = self.config.get('securitytrails_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key SecurityTrails non configurata"}
        
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}"
        headers = {'APIKEY': api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore SecurityTrails DNS history: {str(e)}"}

    # CIRCL PDNS
    def circl_pdns_lookup(self, query):
        api_user = self.config.get('circl_api_user')
        api_pass = self.config.get('circl_api_pass')
        
        if not api_user or not api_pass or api_user.startswith('TUO_'):
            return {"error": "Credenziali CIRCL non configurate"}
        
        url = f"https://www.circl.lu/pdns/query/{query}"
        auth = (api_user, api_pass)
        
        try:
            response = self.session.get(url, auth=auth, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore CIRCL PDNS: {str(e)}"}

    # Leak-Lookup
    def leaklookup_check(self, email):
        api_key = self.config.get('leaklookup_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key Leak-Lookup non configurata"}
        
        url = "https://leak-lookup.com/api/search"
        headers = {'Content-Type': 'application/json'}
        payload = {
            'key': api_key,
            'type': 'email_address',
            'query': email
        }
        
        try:
            response = self.session.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore Leak-Lookup: {str(e)}"}

    # DeHashed
    def dehashed_search(self, email):
        api_key = self.config.get('dehashed_api_key')
        email_auth = self.config.get('dehashed_email')
        
        if not api_key or not email_auth or api_key.startswith('TUO_'):
            return {"error": "Credenziali DeHashed non configurate"}
        
        url = f"https://api.dehashed.com/search?query=email:{email}"
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {base64.b64encode(f"{email_auth}:{api_key}".encode()).decode()}'
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore DeHashed: {str(e)}"}

    def dehashed_search_advanced(self, query, type="email"):
        api_key = self.config.get('dehashed_api_key')
        email_auth = self.config.get('dehashed_email')
        
        if not api_key or not email_auth or api_key.startswith('TUO_'):
            return {"error": "Credenziali DeHashed non configurate"}
        
        url = "https://api.dehashed.com/search"
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {base64.b64encode(f"{email_auth}:{api_key}".encode()).decode()}'
        }
        params = {
            'query': f'{type}:"{query}"'
        }
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                response.raise_for_status()
        except Exception as e:
            return {"error": f"Errore DeHashed advanced: {str(e)}"}

    # === ANALISI DOMINIO AVANZATA ===
    def advanced_domain_intel(self, domain):
        """Analisi dominio avanzata con tutte le API integrate"""
        if not self.validate_input(domain, 'domain'):
            return {"error": "Dominio non valido"}

        self.logger.info("Avvio analisi dominio avanzata: %s", domain)
        domain_data = {'domain': domain}
        
        # WHOIS avanzato
        domain_data['whois'] = self.advanced_whois_lookup(domain)
        
        # DNS ricognizione avanzata
        domain_data['dns'] = self.advanced_dns_recon(domain)
        
        # SSL/TLS analisi avanzata
        domain_data['ssl'] = self.advanced_ssl_analysis(domain)
        
        # Subdomain enumeration
        domain_data['subdomains'] = self.enumerate_subdomains(domain)
        
        # Tecnologie web
        domain_data['technologies'] = self.detect_technologies(domain)
        
        # Security headers
        domain_data['security_headers'] = self.check_security_headers(domain)
        
        # === INTEGRAZIONE DI TUTTE LE API ===
        
        # VirusTotal
        if self.config.get('virustotal_api_key'):
            domain_data['virustotal'] = self.safe_api_call(self.virustotal_domain, domain)
        
        # SecurityTrails - Completa
        if self.config.get('securitytrails_api_key'):
            domain_data['securitytrails'] = {
                'domain_info': self.safe_api_call(self.securitytrails_domain, domain),
                'subdomains': self.safe_api_call(self.securitytrails_subdomains, domain),
                'dns_history': self.safe_api_call(self.securitytrails_dns_history, domain, 'a')
            }
        
        # AlienVault OTX - Completa
        if self.config.get('alienvault_api_key'):
            domain_data['alienvault'] = {
                'general': self.safe_api_call(self.alienvault_domain, domain),
                'related': self.safe_api_call(self.alienvault_related, domain)
            }
        
        # CIRCL Passive DNS
        if self.config.get('circl_api_user') and self.config.get('circl_api_pass'):
            domain_data['circl_pdns'] = self.safe_api_call(self.circl_pdns_lookup, domain)
        
        # Hunter.io per email discovery
        if self.config.get('hunter_api_key'):
            domain_data['hunter'] = self.safe_api_call(self.hunter_domain_search, domain)
        
        # Whoxy WHOIS esteso
        if self.config.get('whoxy_api_key'):
            domain_data['whoxy'] = self.safe_api_call(self.whoxy_whois, domain)
        
        # Shodan per dominio
        if self.config.get('shodan_api_key'):
            domain_data['shodan'] = self.safe_api_call(self.shodan_domain, domain)
        
        # Historical data
        domain_data['historical'] = self.get_historical_data(domain)
        
        self.results['domain'] = domain_data
        
        # Display risultati in terminale
        self.display_domain_results(domain_data)
        
        return domain_data

    def display_domain_results(self, domain_data):
        """Mostra i risultati del dominio nel terminale"""
        print("\n" + "="*80)
        print(f"📊 RISULTATI DOMINIO: {domain_data.get('domain', 'N/A')}")
        print("="*80)
        
        # WHOIS Info
        if domain_data.get('whois', {}).get('standard'):
            whois_info = domain_data['whois']['standard']
            print("\n🔍 INFORMAZIONI WHOIS:")
            print(f"   Registrar: {whois_info.get('registrar', 'N/A')}")
            print(f"   Data creazione: {whois_info.get('creation_date', 'N/A')}")
            print(f"   Data scadenza: {whois_info.get('expiration_date', 'N/A')}")
        
        # DNS Records
        if domain_data.get('dns'):
            print("\n🌐 RECORD DNS:")
            for record_type, records in domain_data['dns'].items():
                if records and record_type in ['A', 'AAAA', 'MX', 'NS'] and len(records) > 0:
                    print(f"   {record_type}: {', '.join(records[:3])}" + ("..." if len(records) > 3 else ""))
        
        # Subdomains
        if domain_data.get('subdomains'):
            print(f"\n🔗 SUBDOMINI TROVATI ({len(domain_data['subdomains'])}):")
            for subdomain in domain_data['subdomains'][:5]:
                print(f"   - {subdomain}")
            if len(domain_data['subdomains']) > 5:
                print(f"   ... e {len(domain_data['subdomains']) - 5} altri")
        
        # Technologies
        if domain_data.get('technologies'):
            tech_count = len([k for k, v in domain_data['technologies'].items() if v is True])
            print(f"\n🛠️  TECNOLOGIE RILEVATE: {tech_count}")
        
        # VirusTotal
        if domain_data.get('virustotal') and not domain_data['virustotal'].get('error'):
            vt_data = domain_data['virustotal'].get('data', {})
            attributes = vt_data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            print(f"\n🛡️  VIRUSTOTAL:")
            print(f"   Malevoli: {stats.get('malicious', 0)}")
            print(f"   Sospetti: {stats.get('suspicious', 0)}")
            print(f"   Puliti: {stats.get('harmless', 0)}")
        
        # SecurityTrails
        if domain_data.get('securitytrails', {}).get('domain_info') and not domain_data['securitytrails']['domain_info'].get('error'):
            print(f"\n🔐 SECURITYTRAILS:")
            st_data = domain_data['securitytrails']['domain_info']
            if st_data.get('current_dns'):
                dns_records = st_data['current_dns']
                for record_type in ['a', 'mx', 'ns']:
                    if dns_records.get(record_type):
                        print(f"   {record_type.upper()}: {len(dns_records[record_type])} records")
        
        print("="*80)

    def advanced_whois_lookup(self, domain):
        """WHOIS lookup avanzato con multiple fonti"""
        whois_data = {}
        
        try:
            # WHOIS standard
            whois_info = whois.whois(domain)
            whois_data['standard'] = {
                'registrar': str(whois_info.registrar) if whois_info.registrar else "N/A",
                'creation_date': str(whois_info.creation_date) if whois_info.creation_date else "N/A",
                'expiration_date': str(whois_info.expiration_date) if whois_info.expiration_date else "N/A",
                'updated_date': str(whois_info.updated_date) if whois_info.updated_date else "N/A",
                'name_servers': list(whois_info.name_servers) if whois_info.name_servers else [],
                'status': list(whois_info.status) if whois_info.status else [],
                'emails': list(whois_info.emails) if whois_info.emails else []
            }
            
            # WHOIS esteso con API
            if self.config.get('whoxy_api_key'):
                whois_data['extended'] = self.safe_api_call(self.whoxy_whois, domain)
                
        except Exception as e:
            self.logger.error("Errore WHOIS avanzato per %s: %s", domain, e)
            whois_data['error'] = str(e)
        
        return whois_data

    def advanced_dns_recon(self, domain):
        """Ricognizione DNS avanzata"""
        dns_data = {}
        
        try:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                    dns_data[rtype] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                    dns_data[rtype] = []
                except Exception as e:
                    dns_data[rtype] = [f"Error: {str(e)}"]
            
            # DNS bruteforce per record non comuni
            if self.config.get('deep_scan', False):
                dns_data['deep_scan'] = self.dns_bruteforce(domain)
                
        except Exception as e:
            self.logger.error("Errore DNS ricognizione per %s: %s", domain, e)
            dns_data['error'] = str(e)
        
        return dns_data

    def dns_bruteforce(self, domain):
        """Bruteforce DNS per record nascosti"""
        common_records = {
            '_dmarc': 'TXT',
            '_domainkey': 'TXT', 
            '_acme-challenge': 'TXT',
            'autodiscover': 'CNAME',
        }
        
        results = {}
        for subdomain, rtype in common_records.items():
            try:
                full_domain = f"{subdomain}.{domain}"
                answers = dns.resolver.resolve(full_domain, rtype, lifetime=5)
                results[full_domain] = [str(rdata) for rdata in answers]
            except:
                continue
                
        return results

    def advanced_ssl_analysis(self, domain):
        """Analisi SSL/TLS avanzata"""
        ssl_data = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_data = {
                        'subject': self._parse_cert_field(cert.get('subject', [])),
                        'issuer': self._parse_cert_field(cert.get('issuer', [])),
                        'not_before': cert.get('notBefore', 'N/A'),
                        'not_after': cert.get('notAfter', 'N/A'),
                        'cipher': {
                            'name': cipher[0] if cipher else 'N/A',
                            'version': cipher[1] if cipher else 'N/A',
                        },
                    }
                    
        except Exception as e:
            self.logger.error("Errore analisi SSL per %s: %s", domain, e)
            ssl_data['error'] = str(e)
        
        return ssl_data

    def enumerate_subdomains(self, domain):
        """Enumerazione subdomain con multiple wordlist"""
        self.logger.info("Enumerazione subdomains per %s", domain)
        subdomains = set()
        
        # Wordlist integrata
        common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'admin', 'blog',
            'forum', 'news', 'shop', 'api', 'cdn', 'dev', 'test', 'staging', 'mobile',
            'secure', 'portal', 'cpanel', 'whm', 'webdisk', 'ns1', 'ns2', 'ns3',
            'remote', 'vpn', 'ftp', 'ssh', 'monitor', 'stats', 'status'
        ]
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
            except:
                pass
        
        # Scansione parallela
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(check_subdomain, common_subs)
        
        return list(subdomains)

    def detect_technologies(self, domain):
        """Rilevamento tecnologie web avanzato"""
        technologies = {}
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text.lower()
            headers = response.headers
            
            # Analisi headers
            server = headers.get('Server', '')
            if server:
                technologies['server'] = server
            
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                technologies['powered_by'] = powered_by
            
            # Pattern matching per tecnologie
            tech_patterns = {
                'wordpress': ['wp-content', 'wordpress', 'wp-json'],
                'joomla': ['joomla', 'com_joomla'],
                'drupal': ['drupal', 'sites/all'],
                'react': ['react', 'reactjs'],
                'angular': ['angular'],
                'nginx': ['nginx'],
                'apache': ['apache', 'httpd'],
                'cloudflare': ['cloudflare'],
                'php': ['php', '.php'],
                'asp_net': ['asp.net', '__viewstate'],
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        technologies[tech] = True
                        break
                        
        except Exception as e:
            self.logger.error("Errore rilevamento tecnologie per %s: %s", domain, e)
            technologies['error'] = str(e)
        
        return technologies

    def check_security_headers(self, domain):
        """Controllo header di sicurezza avanzato"""
        security_headers = {}
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10, verify=False)
            
            security_checks = {
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
            }
            
            for header, value in security_checks.items():
                security_headers[header] = {
                    'present': value is not None,
                    'value': value,
                }
                
        except Exception as e:
            self.logger.error("Errore controllo security headers per %s: %s", domain, e)
            security_headers['error'] = str(e)
        
        return security_headers

    def get_historical_data(self, domain):
        """Recupera dati storici del dominio"""
        historical = {}
        
        try:
            # Wayback Machine
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey&limit=5"
            response = self.session.get(wayback_url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    historical['wayback'] = [
                        {'timestamp': row[1], 'url': row[2]} 
                        for row in data[1:4]  # Primi 3 risultati
                    ]
        except:
            pass
            
        return historical

    # === ANALISI IP AVANZATA ===
    def advanced_ip_intel(self, ip):
        """Analisi IP avanzata con tutte le API integrate"""
        if not self.validate_input(ip, 'ip'):
            return {"error": "IP non valido"}

        self.logger.info("Avvio analisi IP avanzata: %s", ip)
        ip_data = {'ip': ip}
        
        # Geolocalizzazione multi-source
        ip_data['geolocation'] = self.multi_source_geolocation(ip)
        
        # Threat intelligence completa
        ip_data['threat_intel'] = self.threat_intelligence_ip(ip)
        
        # Port scanning (light)
        ip_data['ports'] = self.quick_port_scan(ip)
        
        # Reverse DNS e PTR
        ip_data['dns'] = self.advanced_reverse_dns(ip)
        
        # === INTEGRAZIONE DI TUTTE LE API ===
        
        # VirusTotal
        if self.config.get('virustotal_api_key'):
            ip_data['virustotal'] = self.safe_api_call(self.virustotal_ip, ip)
        
        # Shodan
        if self.config.get('shodan_api_key'):
            ip_data['shodan'] = self.safe_api_call(self.shodan_ip_lookup, ip)
        
        # AbuseIPDB
        if self.config.get('abuseipdb_api_key'):
            ip_data['abuseipdb'] = self.safe_api_call(self.abuseipdb_check, ip)
        
        # GreyNoise
        if self.config.get('greynoise_api_key'):
            ip_data['greynoise'] = self.safe_api_call(self.greynoise_ip, ip)
        
        # AlienVault OTX
        if self.config.get('alienvault_api_key'):
            ip_data['alienvault'] = self.safe_api_call(self.alienvault_ip, ip)
        
        # IPInfo.io
        if self.config.get('ipinfo_api_key'):
            ip_data['ipinfo'] = self.safe_api_call(self.ipinfo_lookup, ip)
        
        # CIRCL Passive DNS
        if self.config.get('circl_api_user') and self.config.get('circl_api_pass'):
            ip_data['circl_pdns'] = self.safe_api_call(self.circl_pdns_lookup, ip)
        
        self.results['ip'] = ip_data
        
        # Display risultati in terminale
        self.display_ip_results(ip_data)
        
        return ip_data

    def display_ip_results(self, ip_data):
        """Mostra i risultati dell'IP nel terminale"""
        print("\n" + "="*80)
        print(f"📍 RISULTATI IP: {ip_data.get('ip', 'N/A')}")
        print("="*80)
        
        # Geolocation
        if ip_data.get('geolocation', {}).get('ip-api'):
            geo = ip_data['geolocation']['ip-api']
            if geo.get('status') == 'success':
                print("\n🌍 GEOLOCALIZZAZIONE:")
                print(f"   Paese: {geo.get('country', 'N/A')}")
                print(f"   Città: {geo.get('city', 'N/A')}")
                print(f"   ISP: {geo.get('isp', 'N/A')}")
                print(f"   Coordinate: {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}")
        
        # Porte aperte
        if ip_data.get('ports'):
            print(f"\n🔓 PORTE APERTE ({len(ip_data['ports'])}):")
            for port_info in ip_data['ports'][:8]:
                print(f"   Porta {port_info['port']} ({port_info.get('service', 'unknown')})")
        
        # Shodan
        if ip_data.get('shodan') and not ip_data['shodan'].get('error'):
            shodan_data = ip_data['shodan']
            print(f"\n🔍 SHODAN:")
            if shodan_data.get('ports'):
                print(f"   Porte: {', '.join(map(str, shodan_data['ports'][:6]))}")
            if shodan_data.get('vulns'):
                print(f"   Vulnerabilità: {len(shodan_data['vulns'])}")
        
        # AbuseIPDB
        if ip_data.get('abuseipdb') and not ip_data['abuseipdb'].get('error'):
            abuse_data = ip_data['abuseipdb'].get('data', {})
            print(f"\n⚠️  ABUSEIPDB:")
            print(f"   Confidence: {abuse_data.get('abuseConfidenceScore', 'N/A')}%")
            print(f"   Utilizzo: {abuse_data.get('usageType', 'N/A')}")
        
        # VirusTotal
        if ip_data.get('virustotal') and not ip_data['virustotal'].get('error'):
            vt_data = ip_data['virustotal'].get('data', {})
            attributes = vt_data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            print(f"\n🛡️  VIRUSTOTAL:")
            print(f"   Malevoli: {stats.get('malicious', 0)}")
            print(f"   Sospetti: {stats.get('suspicious', 0)}")
        
        # GreyNoise
        if ip_data.get('greynoise') and not ip_data['greynoise'].get('error'):
            gn_data = ip_data['greynoise']
            print(f"\n🌫️  GREYNOISE:")
            if gn_data.get('classification'):
                print(f"   Classificazione: {gn_data.get('classification', 'N/A')}")
            if gn_data.get('name'):
                print(f"   Nome: {gn_data.get('name', 'N/A')}")
        
        print("="*80)

    def multi_source_geolocation(self, ip):
        """Geolocalizzazione da multiple fonti"""
        geolocation = {}
        
        sources = [
            ('ip-api', f'http://ip-api.com/json/{ip}'),
        ]
        
        # IPInfo.io se configurato
        if self.config.get('ipinfo_api_key'):
            ipinfo_data = self.safe_api_call(self.ipinfo_lookup, ip)
            if ipinfo_data and not ipinfo_data.get('error'):
                geolocation['ipinfo'] = ipinfo_data
        
        for source_name, url in sources:
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    geolocation[source_name] = response.json()
            except:
                continue
                
        return geolocation

    def threat_intelligence_ip(self, ip):
        """Threat intelligence multi-source completa per IP"""
        threat_data = {}
        
        # AlienVault OTX
        if self.config.get('alienvault_api_key'):
            threat_data['alienvault'] = self.safe_api_call(self.alienvault_ip, ip)
        
        # GreyNoise
        if self.config.get('greynoise_api_key'):
            threat_data['greynoise'] = self.safe_api_call(self.greynoise_ip, ip)
        
        # CIRCL Passive DNS
        if self.config.get('circl_api_user') and self.config.get('circl_api_pass'):
            threat_data['circl_pdns'] = self.safe_api_call(self.circl_pdns_lookup, ip)
        
        # VirusTotal
        if self.config.get('virustotal_api_key'):
            threat_data['virustotal'] = self.safe_api_call(self.virustotal_ip, ip)
        
        # AbuseIPDB
        if self.config.get('abuseipdb_api_key'):
            threat_data['abuseipdb'] = self.safe_api_call(self.abuseipdb_check, ip)
        
        return threat_data

    def quick_port_scan(self, ip):
        """Scansione porte veloce per servizi comuni"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443]
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = 'unknown'
                        open_ports.append({'port': port, 'service': service})
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_port, common_ports)
        
        return open_ports

    def advanced_reverse_dns(self, ip):
        """Reverse DNS avanzato"""
        dns_info = {}
        
        try:
            # PTR record
            hostname = socket.gethostbyaddr(ip)[0]
            dns_info['ptr'] = hostname
                
        except (socket.herror, socket.gaierror):
            dns_info['ptr'] = "N/A"
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info

    # === GEOLOCALIZZAZIONE GSM AVANZATA ===
    def advanced_gsm_geolocation(self, mcc, mnc, lac, cid, signal=None, towers_data=None):
        """Geolocalizzazione GSM avanzata"""
        self.logger.info("Avvio geolocalizzazione GSM avanzata: MCC=%s, MNC=%s, LAC=%s, CID=%s", mcc, mnc, lac, cid)
        gsm_data = {}
        
        # Informazioni operatore
        gsm_data['operator'] = self.get_gsm_operator_info(mcc, mnc)
        
        # Geolocalizzazione con UnwiredLabs
        if self.config.get('unwiredlabs_api_key'):
            gsm_data['unwiredlabs'] = self.safe_api_call(self.unwiredlabs_gsm_geolocation, mcc, mnc, lac, cid, signal, towers_data)
        
        # Stima accuratezza
        gsm_data['accuracy_estimate'] = self.estimate_accuracy(gsm_data)
        
        self.results['gsm_geolocation'] = gsm_data
        
        # Display risultati in terminale
        self.display_gsm_results(gsm_data)
        
        return gsm_data

    def display_gsm_results(self, gsm_data):
        """Mostra i risultati GSM nel terminale"""
        print("\n" + "="*80)
        print("📡 RISULTATI GEOLOCALIZZAZIONE GSM")
        print("="*80)
        
        # Operatore
        if gsm_data.get('operator'):
            op = gsm_data['operator']
            print(f"\n📞 OPERATORE:")
            print(f"   Nome: {op.get('operator', 'N/A')}")
            print(f"   Paese: {op.get('country', 'N/A')}")
            print(f"   Rete: {op.get('network', 'N/A')}")
        
        # UnwiredLabs
        if gsm_data.get('unwiredlabs') and gsm_data['unwiredlabs'].get('status') == 'success':
            geo = gsm_data['unwiredlabs']
            print(f"\n📍 POSIZIONE:")
            print(f"   Latitudine: {geo.get('latitude', 'N/A')}")
            print(f"   Longitudine: {geo.get('longitude', 'N/A')}")
            print(f"   Accuratezza: {geo.get('accuracy', 'N/A')} metri")
            if geo.get('address'):
                print(f"   Indirizzo: {geo.get('address', 'N/A')}")
        
        # Accuratezza
        if gsm_data.get('accuracy_estimate'):
            acc = gsm_data['accuracy_estimate']
            print(f"\n🎯 STIMA ACCURATEZZA:")
            print(f"   Livello: {acc.get('estimate', 'N/A')}")
            print(f"   Confidence: {acc.get('confidence', 'N/A')}")
        
        print("="*80)

    def get_gsm_operator_info(self, mcc, mnc):
        """Database operatori GSM avanzato"""
        operators_db = {
            # Italia
            "22201": {"operator": "TIM", "country": "Italy", "network": "GSM/UMTS/LTE"},
            "22210": {"operator": "Vodafone", "country": "Italy", "network": "GSM/UMTS/LTE"},
            "22288": {"operator": "Wind", "country": "Italy", "network": "GSM/UMTS/LTE"},
            "22299": {"operator": "3 Italia", "country": "Italy", "network": "UMTS/LTE"},
            # USA
            "310260": {"operator": "T-Mobile", "country": "USA", "network": "GSM/UMTS/LTE"},
            "310410": {"operator": "AT&T", "country": "USA", "network": "GSM/UMTS/LTE"},
            "311480": {"operator": "Verizon", "country": "USA", "network": "CDMA/LTE"},
        }
        
        operator_key = f"{mcc}{mnc:02d}"
        return operators_db.get(operator_key, {
            "operator": "Unknown",
            "country": "Unknown", 
            "network": "Unknown",
        })

    def estimate_accuracy(self, gsm_data):
        """Stima accuratezza basata su dati disponibili"""
        accuracy = {
            'estimate': 'Unknown',
            'confidence': 'Low',
            'factors': []
        }
        
        # Controlla UnwiredLabs
        if 'unwiredlabs' in gsm_data and gsm_data['unwiredlabs'].get('status') == 'success':
            accuracy['factors'].append('UnwiredLabs')
            accuracy['confidence'] = 'High'
            acc_value = gsm_data['unwiredlabs'].get('accuracy')
            if acc_value and acc_value != 'N/A':
                if acc_value <= 100:
                    accuracy['estimate'] = 'High (<= 100m)'
                elif acc_value <= 500:
                    accuracy['estimate'] = 'Medium (100-500m)'
                else:
                    accuracy['estimate'] = 'Low (500m+)'
        
        return accuracy

    def parse_gsm_data_from_string(self, gsm_string):
        """Parsa stringhe GSM in formati multipli"""
        try:
            gsm_string = gsm_string.strip().lower()
            
            # Pattern 1: mcc:222,mnc:1,lac:1234,cid:5678
            if 'mcc' in gsm_string:
                mcc = int(re.search(r'mcc:(\d+)', gsm_string).group(1))
                mnc = int(re.search(r'mnc:(\d+)', gsm_string).group(1))
                lac = int(re.search(r'lac:(\d+)', gsm_string).group(1))
                cid = int(re.search(r'cid:(\d+)', gsm_string).group(1))
                
            # Pattern 2: 222-1-1234-5678
            elif '-' in gsm_string:
                parts = gsm_string.split('-')
                mcc, mnc, lac, cid = map(int, parts[:4])
                
            # Pattern 3: 222,1,1234,5678
            elif ',' in gsm_string:
                parts = gsm_string.split(',')
                mcc, mnc, lac, cid = map(int, parts[:4])
                
            else:
                raise ValueError("Formato dati GSM non riconosciuto")
            
            return mcc, mnc, lac, cid
            
        except Exception as e:
            self.logger.error("Errore parsing dati GSM: %s", e)
            raise ValueError(f"Formato dati GSM non valido: {e}")

    # === ANALISI EMAIL AVANZATA ===
    def advanced_email_intel(self, email):
        """Analisi email avanzata con tutte le API integrate"""
        if not self.validate_input(email, 'email'):
            return {"error": "Email non valida"}

        self.logger.info("Avvio analisi email avanzata: %s", email)
        email_data = {'email': email}
        
        # Validazione avanzata
        email_data['validation'] = self.advanced_email_validation(email)
        
        # Breach checking multi-source completa
        email_data['breaches'] = self.multi_source_breach_check(email)
        
        # Social media discovery
        email_data['social_discovery'] = self.email_social_discovery(email)
        
        # === INTEGRAZIONE DI TUTTE LE API ===
        
        # Have I Been Pwned
        if self.config.get('hibp_api_key'):
            email_data['hibp'] = self.safe_api_call(self.hibp_breach_check, email)
        
        # Leak-Lookup
        if self.config.get('leaklookup_api_key'):
            email_data['leaklookup'] = self.safe_api_call(self.leaklookup_check, email)
        
        # DeHashed - Ricerca avanzata
        if self.config.get('dehashed_api_key') and self.config.get('dehashed_email'):
            email_data['dehashed'] = self.safe_api_call(self.dehashed_search, email)
        
        # Hunter.io verifica email
        if self.config.get('hunter_api_key'):
            email_data['hunter'] = self.safe_api_call(self.hunter_verify, email)
        
        # Email reputation
        email_data['reputation'] = self.email_reputation_check(email)
        
        self.results['email'] = email_data
        
        # Display risultati in terminale
        self.display_email_results(email_data)
        
        return email_data

    def display_email_results(self, email_data):
        """Mostra i risultati dell'email nel terminale"""
        print("\n" + "="*80)
        print(f"📧 RISULTATI EMAIL: {email_data.get('email', 'N/A')}")
        print("="*80)
        
        # Validazione
        if email_data.get('validation'):
            val = email_data['validation']
            print(f"\n✅ VALIDAZIONE:")
            print(f"   Formato valido: {'Sì' if val.get('format_valid') else 'No'}")
            print(f"   MX valido: {'Sì' if val.get('mx_valid') else 'No'}")
            print(f"   Dominio: {val.get('domain', 'N/A')}")
        
        # Breaches
        if email_data.get('breaches', {}).get('hibp'):
            hibp = email_data['breaches']['hibp']
            if not hibp.get('error'):
                status = "SÌ" if hibp.get('breached') else "NO"
                print(f"\n🔓 HIBP - ACCOUNT COMPROMESSO: {status}")
                if hibp.get('breached'):
                    print(f"   Numero breach: {hibp.get('breach_count', 0)}")
        
        # DeHashed
        if email_data.get('dehashed') and not email_data['dehashed'].get('error'):
            dehashed_data = email_data['dehashed']
            if dehashed_data.get('total'):
                print(f"\n🔐 DEHASHED:")
                print(f"   Record trovati: {dehashed_data.get('total', 0)}")
        
        # Reputazione
        if email_data.get('reputation'):
            rep = email_data['reputation']
            print(f"\n⭐ REPUTAZIONE:")
            print(f"   Score: {rep.get('score', 0)}/100")
            print(f"   Rating: {rep.get('rating', 'N/A')}")
        
        print("="*80)

    def advanced_email_validation(self, email):
        """Validazione email avanzata"""
        validation = self.validate_email_format(email)
        
        # Controllo dominio
        domain = email.split('@')[1]
        validation['domain_analysis'] = self.analyze_email_domain(domain)
        
        # Disposable email check
        validation['is_disposable'] = self.check_disposable_email(domain)
        
        return validation

    def validate_email_format(self, email):
        """Validazione formato email"""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,64}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(pattern, email))
        
        domain = email.split('@')[1] if '@' in email else None
        mx_valid = False
        
        if domain and is_valid:
            try:
                dns.resolver.resolve(domain, 'MX', lifetime=10)
                mx_valid = True
            except:
                mx_valid = False
        
        return {
            'format_valid': is_valid,
            'mx_valid': mx_valid,
            'domain': domain,
        }

    def analyze_email_domain(self, domain):
        """Analisi dominio email"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = [str(rdata.exchange) for rdata in mx_records]
            
            return {
                'mx_servers': mx_servers,
                'has_mx': len(mx_servers) > 0,
                'common_provider': self.check_email_provider(domain)
            }
        except:
            return {'mx_servers': [], 'has_mx': False, 'common_provider': False}

    def check_email_provider(self, domain):
        """Verifica provider email comune"""
        common_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'protonmail.com', 'icloud.com'
        ]
        return domain.lower() in common_providers

    def check_disposable_email(self, domain):
        """Verifica email disposable/temporanea"""
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'mailinator.com',
            'yopmail.com', 'throwawaymail.com'
        ]
        return domain.lower() in disposable_domains

    def multi_source_breach_check(self, email):
        """Controllo breach da tutte le fonti disponibili"""
        breaches = {}
        
        # Have I Been Pwned
        if self.config.get('hibp_api_key'):
            breaches['hibp'] = self.safe_api_call(self.hibp_breach_check, email)
        
        # Leak-Lookup
        if self.config.get('leaklookup_api_key'):
            breaches['leaklookup'] = self.safe_api_call(self.leaklookup_check, email)
        
        # DeHashed
        if self.config.get('dehashed_api_key') and self.config.get('dehashed_email'):
            breaches['dehashed'] = self.safe_api_call(self.dehashed_search, email)
        
        return breaches

    def email_social_discovery(self, email):
        """Scopri social media associati all'email"""
        social_data = {}
        
        # Ricerca su piattaforme comuni
        platforms = {
            'gravatar': f'https://www.gravatar.com/{hashlib.md5(email.lower().encode()).hexdigest()}.json',
        }
        
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('entry'):
                        social_data[platform] = {'exists': True, 'profile': data['entry'][0]}
            except:
                continue
        
        return social_data

    def email_reputation_check(self, email):
        """Controllo reputazione email"""
        reputation = {
            'score': 50,  # Score neutrale di partenza
            'factors': []
        }
        
        validation = self.validate_email_format(email)
        
        if validation.get('format_valid'):
            reputation['score'] += 20
            reputation['factors'].append('Formato valido')
        
        if validation.get('mx_valid'):
            reputation['score'] += 20
            reputation['factors'].append('MX records validi')
        
        if not self.check_disposable_email(validation.get('domain', '')):
            reputation['score'] += 15
            reputation['factors'].append('Dominio non disposable')
        else:
            reputation['score'] -= 30
            reputation['factors'].append('Dominio disposable - Alta probabilità spam')
        
        if self.check_email_provider(validation.get('domain', '')):
            reputation['score'] += 10
            reputation['factors'].append('Provider affidabile')
        
        # Normalizza score tra 0-100
        reputation['score'] = max(0, min(100, reputation['score']))
        
        if reputation['score'] >= 80:
            reputation['rating'] = 'Excellent'
        elif reputation['score'] >= 60:
            reputation['rating'] = 'Good'
        elif reputation['score'] >= 40:
            reputation['rating'] = 'Fair'
        else:
            reputation['rating'] = 'Poor'
        
        return reputation

    # === ANALISI SOCIAL MEDIA AVANZATA ===
    def advanced_social_intel(self, username):
        """Analisi social media avanzata"""
        if not self.validate_input(username, 'username'):
            return {"error": "Username non valido"}

        self.logger.info("Avvio analisi social avanzata: %s", username)
        social_data = {}
        
        # Piattaforme estese
        platforms = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'youtube': f'https://youtube.com/@{username}',
        }
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_platform = {
                executor.submit(self.advanced_social_check, platform, url, username): platform 
                for platform, url in platforms.items()
            }
            
            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    result = future.result(timeout=10)
                    social_data[platform] = result
                    
                    if result.get('exists'):
                        self.logger.info("Profilo trovato su %s", platform.upper())
                        
                except Exception as e:
                    social_data[platform] = {'exists': False, 'error': str(e)}
        
        # Analisi aggregata
        social_data['summary'] = self.analyze_social_presence(social_data)
        
        self.results['social'] = social_data
        
        # Display risultati in terminale
        self.display_social_results(social_data, username)
        
        return social_data

    def display_social_results(self, social_data, username):
        """Mostra i risultati social nel terminale"""
        print("\n" + "="*80)
        print(f"👤 RISULTATI SOCIAL: {username}")
        print("="*80)
        
        # Summary
        if social_data.get('summary'):
            summary = social_data['summary']
            print(f"\n📊 RIEPILOGO:")
            print(f"   Piattaforme trovate: {summary.get('platforms_found', 0)}")
            print(f"   Confidence: {summary.get('confidence_score', 0)}%")
            print(f"   Tipo persona: {summary.get('persona_type', 'N/A')}")
        
        # Piattaforme trovate
        found_platforms = [p for p, d in social_data.items() if p != 'summary' and d.get('exists')]
        if found_platforms:
            print(f"\n✅ PROFILI TROVATI:")
            for platform in found_platforms:
                platform_data = social_data[platform]
                print(f"   - {platform.upper()}: {platform_data.get('url', 'N/A')}")
        else:
            print(f"\n❌ Nessun profilo trovato per {username}")
        
        print("="*80)

    def advanced_social_check(self, platform, url, username):
        """Verifica avanzata presenza su piattaforma sociale"""
        try:
            headers = {
                'User-Agent': self.ua.random,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            }
            
            response = self.session.head(url, timeout=10, allow_redirects=True, headers=headers)
            
            exists = False
            final_url = response.url
            
            # Logica specifica per piattaforma
            if platform == 'github':
                exists = response.status_code == 200 and 'github.com' in final_url and username in final_url
            elif platform == 'reddit':
                exists = response.status_code == 200 and 'reddit.com/user' in final_url and username in final_url
            elif platform == 'twitter':
                exists = response.status_code == 200 and 'twitter.com' in final_url and username in final_url
            elif platform == 'instagram':
                exists = response.status_code == 200 and 'instagram.com' in final_url and username in final_url
            elif platform == 'facebook':
                exists = response.status_code == 200 and 'facebook.com' in final_url and username in final_url
            elif platform == 'linkedin':
                exists = response.status_code == 200 and 'linkedin.com' in final_url and username in final_url
            elif platform == 'youtube':
                exists = response.status_code == 200 and 'youtube.com' in final_url and username in final_url


            
            else:
                exists = response.status_code == 200 and ''
            
            result = {
                'exists': exists,
                'url': final_url if exists else url,
                'status_code': response.status_code,
                'platform': platform,
            }
            
            return result
            
        except Exception as e:
            return {
                'exists': False, 
                'url': url, 
                'error': str(e),
                'platform': platform
            }

    def analyze_social_presence(self, social_data):
        """Analisi aggregata presenza social"""
        summary = {
            'total_platforms_checked': len(social_data) - 1,  # -1 per escludere summary
            'platforms_found': 0,
            'platforms_list': [],
            'confidence_score': 0,
            'persona_type': 'Unknown'
        }
        
        found_platforms = []
        for platform, data in social_data.items():
            if platform != 'summary' and data.get('exists'):
                found_platforms.append(platform)
        
        summary['platforms_found'] = len(found_platforms)
        summary['platforms_list'] = found_platforms
        
        # Calcolo confidence score
        if found_platforms:
            base_score = (len(found_platforms) / summary['total_platforms_checked']) * 100
            summary['confidence_score'] = min(100, int(base_score))
        
        # Determinazione tipo persona
        tech_platforms = ['github']
        social_platforms = ['instagram', 'facebook', 'tiktok', 'youtube', 'twitter', 'reddit']
        professional_platforms = ['linkedin']
        
        tech_count = sum(1 for platform in found_platforms if platform in tech_platforms)
        social_count = sum(1 for platform in found_platforms if platform in social_platforms)
        professional_count = sum(1 for platform in found_platforms if platform in professional_platforms)
        
        if tech_count > social_count and tech_count > professional_count:
            summary['persona_type'] = 'Technical'
        elif professional_count > tech_count and professional_count > social_count:
            summary['persona_type'] = 'Professional'
        elif social_count > tech_count and social_count > professional_count:
            summary['persona_type'] = 'Social'
        else:
            summary['persona_type'] = 'Mixed'
        
        return summary

    # === UTILITIES ===
    def _parse_cert_field(self, field):
        """Parsa i campi del certificato SSL"""
        if isinstance(field, list):
            result = {}
            for item in field:
                if isinstance(item, tuple):
                    for subitem in item:
                        if isinstance(subitem, tuple) and len(subitem) == 2:
                            key, value = subitem
                            result[key] = value
            return result
        elif isinstance(field, tuple):
            result = {}
            for item in field:
                if isinstance(item, tuple) and len(item) == 2:
                    key, value = item
                    result[key] = value
            return result
        else:
            return str(field) if field else {}

    def generate_advanced_report(self, output_file=None, format='json', verbose=False):
        """Genera report avanzati in multiple formati"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = f"ms17_osint_report_{timestamp}"
        else:
            base_name = output_file.rsplit('.', 1)[0] if '.' in output_file else output_file
        
        reports_generated = []
        
        if format in ['json', 'all']:
            json_file = f"{base_name}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                full_report = {
                    'metadata': {
                        'tool': 'MS17 OSINT ULTRA PRO v3.0',
                        'generated_at': datetime.now().isoformat(),
                        'execution_time': getattr(self, 'execution_time', 'N/A')
                    },
                    'results': self.results,
                }
                json.dump(full_report, f, indent=2, ensure_ascii=False, default=str)
            reports_generated.append(json_file)
        
        if format in ['txt', 'all']:
            txt_file = f"{base_name}.txt"
            self._generate_advanced_txt_report(txt_file)
            reports_generated.append(txt_file)
            if verbose:
                print("\n" + "="*80)
                print("📄 REPORT COMPLETO")
                print("="*80)
                with open(txt_file, 'r', encoding='utf-8') as f:
                    print(f.read())
        
        if format in ['csv', 'all']:
            csv_file = f"{base_name}.csv"
            self._generate_advanced_csv_report(csv_file)
            reports_generated.append(csv_file)
        
        self.logger.info("Report generati: %s", reports_generated)
        return reports_generated

    def _generate_advanced_txt_report(self, output_file):
        """Genera report di testo avanzato"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("MS17 OSINT ULTRA PRO - RAPPORTO DI ANALISI AVANZATO\n")
            f.write("=" * 70 + "\n")
            f.write(f"Tool: MS17 OSINT ULTRA PRO v3.0\n")
            f.write(f"Data generazione: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            for category, data in self.results.items():
                f.write(f"\n{category.upper()} ANALYSIS:\n")
                f.write("-" * 50 + "\n")
                
                if category == 'domain' and isinstance(data, dict):
                    self._write_domain_txt(f, data)
                elif category == 'ip' and isinstance(data, dict):
                    self._write_ip_txt(f, data)
                elif category == 'email' and isinstance(data, dict):
                    self._write_email_txt(f, data)
                elif category == 'social' and isinstance(data, dict):
                    self._write_social_txt(f, data)
                elif category == 'gsm_geolocation' and isinstance(data, dict):
                    self._write_gsm_txt(f, data)
                
                f.write("\n")

    def _write_domain_txt(self, f, data):
        if 'whois' in data and 'standard' in data['whois']:
            whois_data = data['whois']['standard']
            f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
            f.write(f"Creation Date: {whois_data.get('creation_date', 'N/A')}\n")
            f.write(f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}\n")
        
        if 'subdomains' in data and data['subdomains']:
            f.write(f"Subdomains Found: {len(data['subdomains'])}\n")
            for sub in data['subdomains'][:10]:
                f.write(f"  - {sub}\n")

    def _write_ip_txt(self, f, data):
        if 'geolocation' in data and 'ip-api' in data['geolocation']:
            geo = data['geolocation']['ip-api']
            if geo.get('status') == 'success':
                f.write(f"Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}\n")
                f.write(f"ISP: {geo.get('isp', 'N/A')}\n")
                f.write(f"Coordinates: {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}\n")
        
        if 'ports' in data and data['ports']:
            f.write(f"Open Ports: {len(data['ports'])}\n")
            for port in data['ports']:
                f.write(f"  - {port['port']} ({port.get('service', 'unknown')})\n")

    def _write_email_txt(self, f, data):
        if 'validation' in data:
            val = data['validation']
            f.write(f"Format Valid: {val.get('format_valid', 'N/A')}\n")
            f.write(f"MX Valid: {val.get('mx_valid', 'N/A')}\n")
            f.write(f"Domain: {val.get('domain', 'N/A')}\n")
        
        if 'breaches' in data and 'hibp' in data['breaches']:
            hibp = data['breaches']['hibp']
            if not hibp.get('error'):
                f.write(f"Breached: {hibp.get('breached', 'N/A')}\n")
                f.write(f"Breach Count: {hibp.get('breach_count', 0)}\n")

    def _write_social_txt(self, f, data):
        if 'summary' in data:
            summary = data['summary']
            f.write(f"Platforms Found: {summary.get('platforms_found', 0)}/{summary.get('total_platforms_checked', 0)}\n")
            f.write(f"Confidence Score: {summary.get('confidence_score', 0)}/100\n")
            f.write(f"Persona Type: {summary.get('persona_type', 'N/A')}\n")
        
        found_platforms = [p for p, d in data.items() if p != 'summary' and d.get('exists')]
        if found_platforms:
            f.write(f"Platforms: {', '.join(found_platforms)}\n")

    def _write_gsm_txt(self, f, data):
        if 'unwiredlabs' in data and data['unwiredlabs'].get('status') == 'success':
            geo = data['unwiredlabs']
            f.write(f"Location: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}\n")
            f.write(f"Accuracy: {geo.get('accuracy', 'N/A')} meters\n")
            f.write(f"Address: {geo.get('address', 'N/A')}\n")
        
        if 'operator' in data:
            op = data['operator']
            f.write(f"Operator: {op.get('operator', 'N/A')} ({op.get('country', 'N/A')})\n")
            f.write(f"Network: {op.get('network', 'N/A')}\n")
        
        if 'accuracy_estimate' in data:
            acc = data['accuracy_estimate']
            f.write(f"Confidence: {acc.get('confidence', 'N/A')}\n")
            f.write(f"Accuracy Estimate: {acc.get('estimate', 'N/A')}\n")

    def _generate_advanced_csv_report(self, output_file):
        """Genera report CSV avanzato"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Type', 'Field', 'Value', 'Confidence'])
            
            for category, data in self.results.items():
                if category == 'domain' and isinstance(data, dict):
                    self._write_domain_csv(writer, data)
                elif category == 'ip' and isinstance(data, dict):
                    self._write_ip_csv(writer, data)
                elif category == 'email' and isinstance(data, dict):
                    self._write_email_csv(writer, data)
                elif category == 'social' and isinstance(data, dict):
                    self._write_social_csv(writer, data)
                elif category == 'gsm_geolocation' and isinstance(data, dict):
                    self._write_gsm_csv(writer, data)

    def _write_domain_csv(self, writer, data):
        if 'whois' in data and 'standard' in data['whois']:
            whois_data = data['whois']['standard']
            writer.writerow(['DOMAIN', 'WHOIS', 'Registrar', whois_data.get('registrar', 'N/A'), 'High'])
            writer.writerow(['DOMAIN', 'WHOIS', 'Creation Date', whois_data.get('creation_date', 'N/A'), 'High'])
        
        if 'dns' in data:
            for rtype, records in data['dns'].items():
                if records and rtype in ['A', 'MX', 'NS']:
                    writer.writerow(['DOMAIN', 'DNS', f'{rtype} Records', '; '.join(records[:3]), 'Medium'])

    def _write_ip_csv(self, writer, data):
        if 'geolocation' in data and 'ip-api' in data['geolocation']:
            geo = data['geolocation']['ip-api']
            if geo.get('status') == 'success':
                writer.writerow(['IP', 'GEOLOCATION', 'Country', geo.get('country', 'N/A'), 'High'])
                writer.writerow(['IP', 'GEOLOCATION', 'City', geo.get('city', 'N/A'), 'High'])
                writer.writerow(['IP', 'GEOLOCATION', 'ISP', geo.get('isp', 'N/A'), 'Medium'])

    def _write_email_csv(self, writer, data):
        if 'validation' in data:
            val = data['validation']
            writer.writerow(['EMAIL', 'VALIDATION', 'Format Valid', val.get('format_valid', 'N/A'), 'High'])
            writer.writerow(['EMAIL', 'VALIDATION', 'MX Valid', val.get('mx_valid', 'N/A'), 'High'])
        
        if 'breaches' in data and 'hibp' in data['breaches']:
            hibp = data['breaches']['hibp']
            if not hibp.get('error'):
                writer.writerow(['EMAIL', 'BREACHES', 'Pwned', hibp.get('breached', 'N/A'), 'High'])
                writer.writerow(['EMAIL', 'BREACHES', 'Breach Count', hibp.get('breach_count', 0), 'Medium'])

    def _write_social_csv(self, writer, data):
        if 'summary' in data:
            summary = data['summary']
            writer.writerow(['SOCIAL', 'SUMMARY', 'Platforms Found', summary.get('platforms_found', 0), 'Medium'])
            writer.writerow(['SOCIAL', 'SUMMARY', 'Persona Type', summary.get('persona_type', 'N/A'), 'Low'])
        
        for platform, platform_data in data.items():
            if platform != 'summary' and platform_data.get('exists'):
                writer.writerow(['SOCIAL', platform.upper(), 'URL', platform_data.get('url', 'N/A'), 'High'])

    def _write_gsm_csv(self, writer, data):
        if 'unwiredlabs' in data and data['unwiredlabs'].get('status') == 'success':
            geo = data['unwiredlabs']
            writer.writerow(['GSM', 'GEOLOCATION', 'Latitude', geo.get('latitude', 'N/A'), 'High'])
            writer.writerow(['GSM', 'GEOLOCATION', 'Longitude', geo.get('longitude', 'N/A'), 'High'])
            writer.writerow(['GSM', 'GEOLOCATION', 'Accuracy', geo.get('accuracy', 'N/A'), 'Medium'])
        
        if 'operator' in data:
            op = data['operator']
            writer.writerow(['GSM', 'OPERATOR', 'Name', op.get('operator', 'N/A'), 'High'])
            writer.writerow(['GSM', 'OPERATOR', 'Country', op.get('country', 'N/A'), 'High'])

    def print_advanced_summary(self):
        """Stampa riepilogo avanzato dei risultati"""
        banner = """
███╗░░░███╗░██████╗░░███╗░░███████╗
████╗░████║██╔════╝░████║░░╚════██║
██╔████╔██║╚█████╗░██╔██║░░░░░░██╔╝
██║╚██╔╝██║░╚═══██╗╚═╝██║░░░░░██╔╝░
██║░╚═╝░██║██████╔╝███████╗░░██╔╝░░
╚═╝░░░░░╚═╝╚═════╝░╚══════╝░░╚═╝░░░
        """
        
        print(banner)
        print("MS17 OSINT ULTRA PRO v3.0 - RIEPILOGO AVANZATO")
        print("=" * 70)
        
        if 'domain' in self.results:
            print("\n[🌐 DOMINIO]")
            data = self.results['domain']
            if 'whois' in data and 'standard' in data['whois']:
                whois_data = data['whois']['standard']
                print(f"  Registrar: {whois_data.get('registrar', 'N/A')}")
            
            if 'subdomains' in data:
                print(f"  Subdomains: {len(data['subdomains'])} trovati")
        
        if 'ip' in self.results:
            print("\n[📍 IP]")
            data = self.results['ip']
            if 'geolocation' in data and 'ip-api' in data['geolocation']:
                geo = data['geolocation']['ip-api']
                if geo.get('status') == 'success':
                    print(f"  Posizione: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
            
            if 'ports' in data:
                print(f"  Porte aperte: {len(data['ports'])}")
        
        if 'email' in self.results:
            print("\n[📧 EMAIL]")
            data = self.results['email']
            if 'validation' in data:
                val = data['validation']
                print(f"  Valida: {'Sì' if val.get('format_valid') else 'No'}")
            
            if 'breaches' in data and 'hibp' in data['breaches']:
                hibp = data['breaches']['hibp']
                if not hibp.get('error'):
                    status = "SÌ" if hibp.get('breached') else "NO"
                    print(f"  Compromessa: {status}")
        
        if 'social' in self.results:
            print("\n[👥 SOCIAL]")
            data = self.results['social']
            if 'summary' in data:
                summary = data['summary']
                print(f"  Piattaforme: {summary.get('platforms_found', 0)} trovate")
        
        if 'gsm_geolocation' in self.results:
            print("\n[📡 GSM]")
            data = self.results['gsm_geolocation']
            if 'unwiredlabs' in data and data['unwiredlabs'].get('status') == 'success':
                geo = data['unwiredlabs']
                print(f"  Posizione: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")

        print("\n" + "=" * 70)

def main():
    parser = argparse.ArgumentParser(description='MS17 OSINT ULTRA PRO - Advanced Intelligence Tool')
    parser.add_argument('-d', '--domain', help='Analizza dominio')
    parser.add_argument('-i', '--ip', help='Analizza indirizzo IP')
    parser.add_argument('-e', '--email', help='Analizza email')
    parser.add_argument('-u', '--username', help='Ricerca username sui social')
    parser.add_argument('-g', '--gsm', help='Geolocalizzazione GSM(formato: mcc,mnc,lac,cid o mcc:222,mnc:1,lac:1234,cid:5678)')
    parser.add_argument('--mcc', type=int, help='Mobile Country Code')
    parser.add_argument('--mnc', type=int, help='Mobile Network Code')
    parser.add_argument('--lac', type=int, help='Location Area Code')
    parser.add_argument('--cid', type=int, help='Cell ID')
    parser.add_argument('--signal', type=int, help='Segnale in dBm (opzionale)')
    parser.add_argument('-c', '--config', default='config.json', help='File di configurazione API')
    parser.add_argument('-o', '--output', help='File di output per il report')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt', 'all'], default='all', help='Formato del report')
    parser.add_argument('--verbose', action='store_true', help='Output verboso')
    parser.add_argument('--threads', type=int, default=10, help='Numero di thread per scansioni parallele')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tool = OSINTUltraPro(args.config)
    tool.max_workers = args.threads

    try:
        start_time = time.time()
        
        # GSM Advanced Geolocation
        if args.gsm:
            if tool.validate_input(args.gsm, 'gsm'):
                try:
                    mcc, mnc, lac, cid = tool.parse_gsm_data_from_string(args.gsm)
                    tool.advanced_gsm_geolocation(mcc, mnc, lac, cid, args.signal)
                    print(f"[📡] Geolocalizzazione GSM avanzata completata")
                except ValueError as e:
                    print(f"[!] Errore dati GSM: {e}")
        
        elif args.mcc and args.mnc and args.lac and args.cid:
            tool.advanced_gsm_geolocation(args.mcc, args.mnc, args.lac, args.cid, args.signal)
            print(f"[📡] Geolocalizzazione GSM avanzata completata")

        # Analisi avanzate
        if args.domain:
            tool.advanced_domain_intel(args.domain)
            print(f"[🌐] Analisi dominio completata")
        
        if args.ip:
            tool.advanced_ip_intel(args.ip)
            print(f"[📍] Analisi IP completata")
        
        if args.email:
            tool.advanced_email_intel(args.email)
            print(f"[📧] Analisi email completata")
        
        if args.username:
            tool.advanced_social_intel(args.username)
            print(f"[👤] Analisi social completata")

        execution_time = time.time() - start_time
        tool.execution_time = f"{execution_time:.2f}s"
        tool.logger.info("Analisi completata in %.2f secondi", execution_time)
        
        tool.print_advanced_summary()
        
        reports = tool.generate_advanced_report(args.output, args.format, args.verbose)
        print(f"\n[✅] ANALISI COMPLETATA in {execution_time:.2f}s!")
        print(f"[📊] Report generati:")
        for report in reports:
            print(f"     ✓ {report}")

    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente")
        tool.logger.info("Analisi interrotta dall'utente")
    except Exception as e:
        print(f"\n[💥] Errore critico: {e}")
        tool.logger.error("Errore critico: %s", e, exc_info=True)

if __name__ == '__main__':
    main()