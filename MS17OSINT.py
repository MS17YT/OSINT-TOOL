#!/usr/bin/env python3
"""
MS17 OSINT TOOL - Advanced Open Source Intelligence Tool
Versione: 2.3 - Con Geolocalizzazione GSM
Autore: MS17
"""

import requests
import json
import dns.resolver
import whois
import socket
import time
import argparse
import sys
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures
import csv
import os
import logging
from typing import Dict, List, Optional, Any
import ssl
import random

class OSINTPro:
    def __init__(self, config_file="config.json"):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Configurazione logging
        self.setup_logging()
        
        self.config = self.load_config(config_file)
        self.results = {}
        self.rate_limit_delay = 1  # Secondi tra le richieste API

    def setup_logging(self):
        """Configura il sistema di logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('osint_pro.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self, config_file):
        """Carica la configurazione dalle API con validazione"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Validazione configurazione
            api_keys = {
                'virustotal_api_key': 'VirusTotal',
                'shodan_api_key': 'Shodan',
                'abuseipdb_api_key': 'AbuseIPDB',
                'hibp_api_key': 'HIBP',
                'hunter_api_key': 'Hunter.io',
                'unwiredlabs_api_key': 'UnwiredLabs'
            }
            
            for key, service in api_keys.items():
                if key in config and config[key].startswith('TUO_'):
                    self.logger.warning("Chiave API %s non configurata - Le funzionalità %s saranno limitate", key, service)
                elif key not in config:
                    self.logger.warning("Chiave API %s mancante nel file di configurazione", key)
            
            return config
        except FileNotFoundError:
            self.logger.error("File di configurazione %s non trovato", config_file)
            print(f"[!] Crea un file {config_file} con il seguente formato:")
            print("""{
  "virustotal_api_key": "tua_chiave_virustotal",
  "shodan_api_key": "tua_chiave_shodan",
  "abuseipdb_api_key": "tua_chiave_abuseipdb",
  "hibp_api_key": "tua_chiave_hibp",
  "hunter_api_key": "tua_chiave_hunter",
  "unwiredlabs_api_key": "tua_chiave_unwiredlabs"
}""")
            return {}
        except json.JSONDecodeError as e:
            self.logger.error("Errore nel parsing del file di configurazione: %s", e)
            return {}

    def _parse_cert_field(self, field):
        """Parsa i campi subject e issuer del certificato SSL"""
        if isinstance(field, list):
            # Formato: [((key, value),), ((key, value),)]
            result = {}
            for item in field:
                if isinstance(item, tuple):
                    for subitem in item:
                        if isinstance(subitem, tuple) and len(subitem) == 2:
                            key, value = subitem
                            result[key] = value
            return result
        elif isinstance(field, tuple):
            # Formato alternativo
            result = {}
            for item in field:
                if isinstance(item, tuple) and len(item) == 2:
                    key, value = item
                    result[key] = value
            return result
        else:
            return str(field) if field else {}

    def validate_input(self, input_str: str, input_type: str) -> bool:
        """Valida e sanitizza gli input utente"""
        try:
            if input_type == 'domain':
                # Validazione dominio
                pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
                if not re.match(pattern, input_str):
                    raise ValueError("Formato dominio non valido")
                return True
                
            elif input_type == 'ip':
                # Validazione IP
                ipaddress.ip_address(input_str)
                return True
                
            elif input_type == 'email':
                # Validazione email più robusta
                pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,64}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$'
                if not re.match(pattern, input_str):
                    raise ValueError("Formato email non valido")
                if len(input_str) > 254:
                    raise ValueError("Email troppo lunga")
                return True
                
            elif input_type == 'username':
                # Validazione username
                if not re.match(r'^[a-zA-Z0-9_.-]{1,50}$', input_str):
                    raise ValueError("Username contiene caratteri non validi")
                return True
                
            elif input_type == 'gsm':
                # Validazione base per stringa GSM
                if not re.match(r'^[\d,:-\s]+$', input_str):
                    raise ValueError("Formato dati GSM non valido")
                return True
                
        except ValueError as e:
            self.logger.error("Validazione input fallita: %s", e)
            return False
        except Exception as e:
            self.logger.error("Errore validazione input: %s", e)
            return False
        
        return False

    def safe_api_call(self, api_func, *args, max_retries=3, **kwargs):
        """Esegue chiamate API con gestione errori e retry"""
        for attempt in range(max_retries):
            try:
                time.sleep(self.rate_limit_delay)  # Rate limiting
                result = api_func(*args, **kwargs)
                return result
            except requests.exceptions.ConnectionError as e:
                self.logger.warning("Errore di connessione (tentativo %d/%d): %s", 
                                  attempt + 1, max_retries, e)
                if attempt == max_retries - 1:
                    return {"error": f"Connection error: {e}"}
                time.sleep(2 ** attempt)  # Exponential backoff
            except requests.exceptions.Timeout as e:
                self.logger.warning("Timeout (tentativo %d/%d)", attempt + 1, max_retries)
                if attempt == max_retries - 1:
                    return {"error": "Request timeout"}
                time.sleep(2 ** attempt)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:  # Too Many Requests
                    wait_time = 30 * (attempt + 1)
                    self.logger.warning("Rate limit raggiunto, attesa di %d secondi", wait_time)
                    time.sleep(wait_time)
                    continue
                elif e.response.status_code == 401:
                    return {"error": "API key non valida o scaduta"}
                elif e.response.status_code == 403:
                    return {"error": "Accesso negato all'API"}
                else:
                    self.logger.error("Errore HTTP %d: %s", e.response.status_code, e)
                    return {"error": f"HTTP error {e.response.status_code}"}
            except Exception as e:
                self.logger.error("Errore imprevisto in API call: %s", e)
                return {"error": f"Unexpected error: {e}"}
        
        return {"error": "Numero massimo di tentativi raggiunto"}

    # === DOMAIN ANALYSIS ===
    def domain_intel(self, domain):
        """Analisi completa del dominio"""
        if not self.validate_input(domain, 'domain'):
            self.logger.error("Dominio non valido: %s", domain)
            return {}

        self.logger.info("Analisi dominio: %s", domain)
        domain_data = {}
        
        # WHOIS Information
        try:
            whois_data = whois.whois(domain)
            domain_data['whois'] = {
                'registrar': str(whois_data.registrar) if whois_data.registrar else "N/A",
                'creation_date': str(whois_data.creation_date) if whois_data.creation_date else "N/A",
                'expiration_date': str(whois_data.expiration_date) if whois_data.expiration_date else "N/A",
                'updated_date': str(whois_data.updated_date) if whois_data.updated_date else "N/A",
                'name_servers': list(whois_data.name_servers) if whois_data.name_servers else [],
                'status': list(whois_data.status) if whois_data.status else [],
                'emails': list(whois_data.emails) if whois_data.emails else []
            }
            self.logger.info("WHOIS informazioni ottenute per %s", domain)
        except Exception as e:
            self.logger.error("Errore WHOIS per %s: %s", domain, e)
            domain_data['whois'] = {"error": str(e)}

        # DNS Records
        try:
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
            
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                    dns_records[rtype] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                    dns_records[rtype] = []
                except Exception as e:
                    dns_records[rtype] = [f"Error: {str(e)}"]
            
            domain_data['dns'] = dns_records
            self.logger.info("Record DNS ottenuti per %s", domain)
        except Exception as e:
            self.logger.error("Errore DNS per %s: %s", domain, e)
            domain_data['dns'] = {"error": str(e)}

        # SSL Certificate Info - VERSIONE CORRETTA
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_info = {
                        'subject': self._parse_cert_field(cert.get('subject', [])),
                        'issuer': self._parse_cert_field(cert.get('issuer', [])),
                        'not_before': cert.get('notBefore', 'N/A'),
                        'not_after': cert.get('notAfter', 'N/A'),
                        'serial_number': cert.get('serialNumber', 'N/A'),
                        'version': cert.get('version', 'N/A')
                    }
                    domain_data['ssl'] = cert_info
            self.logger.info("Certificato SSL analizzato per %s", domain)
        except Exception as e:
            self.logger.error("Errore SSL per %s: %s", domain, e)
            domain_data['ssl'] = {"error": str(e)}

        # VirusTotal Domain Report
        if self.config.get('virustotal_api_key') and not self.config['virustotal_api_key'].startswith('TUO_'):
            vt_result = self.safe_api_call(self.virustotal_domain, domain)
            domain_data['virustotal'] = vt_result
            if 'error' not in vt_result:
                self.logger.info("Scan VirusTotal completato per %s", domain)

        # Risoluzione IP del dominio
        try:
            ip = socket.gethostbyname(domain)
            domain_data['resolved_ip'] = ip
            self.logger.info("Dominio %s risolto a IP: %s", domain, ip)
        except Exception as e:
            self.logger.error("Errore risoluzione IP per %s: %s", domain, e)

        self.results['domain'] = domain_data
        return domain_data

    # === IP ANALYSIS ===
    def ip_intel(self, ip):
        """Analisi completa IP"""
        if not self.validate_input(ip, 'ip'):
            self.logger.error("IP non valido: %s", ip)
            return {}

        self.logger.info("Analisi IP: %s", ip)
        ip_data = {}
        
        # IP Geolocation
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=10)
            geo_data = response.json()
            if geo_data['status'] == 'success':
                ip_data['geolocation'] = {
                    'country': geo_data.get('country', 'N/A'),
                    'country_code': geo_data.get('countryCode', 'N/A'),
                    'region': geo_data.get('regionName', 'N/A'),
                    'city': geo_data.get('city', 'N/A'),
                    'zip': geo_data.get('zip', 'N/A'),
                    'isp': geo_data.get('isp', 'N/A'),
                    'asn': geo_data.get('as', 'N/A'),
                    'lat': geo_data.get('lat', 'N/A'),
                    'lon': geo_data.get('lon', 'N/A'),
                    'timezone': geo_data.get('timezone', 'N/A')
                }
                self.logger.info("Geolocalizzazione completata per %s", ip)
            else:
                ip_data['geolocation'] = {"error": geo_data.get('message', 'Unknown error')}
        except Exception as e:
            self.logger.error("Errore geolocalizzazione per %s: %s", ip, e)
            ip_data['geolocation'] = {"error": str(e)}

        # Shodan (se API key disponibile)
        if self.config.get('shodan_api_key') and not self.config['shodan_api_key'].startswith('TUO_'):
            shodan_result = self.safe_api_call(self.shodan_ip_lookup, ip)
            ip_data['shodan'] = shodan_result
            if 'error' not in shodan_result:
                self.logger.info("Dati Shodan ottenuti per %s", ip)

        # AbuseIPDB (se API key disponibile)
        if self.config.get('abuseipdb_api_key') and not self.config['abuseipdb_api_key'].startswith('TUO_'):
            abuse_result = self.safe_api_call(self.abuseipdb_check, ip)
            ip_data['abuseipdb'] = abuse_result
            if 'error' not in abuse_result:
                self.logger.info("Check AbuseIPDB completato per %s", ip)

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            ip_data['reverse_dns'] = hostname
        except (socket.herror, socket.gaierror):
            ip_data['reverse_dns'] = "N/A"
        except Exception as e:
            self.logger.error("Errore reverse DNS per %s: %s", ip, e)
            ip_data['reverse_dns'] = {"error": str(e)}

        self.results['ip'] = ip_data
        return ip_data

    # === EMAIL ANALYSIS ===
    def email_intel(self, email):
        """Analisi completa email"""
        if not self.validate_input(email, 'email'):
            self.logger.error("Email non valida: %s", email)
            return {}

        self.logger.info("Analisi email: %s", email)
        email_data = {}
        
        # Email Format Validation
        try:
            email_data['validation'] = self.validate_email(email)
            self.logger.info("Validazione email completata per %s", email)
        except Exception as e:
            self.logger.error("Errore validazione email %s: %s", email, e)
            email_data['validation'] = {"error": str(e)}

        # Breach Check (HaveIBeenPwned)
        if self.config.get('hibp_api_key') and not self.config['hibp_api_key'].startswith('TUO_'):
            breach_data = self.safe_api_call(self.hibp_breach_check, email)
            email_data['breaches'] = breach_data
            if 'error' not in breach_data:
                self.logger.info("Verifica breach completata per %s", email)

        # Hunter.io (se API key disponibile)
        if self.config.get('hunter_api_key') and not self.config['hunter_api_key'].startswith('TUO_'):
            hunter_data = self.safe_api_call(self.hunter_verify, email)
            email_data['hunter'] = hunter_data
            if 'error' not in hunter_data:
                self.logger.info("Verifica Hunter.io completata per %s", email)

        self.results['email'] = email_data
        return email_data

    # === SOCIAL MEDIA ANALYSIS ===
    def social_intel(self, username):
        """Ricerca username sui social media"""
        if not self.validate_input(username, 'username'):
            self.logger.error("Username non valido: %s", username)
            return {}

        self.logger.info("Ricerca social per: %s", username)
        social_data = {}
        
        platforms = {
            'github': f'https://github.com/{username}',
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'youtube': f'https://youtube.com/@{username}',
            'tiktok': f'https://tiktok.com/@{username}',
            'pinterest': f'https://pinterest.com/{username}',
            'spotify': f'https://open.spotify.com/user/{username}',
            'twitch': f'https://twitch.tv/{username}'
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_platform = {
                executor.submit(self.check_social_platform, platform, url): platform 
                for platform, url in platforms.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    result = future.result(timeout=15)
                    social_data[platform] = result
                    if result.get('exists'):
                        self.logger.info("Profilo trovato su %s", platform.upper())
                except concurrent.futures.TimeoutError:
                    social_data[platform] = {'exists': False, 'url': platforms[platform], 'error': 'Timeout'}
                    self.logger.warning("Timeout per piattaforma %s", platform)
                except Exception as e:
                    social_data[platform] = {'exists': False, 'url': platforms[platform], 'error': str(e)}
                    self.logger.error("Errore piattaforma %s: %s", platform, e)

        self.results['social'] = social_data
        return social_data

    def check_social_platform(self, platform, url):
        """Verifica presenza su una piattaforma sociale"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3',
            }
            
            response = self.session.head(url, timeout=10, allow_redirects=True, headers=headers)
            
            exists = False
            if platform == 'github':
                exists = response.status_code == 200 and 'github.com' in response.url
            elif platform == 'reddit':
                exists = response.status_code == 200 and 'reddit.com/user' in response.url
            else:
                exists = response.status_code == 200
            
            return {
                'exists': exists,
                'url': response.url if exists else url,
                'status_code': response.status_code,
                'platform': platform
            }
        except requests.exceptions.RequestException as e:
            return {'exists': False, 'url': url, 'error': str(e), 'platform': platform}
        except Exception as e:
            return {'exists': False, 'url': url, 'error': f"Unexpected error: {str(e)}", 'platform': platform}

    # === UNWIREDLABS GSM GEOLOCATION ===
    def unwiredlabs_gsm_geolocation(self, cell_towers_data):
        """
        Geolocalizzazione GSM tramite Cell Towers usando UnwiredLabs
        
        Args:
            cell_towers_data (dict): Dati delle celle GSM con formato:
                {
                    "mcc": 222,        # Mobile Country Code
                    "mnc": 1,          # Mobile Network Code
                    "cells": [
                        {
                            "lac": 1234,    # Location Area Code
                            "cid": 5678,    # Cell ID
                            "signal": -70   # Opzionale: segnale in dBm
                        }
                    ],
                    "address": 1       # Opzionale: richiedi indirizzo
                }
        """
        api_key = self.config.get('unwiredlabs_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key UnwiredLabs mancante o non configurata"}
        
        url = "https://us1.unwiredlabs.com/v2/process.php"
        
        payload = {
            "token": api_key,
            "radio": "gsm",
            "mcc": cell_towers_data.get("mcc"),
            "mnc": cell_towers_data.get("mnc"),
            "cells": cell_towers_data.get("cells", []),
            "address": cell_towers_data.get("address", 1)
        }
        
        try:
            self.logger.info("Invio richiesta di geolocalizzazione GSM a UnwiredLabs")
            response = self.session.post(url, json=payload, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('status') == 'ok':
                    geolocation_data = {
                        "status": "success",
                        "latitude": result.get('lat'),
                        "longitude": result.get('lon'),
                        "accuracy": result.get('accuracy'),
                        "address": result.get('address'),
                        "country": result.get('country'),
                        "city": result.get('city'),
                        "district": result.get('district'),
                        "street": result.get('street'),
                        "postal_code": result.get('postal_code'),
                        "timezone": result.get('timezone'),
                        "balance": result.get('balance')
                    }
                    self.logger.info("Geolocalizzazione GSM completata con successo")
                    return geolocation_data
                else:
                    error_msg = result.get('message', 'Unknown error from UnwiredLabs')
                    self.logger.error("Errore UnwiredLabs: %s", error_msg)
                    return {"error": error_msg, "status": "error"}
            else:
                self.logger.error("HTTP error %d da UnwiredLabs", response.status_code)
                return {"error": f"HTTP error {response.status_code}"}
                
        except requests.exceptions.Timeout:
            self.logger.error("Timeout nella richiesta a UnwiredLabs")
            return {"error": "Timeout nella richiesta a UnwiredLabs"}
        except requests.exceptions.ConnectionError:
            self.logger.error("Errore di connessione a UnwiredLabs")
            return {"error": "Errore di connessione a UnwiredLabs"}
        except Exception as e:
            self.logger.error("Errore imprevisto in UnwiredLabs: %s", e)
            return {"error": f"Unexpected error: {str(e)}"}

    def gsm_geolocation_intel(self, mcc, mnc, lac, cid, signal_strength=None):
        """
        Analisi completa di geolocalizzazione GSM
        
        Args:
            mcc (int): Mobile Country Code
            mnc (int): Mobile Network Code  
            lac (int): Location Area Code
            cid (int): Cell ID
            signal_strength (int): Opzionale, segnale in dBm
        """
        self.logger.info("Avvio analisi geolocalizzazione GSM")
        gsm_data = {}
        
        # Preparazione dati cella
        cell_data = {
            "lac": lac,
            "cid": cid
        }
        
        if signal_strength is not None:
            cell_data["signal"] = signal_strength
        
        towers_data = {
            "mcc": mcc,
            "mnc": mnc,
            "cells": [cell_data],
            "address": 1
        }
        
        # Geolocalizzazione con UnwiredLabs
        geolocation_result = self.unwiredlabs_gsm_geolocation(towers_data)
        gsm_data['unwiredlabs'] = geolocation_result
        
        # Informazioni aggiuntive sul operatore
        operator_info = self.get_gsm_operator_info(mcc, mnc)
        gsm_data['operator'] = operator_info
        
        self.results['gsm_geolocation'] = gsm_data
        return gsm_data

    def get_gsm_operator_info(self, mcc, mnc):
        """Ottiene informazioni sull'operatore GSM da database locale/API"""
        # Database semplificato degli operatori (può essere espanso)
        operators_db = {
            "22201": {"operator": "TIM", "country": "Italy", "network": "GSM"},
            "22210": {"operator": "Vodafone", "country": "Italy", "network": "GSM"},
            "22288": {"operator": "Wind", "country": "Italy", "network": "GSM"},
            "22299": {"operator": "3 Italia", "country": "Italy", "network": "3G"},
            "23415": {"operator": "Vodafone", "country": "UK", "network": "GSM"},
            "23420": {"operator": "3", "country": "UK", "network": "3G"},
            "310260": {"operator": "T-Mobile", "country": "USA", "network": "GSM"},
            "310410": {"operator": "AT&T", "country": "USA", "network": "GSM"},
            "26201": {"operator": "Telekom", "country": "Germany", "network": "GSM"},
            "26202": {"operator": "Vodafone", "country": "Germany", "network": "GSM"},
        }
        
        operator_key = f"{mcc}{mnc:02d}"
        return operators_db.get(operator_key, {"operator": "Unknown", "country": "Unknown", "network": "Unknown"})

    def parse_gsm_data_from_string(self, gsm_string):
        """
        Parsa una stringa con dati GSM in formato vario
        Formati supportati:
        - "mcc:222,mnc:1,lac:1234,cid:5678"
        - "222-1-1234-5678"
        - "222,1,1234,5678"
        """
        try:
            # Rimuovi spazi e converti in lowercase
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
            self.logger.error("Errore nel parsing dati GSM: %s", e)
            raise ValueError(f"Formato dati GSM non valido: {e}")

    # === API INTEGRATIONS ===
    def virustotal_domain(self, domain):
        """VirusTotal Domain Report"""
        api_key = self.config.get('virustotal_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key mancante o non configurata"}
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        response = self.session.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "Dominio non trovato in VirusTotal"}
        else:
            response.raise_for_status()

    def shodan_ip_lookup(self, ip):
        """Shodan IP Lookup"""
        api_key = self.config.get('shodan_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key mancante o non configurata"}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = self.session.get(url, timeout=15)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "IP non trovato in Shodan"}
        else:
            response.raise_for_status()

    def abuseipdb_check(self, ip):
        """AbuseIPDB Check"""
        api_key = self.config.get('abuseipdb_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key mancante o non configurata"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json',
            'User-Agent': 'OSINT-Pro/2.3'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        
        response = self.session.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    def hibp_breach_check(self, email):
        """Have I Been Pwned Breach Check"""
        api_key = self.config.get('hibp_api_key')
        headers = {'hibp-api-key': api_key} if api_key and not api_key.startswith('TUO_') else {}
        headers['User-Agent'] = 'OSINT-Pro-2.3'
        
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
                return {"error": "Rate limit exceeded - wait before retrying"}
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def hunter_verify(self, email):
        """Hunter.io Email Verification"""
        api_key = self.config.get('hunter_api_key')
        if not api_key or api_key.startswith('TUO_'):
            return {"error": "API key mancante o non configurata"}
        
        url = "https://api.hunter.io/v2/email-verifier"
        params = {'email': email, 'api_key': api_key}
        
        response = self.session.get(url, params=params, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()

    # === UTILITIES ===
    def validate_email(self, email):
        """Validazione formato email con controllo MX"""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,64}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$'
        is_valid = bool(re.match(pattern, email))
        
        domain = email.split('@')[1] if '@' in email else None
        mx_valid = False
        
        if domain and is_valid:
            try:
                dns.resolver.resolve(domain, 'MX', lifetime=10)
                mx_valid = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                mx_valid = False
            except Exception as e:
                mx_valid = False
        
        return {
            'format_valid': is_valid,
            'mx_valid': mx_valid,
            'domain': domain,
            'length_valid': len(email) <= 254
        }

    def generate_report(self, output_file=None, format='json'):
        """Genera report dei risultati in diversi formati"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"osint_report_{timestamp}"
        
        if format == 'json':
            output_file += '.json'
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        
        elif format == 'csv':
            output_file += '.csv'
            self._generate_csv_report(output_file)
        
        elif format == 'txt':
            output_file += '.txt'
            self._generate_txt_report(output_file)
        
        self.logger.info("Report salvato in: %s", output_file)
        return output_file

    def _generate_csv_report(self, output_file):
        """Genera report in formato CSV"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Tipo', 'Parametro', 'Dettaglio', 'Valore'])
            
            for category, data in self.results.items():
                if category == 'domain' and isinstance(data, dict):
                    if 'whois' in data:
                        whois_data = data['whois']
                        writer.writerow(['DOMINIO', 'WHOIS', 'Registrar', whois_data.get('registrar', 'N/A')])
                        writer.writerow(['DOMINIO', 'WHOIS', 'Data Creazione', whois_data.get('creation_date', 'N/A')])
                
                elif category == 'ip' and isinstance(data, dict):
                    if 'geolocation' in data:
                        geo = data['geolocation']
                        writer.writerow(['IP', 'GEOLOC', 'Città', geo.get('city', 'N/A')])
                        writer.writerow(['IP', 'GEOLOC', 'Paese', geo.get('country', 'N/A')])
                
                elif category == 'social' and isinstance(data, dict):
                    for platform, platform_data in data.items():
                        if platform_data.get('exists'):
                            writer.writerow(['SOCIAL', platform.upper(), 'URL', platform_data.get('url', 'N/A')])
                
                elif category == 'gsm_geolocation' and isinstance(data, dict):
                    if 'unwiredlabs' in data and data['unwiredlabs'].get('status') == 'success':
                        geo = data['unwiredlabs']
                        writer.writerow(['GSM', 'GEOLOC', 'Latitudine', geo.get('latitude', 'N/A')])
                        writer.writerow(['GSM', 'GEOLOC', 'Longitudine', geo.get('longitude', 'N/A')])
                        writer.writerow(['GSM', 'GEOLOC', 'Indirizzo', geo.get('address', 'N/A')])

    def _generate_txt_report(self, output_file):
        """Genera report in formato testo"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("MS17 OSINT TOOL - RAPPORTO DI ANALISI\n")
            f.write("=" * 60 + "\n")
            f.write(f"Data generazione: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for category, data in self.results.items():
                f.write(f"\n{category.upper()}:\n")
                f.write("-" * 40 + "\n")
                
                if category == 'domain' and isinstance(data, dict):
                    if 'whois' in data:
                        f.write(f"Registrar: {data['whois'].get('registrar', 'N/A')}\n")
                        f.write(f"Data creazione: {data['whois'].get('creation_date', 'N/A')}\n")
                
                elif category == 'social' and isinstance(data, dict):
                    found_platforms = [p for p, d in data.items() if d.get('exists')]
                    f.write(f"Piattaforme trovate: {', '.join(found_platforms) if found_platforms else 'Nessuna'}\n")
                
                elif category == 'gsm_geolocation' and isinstance(data, dict):
                    if 'unwiredlabs' in data and data['unwiredlabs'].get('status') == 'success':
                        geo = data['unwiredlabs']
                        f.write(f"Posizione: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}\n")
                        f.write(f"Indirizzo: {geo.get('address', 'N/A')}\n")
                        f.write(f"Accuratezza: {geo.get('accuracy', 'N/A')} metri\n")

    def print_summary(self):
        """Stampa un riepilogo dei risultati"""
        print("\n" + "="*60)
        print("📋 RIEPILOGO MS17 OSINT TOOL v2.3")
        print("="*60)
        
        if 'domain' in self.results:
            print("\n[🌐 DOMINIO]")
            domain_data = self.results['domain']
            if 'whois' in domain_data:
                print(f"  Registrar: {domain_data['whois'].get('registrar', 'N/A')}")
                print(f"  Data creazione: {domain_data['whois'].get('creation_date', 'N/A')}")
            if 'resolved_ip' in domain_data:
                print(f"  IP risolto: {domain_data['resolved_ip']}")
        
        if 'ip' in self.results:
            print("\n[📍 IP]")
            ip_data = self.results['ip']
            if 'geolocation' in ip_data:
                geo = ip_data['geolocation']
                print(f"  Posizione: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
                print(f"  ISP: {geo.get('isp', 'N/A')}")
        
        if 'email' in self.results:
            print("\n[📧 EMAIL]")
            email_data = self.results['email']
            if 'validation' in email_data:
                val = email_data['validation']
                print(f"  Formato valido: {'Sì' if val.get('format_valid') else 'No'}")
                print(f"  MX valido: {'Sì' if val.get('mx_valid') else 'No'}")
            if 'breaches' in email_data:
                breaches = email_data['breaches']
                if breaches.get('breached'):
                    print(f"  Account compromesso: Sì ({breaches.get('breach_count', 0)} breach)")
                else:
                    print("  Account compromesso: No")
        
        if 'social' in self.results:
            print("\n[👥 SOCIAL MEDIA]")
            social_data = self.results['social']
            found_platforms = [platform for platform, data in social_data.items() if data.get('exists')]
            if found_platforms:
                print(f"  Piattaforme trovate: {', '.join(found_platforms)}")
            else:
                print("  Nessun profilo trovato")

        if 'gsm_geolocation' in self.results:
            print("\n[📡 GEOLOCALIZZAZIONE GSM]")
            gsm_data = self.results['gsm_geolocation']
            if 'unwiredlabs' in gsm_data and gsm_data['unwiredlabs'].get('status') == 'success':
                geo = gsm_data['unwiredlabs']
                print(f"  Posizione: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
                print(f"  Indirizzo: {geo.get('address', 'N/A')}")
                print(f"  Accuratezza: {geo.get('accuracy', 'N/A')} metri")
            if 'operator' in gsm_data:
                op = gsm_data['operator']
                print(f"  Operatore: {op.get('operator', 'N/A')} - {op.get('country', 'N/A')}")

        print("\n" + "="*60)

def main():
    banner = """
███╗░░░███╗░██████╗░░███╗░░███████╗
████╗░████║██╔════╝░████║░░╚════██║
██╔████╔██║╚█████╗░██╔██║░░░░░░██╔╝
██║╚██╔╝██║░╚═══██╗╚═╝██║░░░░░██╔╝░
██║░╚═╝░██║██████╔╝███████╗░░██╔╝░░
╚═╝░░░░░╚═╝╚═════╝░╚══════╝░░╚═╝░░░   
    """
    
    parser = argparse.ArgumentParser(description='MS17 - OSINT Tool')
    parser.add_argument('-d', '--domain', help='Analizza dominio')
    parser.add_argument('-i', '--ip', help='Analizza indirizzo IP')
    parser.add_argument('-e', '--email', help='Analizza email')
    parser.add_argument('-u', '--username', help='Ricerca username sui social')
    parser.add_argument('-g', '--gsm', help='Geolocalizzazione GSM (formato: mcc,mnc,lac,cid o mcc:222,mnc:1,lac:1234,cid:5678)')
    parser.add_argument('--mcc', type=int, help='Mobile Country Code')
    parser.add_argument('--mnc', type=int, help='Mobile Network Code')
    parser.add_argument('--lac', type=int, help='Location Area Code')
    parser.add_argument('--cid', type=int, help='Cell ID')
    parser.add_argument('--signal', type=int, help='Segnale in dBm (opzionale)')
    parser.add_argument('-c', '--config', default='config.json', help='File di configurazione API')
    parser.add_argument('-o', '--output', help='File di output per il report')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt'], default='json', help='Formato del report')
    parser.add_argument('--all', action='store_true', help='Esegui tutte le analisi disponibili')
    parser.add_argument('-v', '--verbose', action='store_true', help='Output verboso')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        return

    print(banner)
    print("MS17 - OSINT TOOL v2.3 (con Geolocalizzazione GSM)")
    print("="*60)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tool = OSINTPro(args.config)

    try:
        start_time = time.time()
        
        # Analisi GSM
        if args.gsm:
            if tool.validate_input(args.gsm, 'gsm'):
                try:
                    mcc, mnc, lac, cid = tool.parse_gsm_data_from_string(args.gsm)
                    tool.gsm_geolocation_intel(mcc, mnc, lac, cid, args.signal)
                    print(f"[📡] Geolocalizzazione GSM avviata per cella: MCC={mcc}, MNC={mnc}, LAC={lac}, CID={cid}")
                except ValueError as e:
                    print(f"[!] Errore nei dati GSM: {e}")
        
        # Analisi con parametri GSM separati
        elif args.mcc and args.mnc and args.lac and args.cid:
            tool.gsm_geolocation_intel(args.mcc, args.mnc, args.lac, args.cid, args.signal)
            print(f"[📡] Geolocalizzazione GSM avviata per cella: MCC={args.mcc}, MNC={args.mnc}, LAC={args.lac}, CID={args.cid}")
        
        # Analisi tradizionali
        if args.domain:
            tool.domain_intel(args.domain)
        
        if args.ip:
            tool.ip_intel(args.ip)
        
        if args.email:
            tool.email_intel(args.email)
        
        if args.username:
            tool.social_intel(args.username)

        if args.all and args.domain:
            print("\n[🚀] Esecuzione analisi completa...")
            domain_data = tool.domain_intel(args.domain)
            
            if 'resolved_ip' in domain_data:
                tool.ip_intel(domain_data['resolved_ip'])
            
            if 'domain' in tool.results and 'whois' in tool.results['domain']:
                whois_data = tool.results['domain']['whois']
                if whois_data.get('emails'):
                    for email in whois_data['emails']:
                        if tool.validate_input(str(email), 'email'):
                            print(f"\n[📧] Analisi email dal WHOIS: {email}")
                            tool.email_intel(str(email))
                            break

        execution_time = time.time() - start_time
        tool.logger.info("Analisi completata in %.2f secondi", execution_time)
        
        tool.print_summary()
        
        report_file = tool.generate_report(args.output, args.format)
        print(f"\n[✅] Analisi completata in {execution_time:.2f}s!")
        print(f"[📊] Report salvato in: {report_file}")

    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente")
        tool.logger.info("Analisi interrotta dall'utente")
    except Exception as e:
        print(f"\n[💥] Errore critico: {e}")
        tool.logger.error("Errore critico: %s", e, exc_info=True)

if __name__ == '__main__':
    main()