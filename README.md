# 🕵️‍♂️ MS17 - OSINT Intelligence Framework

**MS17** è un tool OSINT (Open Source Intelligence) avanzato scritto in **Python**, progettato per raccogliere, analizzare e correlare informazioni da fonti pubbliche su **domini, IP, email e username**.  
Combina diverse API (VirusTotal, Shodan, AbuseIPDB, HaveIBeenPwned, Hunter.io, ipqualityscore.com) e analisi locali (DNS, WHOIS, SSL, Social Media).

---

![Python](https://img.shields.io/badge/Python-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Category](https://img.shields.io/badge/category-OSINT-orange)

---

## 🚀 Funzionalità principali

| Categoria | Descrizione |
|------------|-------------|
| 🌐 **Domain Intel** | WHOIS, DNS Records, SSL Certificate, VirusTotal Lookup |
| 📍 **IP Intel** | Geolocalizzazione, Shodan Scan, AbuseIPDB Reputation, Reverse DNS |
| 📧 **Email Intel** | Validazione formato e MX, Hunter.io, HaveIBeenPwned breach check |
| 👥 **Social Intel** | Ricerca username su GitHub, Twitter, Instagram, LinkedIn, Reddit, ecc. |
| 🧩 **Reportistica** | Genera report in formato **JSON**, **CSV** o **TXT** |
| ⚙️ **Sicurezza & Affidabilità** | Gestione errori, rate limiting, retry automatici, logging dettagliato |

---

## 🧰 Requisiti

- Python 
- Librerie Python necessarie:
  ```bash
  pip install requests dnspython python-whois
  ```
- (Facoltativo ma consigliato) API key valide per:
  - VirusTotal  
  - Shodan  
  - AbuseIPDB  
  - HaveIBeenPwned  
  - Hunter.io
  - ipqualityscore.com  

---

## ⚙️ Configurazione

Crea un file `config.json` nella directory principale del progetto, con questo formato:

```json
{
  "virustotal_api_key": "INSERISCI_LA_TUA_API_KEY_VIRUSTOTAL",
  "shodan_api_key": "INSERISCI_LA_TUA_API_KEY_SHODAN",
  "abuseipdb_api_key": "INSERISCI_LA_TUA_API_KEY_ABUSEIPDB",
  "hibp_api_key": "INSERISCI_LA_TUA_API_KEY_HIBP",
  "hunter_api_key": "INSERISCI_LA_TUA_API_KEY_HUNTER",
  "ipqualityscore_api_key": "INSERISCI_LA_TUA_API_KEY_IPQUALITYSCORE"
}
```

⚠️ Se una chiave API non è configurata, le relative funzioni saranno disattivate automaticamente.

---

## 🖥️ Utilizzo

Esegui il programma da terminale:

```bash
python MS17OSINT.py [opzioni]
```

### Opzioni disponibili:

| Flag | Descrizione |
|------|--------------|
| `-d`, `--domain` | Analizza un dominio (es: `example.com`) |
| `-i`, `--ip` | Analizza un indirizzo IP |
| `-e`, `--email` | Analizza un indirizzo email |
| `-u`, `--username` | Ricerca un username sui social media |
| `-c`, `--config` | Specifica un file di configurazione (default: `config.json`) |
| `-o`, `--output` | Specifica il nome del file di output |
| `-f`, `--format` | Formato del report (`json`, `csv`, `txt`) |
| `--all` | Esegue tutte le analisi disponibili in modo automatico |
| `-v`, `--verbose` | Abilita log dettagliati su console |

---

## 🔍 Esempi d'uso

### Analisi di un dominio
```bash
python MS17OSINT.py -d example.com
```

### Analisi di un IP
```bash
python MS17OSINT.py -i 8.8.8.8
```

### Analisi email
```bash
python MS17OSINT.py -e test@example.com
```

### Ricerca di un username
```bash
python MS17OSINT.py -u johnsmith
```

### Analisi completa di un dominio con tutte le API e report in TXT
```bash
python MS17OSINT.py -d example.com --all -f txt
```

---

## 📊 Output e Report

Al termine dell’esecuzione, verrà generato un report nella directory corrente:
- `osint_report_<data>.json`
- `osint_report_<data>.csv`
- `osint_report_<data>.txt`

Esempio di riepilogo a schermo:

```
📋 RIEPILOGO 
============================================
🌐 Dominio: example.com
  Registrar: NameCheap Inc.
  IP risolto: 93.184.216.34
📍 IP: USA (Cloudflare)
📧 Email: Sicura, nessun breach noto
👥 Social Media: Profilo GitHub trovato
============================================
```

---

## 💻 Installazione rapida su Kali Linux

```bash
git clone https://github.com/MS17YT/OSINT-TOOL
cd OSINT-TOOL
pip install -r requirements.txt
python MS17OSINT.py -h
```

Crea il file `config.json` con le tue API key e inizia l’analisi.

---

## 🧠 Architettura interna

- **Classe principale:** `OSINTPro`
- **Metodi principali:**
  - `domain_intel()` – Analizza domini
  - `ip_intel()` – Analizza IP
  - `email_intel()` – Analizza email
  - `social_intel()` – Ricerca social
  - `generate_report()` – Crea report strutturati
  - `print_summary()` – Mostra il riepilogo

Logging automatico su `osint_pro.log`  
Gestione retry, timeouts e error handling avanzato.

---

## 🪪 Crediti

- Sviluppato da **[MS17]**
- Versione corrente: **1.0**
- Licenza: **MIT License**

---

## ⚠️ Disclaimer

> Questo strumento è destinato **solo a scopi di ricerca e cybersecurity etica**.  
> L’uso improprio per attività non autorizzate o dannose è **strettamente vietato**.  
> L’autore **non si assume responsabilità** per un utilizzo scorretto del software.

---
