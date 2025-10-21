🌐 Analisi Dominio Completa

    WHOIS Information: Registrar, date di registrazione, name server

    DNS Records: A, AAAA, MX, TXT, NS, CNAME, SOA

    SSL Certificate Analysis: Subject, issuer, date di scadenza

    VirusTotal Integration: Report completo di sicurezza

    Risoluzione IP: Mappatura dominio → indirizzo IP

📍 Analisi IP Avanzata

    Geolocalizzazione: Paese, città, ISP, coordinate

    Shodan Integration: Porte aperte, servizi, vulnerabilità

    AbuseIPDB Check: Reputazione e report di abuso

    Reverse DNS: Risoluzione nome host

📧 Investigazione Email

    Validazione Formato: Controllo sintattico e MX records

    Have I Been Pwned: Verifica violazioni dati

    Hunter.io Integration: Verifica esistenza email

    Reputazione: Controllo blacklist e servizi anti-spam

👥 Ricerca Social Media

    30+ Piattaforme: GitHub, Twitter, Instagram, Facebook, LinkedIn, Reddit, YouTube, TikTok e altre

    Multi-threading: Ricerche parallele per performance ottimali

    Verifica Esistenza: Controllo presenza username cross-platform

🚀 Installazione
Prerequisiti

    Python 3.8 o superiore

    Connessione internet

    API keys (opzionali ma consigliate)

Installazione Dipendenze
bash

# Clona il repository
git clone https://github.com/tuo-username/osint-pro.git
cd osint-pro

# Installa le dipendenze
pip install -r requirements.txt

File delle Dipendenze (requirements.txt)
text

requests>=2.28.0
dnspython>=2.2.0
python-whois>=0.8.0
argparse>=1.4.0

⚙️ Configurazione
1. Configurazione API Keys

Crea il file config.json nella root del progetto:
json

{
  "virustotal_api_key": "tua_chiave_virustotal",
  "shodan_api_key": "tua_chiave_shodan",
  "abuseipdb_api_key": "tua_chiave_abuseipdb",
  "hibp_api_key": "tua_chiave_hibp",
  "hunter_api_key": "tua_chiave_hunter"
}

2. Come Ottenere le API Keys
Servizio	URL	Costo	Limitazioni
VirusTotal	https://www.virustotal.com	Free: 500 req/giorno	Richiede account
Shodan	https://developer.shodan.io	Free: 100 risultati/query	Credit-based
AbuseIPDB	https://www.abuseipdb.com	Free: 1,000 req/giorno	Daily limits
HIBP	https://haveibeenpwned.com/API/Key	Free	Rate limiting
Hunter.io	https://hunter.io/api-keys	Free: 50 req/mese	Monthly limits
💡 Utilizzo
Analisi Dominio
bash

python Osint.py -d example.com
python Osint.py -d google.com -o report_google.json
python Osint.py -d target.com --all -f csv -v

Analisi IP
bash

python Osint.py -i 8.8.8.8
python Osint.py -i 192.168.1.1 -o ip_report.json

Investigazione Email
bash

python Osint.py -e test@example.com
python Osint.py -e admin@company.com -f txt

Ricerca Social Media
bash

python Osint.py -u john_doe
python Osint.py -u target_username -o social_report.json

Analisi Completa
bash

# Analisi completa di un dominio (dominio + IP + email dal WHOIS)
python Osint.py -d target.com --all -v

📊 Opzioni della Command Line
Opzione	Descrizione	Esempio
-d, --domain	Analizza un dominio	-d example.com
-i, --ip	Analizza un indirizzo IP	-i 8.8.8.8
-e, --email	Analizza un'email	-e test@example.com
-u, --username	Cerca username sui social	-u john_doe
--all	Esegui analisi completa	-d example.com --all
-o, --output	File di output personalizzato	-o mio_report.json
-f, --format	Formato output (json/csv/txt)	-f csv
-c, --config	File configurazione personalizzato	-c my_config.json
-v, --verbose	Output dettagliato	-v
-h, --help	Mostra help	-h
📋 Esempi di Output
Esempio Analisi Dominio
json

{
  "domain": {
    "whois": {
      "registrar": "MarkMonitor Inc.",
      "creation_date": "1997-09-15 00:00:00",
      "expiration_date": "2028-09-14 00:00:00",
      "name_servers": ["ns1.google.com", "ns2.google.com"]
    },
    "dns": {
      "A": ["216.58.206.78"],
      "MX": ["aspmx.l.google.com"],
      "TXT": ["v=spf1 include:_spf.google.com ~all"]
    },
    "ssl": {
      "subject": {"commonName": "*.google.com"},
      "issuer": {"commonName": "GTS CA 1C3"},
      "not_after": "2024-12-31 23:59:59"
    },
    "resolved_ip": "216.58.206.78"
  }
}

Esempio Analisi IP
json

{
  "ip": {
    "geolocation": {
      "country": "United States",
      "city": "Mountain View",
      "isp": "Google LLC",
      "asn": "AS15169 Google LLC"
    },
    "abuseipdb": {
      "data": {
        "abuseConfidenceScore": 0,
        "isWhitelisted": true
      }
    }
  }
}

🛡️ Funzionalità di Sicurezza

    Validazione Input: Sanitizzazione di tutti gli input utente

    Rate Limiting: Gestione automatica dei limiti API

    Gestione Errori: Robust error handling con retry mechanism

    Logging Sicuro: Nessuna esposizione di API keys nei log

    Timeout Configurabili: Prevenzione hanging requests

    ⚠️ Disclaimer e Avvertenze Legali
❗ Importante

    Utilizzo Etico: Questo tool è progettato per scopi legittimi di sicurezza e ricerca

    Compliance Legale: Rispettare le leggi locali sulla privacy e protezione dati

    Autorizzazioni: Ottenere il permesso prima di testare domini/IP di terzi

    Rate Limiting: Rispettare i termini di servizio delle API integrate

    Educational Use: Utilizzare solo in ambienti controllati e per apprendimento

Casi d'Uso Approvati

    ✅ Penetration testing autorizzati

    ✅ Ricerca accademica e educativa

    ✅ Security assessment di proprietà proprie

    ✅ Digital forensics investigative

    ✅ Red team exercises

Casi d'Uso NON Approvati

    ❌ Attacchi a sistemi senza autorizzazione

    ❌ Violazione della privacy altrui

    ❌ Attività di hacking non etiche

    ❌ Spionaggio industriale

    ❌ Qualsiasi attività illegale

🐛 Risoluzione Problemi
Errori Comuni e Soluzioni

Problema: ModuleNotFoundError
bash

# Soluzione: Installa le dipendenze mancanti
pip install requests dnspython python-whois

Problema: SSL Certificate Error
bash

# Soluzione: Aggiorna certificati Python
pip install --upgrade certifi

Problema: API Rate Limit Exceeded
bash

# Soluzione: Aspetta o usa API key diverse
# Il tool gestisce automaticamente i retry

Problema: DNS Resolution Failed
bash

# Soluzione: Verifica connessione internet e DNS
nslookup example.com

Logging e Debug
bash

# Abilita logging verboso
python Osint.py -d example.com -v

# Controlla il file di log
tail -f osint_pro.log

🔄 Sviluppi Futuri

    Integrazione Threat Intelligence

    Supporto più piattaforme social

    Analisi immagini e metadati

    Dashboard web-based

    Plugin system per estensioni

    Machine learning integration

🤝 Contribuire

Le contribuzioni sono benvenute! Per contribuire:

    Fork del progetto

    Crea un branch per la feature (git checkout -b feature/AmazingFeature)

    Commit delle modifiche (git commit -m 'Add AmazingFeature')

    Push del branch (git push origin feature/AmazingFeature)

    Apri una Pull Request

📄 Licenza

Distribuito sotto licenza MIT. Vedi LICENSE per maggiori informazioni.
👨‍💻 Autore

MS17 - GitHub Profile
🙏 Ringraziamenti

    VirusTotal per l'API di sicurezza

    Shodan per i dati di intelligence

    AbuseIPDB per i report di reputazione

    Have I Been Pwned per il breach monitoring

    Hunter.io per la verifica email

⭐ Se ti piace questo progetto, per favore lascia una stella su GitHub!

Per domande o supporto, apri una issue sul repository.

