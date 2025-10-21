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

🚀 Installazione
Clona il Repository

git clone https://github.com/tuo-username/OSINT-TOOL.git
cd OSINT-TOOL

Installa le Dipendenze

pip install -r requirements.txt

File delle Dipendenze (requirements.txt)

requests>=2.28.0
dnspython>=2.2.0
python-whois>=0.8.0
argparse>=1.4.0

1. Configurazione API Keys

{
  "virustotal_api_key": "tua_chiave_virustotal",      <---------- Sostituisi con le API key
  "shodan_api_key": "tua_chiave_shodan", 
  "abuseipdb_api_key": "tua_chiave_abuseipdb",
  "hibp_api_key": "tua_chiave_hibp",
  "hunter_api_key": "tua_chiave_hunter"
}

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

💡 Utilizzo Rapido
Analisi Dominio
bash

python Osint.py -d example.com

Ricerca Username
bash

python Osint.py -u username

Analisi Completa
bash

python Osint.py -d example.com --all -v


