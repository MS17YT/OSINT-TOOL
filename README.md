# MS17 OSINT PRO

**Versione**: 3.0  

---

## Descrizione
MS17 OSINT PRO è uno strumento Python per attività di intelligence aperta (OSINT) focalizzato su analisi di domini, indirizzi IP, email, username social e geolocalizzazione GSM. Integra molteplici sorgenti (VirusTotal, Shodan, AbuseIPDB, GreyNoise, AlienVault OTX, SecurityTrails, CIRCL PDNS, DeHashed, Leak-Lookup, HaveIBeenPwned, Hunter.io, UnwiredLabs, IPInfo e altre) e fornisce report in diversi formati.


---

## Caratteristiche principali
- Analisi dominio completa (WHOIS, DNS, SSL/TLS, subdomain enumeration, tecnologie, security headers, integrazione API).
- Analisi IP (geolocalizzazione multi-source, port scan light, threat intelligence multi-source).
- Analisi email (validazione, breach check multi-source, reputazione, discovery social via Gravatar).
- Ricerca username su più social network con analisi aggregata della presenza.
- Geolocalizzazione GSM (supporta input in vari formati e UnwiredLabs integration).
- Generazione report: JSON, CSV e TXT con metadata e timestamp.
- Logging avanzato e rotazione User-Agent per limitare rilevamento.
- Supporto opzionale a proxy (es. Tor socks5h) e gestione retry/backoff per API.

---

## Requisiti
- Python 3.8+

### Dipendenze Python
Installare le dipendenze principali (esempio pip):

```bash
pip install -r requirements.txt
```

Esempio di `requirements.txt` (da creare se non presente):
```
requests
python-whois
dnspython
fake-useragent
urllib3
```

> Alcune funzioni richiedono librerie/credenziali esterne (Shodan, VirusTotal, UnwiredLabs, ecc.).

---

## Configurazione
Il tool legge le impostazioni da `config.json` (parametro `--config` per specificarne un altro). Nel `config.json` puoi definire timeout, API key e opzioni come `deep_scan`, `user_agents_rotation`, `tor_proxy`.

Esempio minimale `config.json`:

```json
{
  "virustotal_api_key": "TUA_APY_KEY_VIRUSOTAL",
  "shodan_api_key": "TUA_API_KEY_SHODAN",
  "abuseipdb_api_key": "TUA_API_KEY_ABUSEIPD",
  "hibp_api_key": "TUA_API_KEY_HIBP",
  "hunter_api_key": "TUA_API_KEY_HUNTER",
  "unwiredlabs_api_key": "TUA_API_KEY_UNWIREDLABS",
  "ipinfo_api_key": "TUA_API_KEY_IPINFO",
  "alienvault_api_key": "TUA_API_KEY_ALIENVAULT",
  "greynoise_api_key": "TUA_API_KEY_GREYNOISE",
  "whoxy_api_key": "TUA_API_KEY_WHOXY",
  "securitytrails_api_key": "TUA_API_KEY_SECURITYTRAILS",
  "circl_api_key": "TUA_API_KEY_CIRCL",
  "leaklookup_api_key": "TUA_API_KEY_LEAKLOOKUP",
  "dehashed_api_key": "TUA_API_KEY_DEHASHED",
  "opencellid_api_key": "TUA_API_KEY_OPENCELLID",
  "timeout": 30,
  "max_threads": 15,
  "deep_scan": true,
  "rate_limit_delay": 1,
  "user_agents_rotation": true,
  "tor_proxy": "socks5h://127.0.0.1:9050"
}
```

> Il codice segnala (con log) quali API non sono configurate e disabilita le funzionalità relative.

---

## Uso
Comando generale (CLI):

```bash
python OSINT.py [opzioni]
```

Opzioni principali:
```
-d, --domain       Analizza dominio
-i, --ip           Analizza indirizzo IP
-e, --email        Analizza email
-u, --username     Ricerca username sui social
-g, --gsm          Geolocalizzazione GSM (formati: mcc,mnc,lac,cid o mcc:222,mnc:1,lac:1234,cid:5678)
--mcc --mnc --lac --cid  Parametri GSM separati
-c, --config       File di configurazione (default config.json)
-o, --output       File di output per il report
-f, --format       Formato report: json, csv, txt, all (default all)
--threads          Numero di thread per scansioni parallele (default 10)
--verbose          Output verboso / Debug
```

### Esempi
Analisi dominio con report JSON:

```bash
python OSINT.py -d example.com -o report_example -f json
```

Analisi IP e output multiplo:

```bash
python OSINT.py -i 8.8.8.8 -f all
```

Ricerca username:

```bash
python OSINT.py -u alice --threads 20
```

Geolocalizzazione GSM con stringa compatta:

```bash
python OSINT.py -g "222,10,12345,67890"
```

---

## Sicurezza e privacy
- **Uso responsabile**: lo strumento può raccogliere informazioni pubbliche su persone e infrastrutture. **Usalo solo per scopi leciti** e con autorizzazione quando necessario.
- **Rate limiting & API keys**: molte API applicano limiti di utilizzo. Inserisci le tue API key in `config.json` e rispetta i termini dei servizi.
- **Proxy/TOR**: il tool include opzioni proxy ma NON abilita automaticamente Tor; configurale con attenzione.

---

## Limitazioni note e consigli
- Alcune chiamate (Whois, DNS, API esterne) possono fallire su rete con restrizioni o senza credenziali.
- La feature di enumerazione subdomain usa una wordlist integrata semplice — per scansioni più complete si consiglia di integrare wordlist personalizzate.
- Lo scanning porte è leggero e non sostituisce strumenti dedicati come `nmap` per analisi approfondite.

---

## Contribuire
- Se vuoi contribuire, apri una issue o una PR migliorando modularità, gestione delle API keys (es. integrazione con vault), o aggiungendo test.
- Suggerimenti di miglioramento: async/await per richieste I/O, integrazione con database per caching, uso di librerie ufficiali per fingerprinting tecnologico.

---

