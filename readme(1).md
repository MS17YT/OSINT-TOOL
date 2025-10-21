# 🕵️‍♂️ MS17 OSINT TOOL v2.3
### Advanced Open Source Intelligence Framework con Geolocalizzazione GSM

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-2.3-orange.svg)

---

## 📖 Descrizione

**MS17 OSINT TOOL** è un framework avanzato di **Open Source Intelligence (OSINT)** scritto in **Python 3**, progettato per analizzare domini, indirizzi IP, email, username sui social e, in aggiunta, eseguire **geolocalizzazione GSM tramite celle mobili** (tramite l’API di UnwiredLabs).

Il tool consente di raccogliere informazioni provenienti da fonti pubbliche e API esterne (VirusTotal, Shodan, AbuseIPDB, HIBP, Hunter.io, UnwiredLabs) in modo automatico, producendo report dettagliati in **JSON**, **CSV** o **TXT**.

---

## ⚙️ Funzionalità Principali

| Categoria | Descrizione |
|------------|-------------|
| 🌐 **Domain Intelligence** | WHOIS lookup, DNS records, SSL certificate, VirusTotal analysis |
| 📍 **IP Intelligence** | IP geolocation, Shodan scan, AbuseIPDB reputation |
| 📧 **Email Intelligence** | Validazione MX, breach check (HIBP), verifica Hunter.io |
| 👤 **Social Intelligence** | Ricerca automatica di username su oltre 10 piattaforme social |
| 📡 **GSM Geolocation** | Geolocalizzazione celle GSM (MCC, MNC, LAC, CID) con UnwiredLabs |
| 🧾 **Report Generation** | Esportazione risultati in JSON / CSV / TXT |
| 🧠 **Validazione Input** | Controlli robusti su domini, IP, email, username e formati GSM |

---

## 🧩 Installazione

```bash
git clone https://github.com/<tuo-username>/MS17OSINT.git
cd MS17OSINT
pip install -r requirements.txt
```

> ⚠️ Il tool richiede **Python 3.9+** e la libreria `dnspython`.

---

## 🔑 Configurazione API

Crea un file `config.json` nella directory principale:

```json
{
  "virustotal_api_key": "tua_chiave_virustotal",
  "shodan_api_key": "tua_chiave_shodan",
  "abuseipdb_api_key": "tua_chiave_abuseipdb",
  "hibp_api_key": "tua_chiave_hibp",
  "hunter_api_key": "tua_chiave_hunter",
  "unwiredlabs_api_key": "tua_chiave_unwiredlabs"
}
```

Puoi ottenere le chiavi API dai rispettivi servizi ufficiali.

---

## 🚀 Utilizzo

### Analisi di un dominio
```bash
python3 MS17OSINT.py -d example.com
```

### Analisi di un indirizzo IP
```bash
python3 MS17OSINT.py -i 8.8.8.8
```

### Analisi di un indirizzo email
```bash
python3 MS17OSINT.py -e test@example.com
```

### Ricerca di un username sui social
```bash
python3 MS17OSINT.py -u johndoe
```

### Geolocalizzazione GSM (celle)
Puoi fornire i dati GSM in vari formati:

```bash
python3 MS17OSINT.py -g "mcc:222,mnc:1,lac:1234,cid:5678"
```

oppure:

```bash
python3 MS17OSINT.py --mcc 222 --mnc 1 --lac 1234 --cid 5678
```

Esempio di output:

```
[📡] Geolocalizzazione GSM avviata per cella: MCC=222, MNC=1, LAC=1234, CID=5678
Posizione: 45.4642, 9.19
Indirizzo: Milano, Italia
Accuratezza: 350 metri
```

---

## 📊 Generazione Report

Puoi scegliere il formato del report (`json`, `csv`, `txt`):

```bash
python3 MS17OSINT.py -d example.com -f csv -o risultato
```

Il file verrà salvato come:
```
risultato.csv
```

---

## 🧠 Modalità Completa

Esegui un’analisi completa con un solo comando:

```bash
python3 MS17OSINT.py --all -d example.com
```

Il tool:
- Analizza il dominio e risolve l’IP
- Esegue IP intelligence
- Analizza email trovate nel WHOIS
- Genera automaticamente il report

---

## 🧩 Argomenti CLI Supportati

| Opzione | Descrizione |
|----------|-------------|
| `-d, --domain` | Analizza un dominio |
| `-i, --ip` | Analizza un IP |
| `-e, --email` | Analizza un'email |
| `-u, --username` | Ricerca username sui social |
| `-g, --gsm` | Analizza cella GSM (mcc,mnc,lac,cid) |
| `--mcc --mnc --lac --cid` | Parametri GSM separati |
| `--signal` | Intensità segnale (opzionale, in dBm) |
| `-f, --format` | Formato report (json/csv/txt) |
| `-o, --output` | Nome file di output |
| `--all` | Analisi completa combinata |
| `-v, --verbose` | Output verboso (debug) |

---

## 🧾 Log

Tutte le operazioni e gli errori vengono salvati in:
```
osint_pro.log
```

---

## ⚠️ Disclaimer

Questo strumento è progettato **solo per scopi di sicurezza e ricerca**.  
L’autore **non si assume alcuna responsabilità** per l’uso improprio o illegale del software.

---

## 🧑‍💻 Autore

**MS17**  
> Versione: 2.3  
> Contatto: [GitHub](https://github.com/MS17)

---

### ⭐ Se trovi utile questo progetto, lascia una stella su GitHub!

---

## 🧾 Esempio di output (estratto JSON)

```json
{
  "domain": {
    "whois": {
      "registrar": "Example Registrar",
      "creation_date": "2020-01-01",
      "expiration_date": "2026-01-01",
      "name_servers": ["ns1.example.com", "ns2.example.com"],
      "emails": ["admin@example.com"]
    },
    "dns": {
      "A": ["93.184.216.34"],
      "MX": ["0 mail.example.com"]
    },
    "ssl": {
      "subject": {"commonName": "example.com"},
      "issuer": {"commonName": "Let's Encrypt"},
      "not_before": "Jan 1 00:00:00 2024 GMT",
      "not_after": "Apr 1 00:00:00 2024 GMT"
    },
    "virustotal": {...}
  },
  "ip": {
    "geolocation": {
      "country": "United States",
      "city": "Mountain View",
      "lat": 37.4056,
      "lon": -122.0775,
      "isp": "Google LLC"
    },
    "shodan": {...}
  },
  "gsm_geolocation": {
    "unwiredlabs": {
      "status": "success",
      "latitude": 45.4642,
      "longitude": 9.19,
      "accuracy": 350,
      "address": "Milano, Italy"
    },
    "operator": {
      "operator": "TIM",
      "country": "Italy",
      "network": "GSM"
    }
  }
}
```

---

## 🧰 Limitazioni e considerazioni tecniche

- La qualità della geolocalizzazione GSM dipende dalla correttezza dei parametri MCC/MNC/LAC/CID e dalla copertura del database UnwiredLabs.
- Alcuni servizi applicano rate-limiting. Il tool include delay e meccanismi di retry, ma rispettare termini di servizio è responsabilità dell’utente.
- Le API esterne possono cambiare behaviour o endpoint: mantenere le chiavi aggiornate e verificare la compatibilità delle API.
- Le funzionalità dipendono dalla presenza delle API key nel `config.json`. In mancanza di chiavi, il tool continua a fornire le analisi locali (WHOIS, DNS, SSL, parsing) ma non potrà interrogare i servizi esterni.

---

## ⚖️ Etica, legalità e responsabilità

- Usa questo strumento solo su asset per i quali hai autorizzazione (i tuoi sistemi, client di test, valutazioni di sicurezza autorizzate).
- Raccogliere dati personali e posizioni senza consenso può violare leggi locali o regolamenti (GDPR, privacy locali). L’autore e i manutentori non si assumono responsabilità per usi impropri.
- Se lavori in un contesto aziendale, assicurati di avere un incarico scritto che autorizzi gli accertamenti.

---

## 🐞 Debugging & Troubleshooting

- Controlla `osint_pro.log` per messaggi estesi e stack trace.
- Errori comuni:
  - `FileNotFoundError: config.json` → crea il file `config.json` con le chiavi necessarie.
  - Rate limit / 429 → attendere o ridurre la frequenza delle richieste; lo script incorpora ritentativi esponenziali.
  - Timeout rete → verifica connettività e reachability degli endpoint API.
- Per problemi DNS, prova a eseguire `dig` / `nslookup` manualmente per verificare la risolvibilità.

---

## 🔒 Sicurezza del codice

- Lo script usa `requests.Session()` e header utenti simulati per alcune richieste.
- Per SSL il codice si connette alla porta 443 e recupera il certificato; in alcuni casi la verifica viene bypassata per compatibilità (`context.verify_mode = ssl.CERT_NONE`) — ciò è stato fatto per evitare failure su server con CA inusuali. Se necessario, riconfigurare per verifica stricter.
- Evitare di inserire chiavi in repository pubblici; usare variabili d’ambiente o secret manager in contesti sensibili.

---

## 🧾 Esempi pratici (comandi)

```bash
# 1) Analisi dominio e salvataggio in JSON
python3 MS17OSINT.py -d example.com -f json -o report_example

# 2) Analisi IP con Shodan (se chiave presente)
python3 MS17OSINT.py -i 1.2.3.4

# 3) Geolocalizzazione GSM
python3 MS17OSINT.py -g "222-1-1234-5678"

# 4) Analisi completa (domain -> ip -> email dal whois)
python3 MS17OSINT.py --all -d example.com
```

---

## 📦 Contribuire

1. Fork del repository
2. Crea un branch feature (`git checkout -b feature/nome`)
3. Aggiungi test / aggiorna `README.md` / migliora logica
4. Apri una Pull Request con descrizione delle modifiche

---

## 📝 Changelog (sommario)

- **v2.3**
  - Aggiunta geolocalizzazione GSM via UnwiredLabs
  - Miglioramenti al parsing certificati SSL
  - Robustezza nelle chiamate API (retry, backoff)
  - Output CSV/TXT migliorati

---

## 📬 Contatti / Autore

- **Autore:** MS17  
- Versione: 2.3  
- Repository: `https://github.com/MS17` (sostituire con URL corretto)

---

## 📜 Licenza

Questo progetto è rilasciato sotto licenza **MIT**. Inserisci qui il file `LICENSE` se vuoi includere il testo completo.

---

## FAQ

**D: Posso usare lo script per tracciare una persona tramite telefono?**
R: Lo script può geolocalizzare una cella GSM (MCC/MNC/LAC/CID) e richiedere una posizione approssimativa tramite UnwiredLabs, ma non dovrebbe essere usato per attività di tracciamento personale senza autorizzazione. L’accuratezza e la legalità dipendono dal contesto e dall’accesso ai dati.

**D: Dove ottengo la chiave UnwiredLabs?**
R: Registrandoti su [unwiredlabs.com](https://unwiredlabs.com/) e creando un token per la loro API. (Nota: rispetta le policy del servizio.)

**D: Posso estendere il database degli operatori GSM?**
R: Sì — la funzione `get_gsm_operator_info` usa una mappa interna semplice: puoi estenderla o collegarla a un database esterno.

