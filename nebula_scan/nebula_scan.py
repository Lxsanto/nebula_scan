import asyncio
import aiohttp
import aiodns
import time
import logging
import socket
import ssl
import ipaddress
import argparse
import re
from colorama import Fore, Style, init
import json
import csv
import sys
import configparser
from pathlib import Path

# Inizializzazione di Colorama e logging
init(autoreset=True)

# Configurazione del logging avanzato
logger = logging.getLogger('orizon')
logger.setLevel(logging.DEBUG)  # Livello di logging globale

# Formatter personalizzato
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

# File Handler per il file di log
file_handler = logging.FileHandler('orizon.log', mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Stream Handler per la console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# Aggiunta dei gestori al logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)


BANNER = f"""
{Fore.GREEN}


 ▒█████   ██▀███   ██▓▒███████▒ ▒█████   ███▄    █ 
▒██▒  ██▒▓██ ▒ ██▒▓██▒▒ ▒ ▒ ▄▀░▒██▒  ██▒ ██ ▀█   █ 
▒██░  ██▒▓██ ░▄█ ▒▒██▒░ ▒ ▄▀▒░ ▒██░  ██▒▓██  ▀█ ██▒
▒██   ██░▒██▀▀█▄  ░██░  ▄▀▒   ░▒██   ██░▓██▒  ▐▌██▒
░ ████▓▒░░██▓ ▒██▒░██░▒███████▒░ ████▓▒░▒██░   ▓██░
░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░▓  ░▒▒ ▓░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ░ ▒ ▒░   ░▒ ░ ▒░ ▒ ░░░▒ ▒ ░ ▒  ░ ▒ ▒░ ░ ░░   ░ ▒░
░ ░ ░ ▒    ░░   ░  ▒ ░░ ░ ░ ░ ░░ ░ ░ ▒     ░   ░ ░ 
    ░ ░     ░      ░    ░ ░        ░ ░           ░ 
                      ░                            

{Fore.RED}  [ Orizon - The Ultra-Fast Subdomain & Email Scanner ]
{Fore.CYAN}  [ Developed by Luca Lorenzi ]
{Fore.YELLOW}  [!] Use responsibly and only with explicit permission 

{Fore.LIGHTBLUE_EX}>>> Join our Community! <<< 
{Fore.LIGHTMAGENTA_EX}>>> Visit: orizon.one <<< {Style.RESET_ALL}
"""



class SubdomainFinder:
    """
    Classe per trovare sottodomini di un dominio specifico utilizzando sia metodi passivi che attivi.
    """

    def __init__(self, domain, wordlist=None, output_format='txt', verbose=False, api_keys=None, proxies=None):
        self.domain = domain
        self.subdomains = {}
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(500)  # Limitazione delle attività concorrenti
        self.wordlist = wordlist if wordlist else self.load_default_wordlist()
        self.output_format = output_format
        self.verbose = verbose
        self.api_keys = api_keys if api_keys else {}
        self.proxies = proxies
        self.dns_semaphore = asyncio.Semaphore(100)
        self.passive_services = [
            self.crt_sh_enumeration,
            self.virustotal_enumeration,
            self.alienvault_enumeration,
            self.threatcrowd_enumeration,
            self.hackertarget_enumeration,
            self.securitytrails_enumeration,
            self.censys_enumeration
        ]

    async def run(self):
        """
        Avvia il processo di scansione dei sottodomini.
        """
        start_time = time.time()
        async with aiohttp.ClientSession() as session:
            self.session = session
            tasks = [
                self.passive_enumeration(),
                self.bruteforce_subdomains()
            ]
            await asyncio.gather(*tasks)
            await self.get_additional_info()
        end_time = time.time()
        logger.info(f"[*] Tempo totale: {end_time - start_time:.2f} secondi")
        return self.subdomains

    async def passive_enumeration(self):
        """
        Esegue l'enumerazione passiva utilizzando servizi online.
        """
        tasks = [service() for service in self.passive_services]
        await asyncio.gather(*tasks)

    async def crt_sh_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando crt.sh.
        """
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        retries = 3
        backoff = 5
        for attempt in range(retries):
            try:
                async with self.session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        for entry in data:
                            name_value = entry.get('name_value')
                            if name_value:
                                subdomains = name_value.split('\n')
                                for subdomain in subdomains:
                                    await self.add_subdomain(subdomain.strip(), "crt.sh")
                        break  # Uscire dal ciclo se la richiesta ha successo
                    else:
                        logger.warning(f"crt.sh ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione crt.sh, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))  # Backoff esponenziale
                else:
                    logger.error("Enumerazione crt.sh fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione crt.sh: {e}")
                break

    async def virustotal_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando VirusTotal.
        Richiede una chiave API.
        """
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            logger.warning("Chiave API per VirusTotal non fornita. Saltando l'enumerazione VirusTotal.")
            return

        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": api_key}
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.get(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get('data', []):
                            await self.add_subdomain(item.get('id'), "VirusTotal")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per VirusTotal.")
                        break
                    else:
                        logger.warning(f"VirusTotal ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione VirusTotal, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione VirusTotal fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione VirusTotal: {e}")
                break

    async def alienvault_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando AlienVault OTX.
        """
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data.get('passive_dns', []):
                            hostname = entry.get('hostname')
                            if hostname:
                                await self.add_subdomain(hostname, "AlienVault")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per AlienVault.")
                        break
                    else:
                        logger.warning(f"AlienVault ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione AlienVault, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione AlienVault fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione AlienVault: {e}")
                break

    async def threatcrowd_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando ThreatCrowd.
        """
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for subdomain in data.get('subdomains', []):
                            await self.add_subdomain(subdomain, "ThreatCrowd")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per ThreatCrowd.")
                        break
                    else:
                        logger.warning(f"ThreatCrowd ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione ThreatCrowd, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione ThreatCrowd fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione ThreatCrowd: {e}")
                break

    async def hackertarget_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando HackerTarget.
        """
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.text()
                        for line in data.splitlines():
                            if line:
                                subdomain = line.split(',')[0]
                                await self.add_subdomain(subdomain, "HackerTarget")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per HackerTarget.")
                        break
                    else:
                        logger.warning(f"HackerTarget ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione HackerTarget, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione HackerTarget fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione HackerTarget: {e}")
                break

    async def securitytrails_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando SecurityTrails.
        Richiede una chiave API.
        """
        api_key = self.api_keys.get('securitytrails')
        if not api_key:
            logger.warning("Chiave API per SecurityTrails non fornita. Saltando l'enumerazione SecurityTrails.")
            return

        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": api_key}
        params = {"children_only": "false"}
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.get(url, headers=headers, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for subdomain in data.get('subdomains', []):
                            full_domain = f"{subdomain}.{self.domain}"
                            await self.add_subdomain(full_domain, "SecurityTrails")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per SecurityTrails.")
                        break
                    else:
                        logger.warning(f"SecurityTrails ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione SecurityTrails, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione SecurityTrails fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione SecurityTrails: {e}")
                break

    async def censys_enumeration(self):
        """
        Enumerazione dei sottodomini utilizzando Censys.
        Richiede una chiave API.
        """
        api_id = self.api_keys.get('censys_id')
        api_secret = self.api_keys.get('censys_secret')
        if not api_id or not api_secret:
            logger.warning("Credenziali API per Censys non fornite. Saltando l'enumerazione Censys.")
            return

        url = "https://search.censys.io/api/v2/hosts/search"
        headers = {"Content-Type": "application/json"}
        auth = aiohttp.BasicAuth(login=api_id, password=api_secret)
        data = {
            "q": self.domain,
            "per_page": 100
        }
        retries = 3
        backoff = 5

        for attempt in range(retries):
            try:
                async with self.session.post(url, headers=headers, auth=auth, json=data, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for result in data.get('result', {}).get('hits', []):
                            subdomain = result.get('name')
                            if subdomain:
                                await self.add_subdomain(subdomain, "Censys")
                        break
                    elif response.status == 429:
                        logger.warning("Limite di richieste raggiunto per Censys.")
                        break
                    else:
                        logger.warning(f"Censys ha restituito lo status {response.status}")
            except asyncio.TimeoutError:
                logger.warning(f"Timeout durante l'enumerazione Censys, tentativo {attempt + 1} di {retries}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))
                else:
                    logger.error("Enumerazione Censys fallita dopo diversi tentativi.")
            except aiohttp.ClientError as e:
                logger.error(f"Errore durante l'enumerazione Censys: {e}")
                break

    async def bruteforce_subdomains(self):
        """
        Esegue un attacco di forza bruta per trovare sottodomini utilizzando una wordlist.
        """
        tasks = [self.check_subdomain(subdomain) for subdomain in self.wordlist]
        await asyncio.gather(*tasks)

    async def check_subdomain(self, subdomain):
        """
        Verifica se un sottodominio esiste tentando di risolverlo.
        """
        full_domain = f"{subdomain}.{self.domain}"
        try:
            async with self.semaphore:
                await self.resolver.gethostbyname(full_domain, socket.AF_INET)
            await self.add_subdomain(full_domain, "Bruteforce")
            return True
        except aiodns.error.DNSError:
            return False

    async def add_subdomain(self, subdomain, source):
        """
        Aggiunge un sottodominio alla lista se non già presente.
        """
        if subdomain.endswith(self.domain) and subdomain != self.domain:
            if subdomain.startswith('*.'):
                subdomain = subdomain[2:]
            if subdomain not in self.subdomains:
                self.subdomains[subdomain] = {"source": source}
                if self.verbose:
                    print(f"{Fore.GREEN}[+] Trovato: {subdomain} {Fore.YELLOW}(Fonte: {source}){Style.RESET_ALL}")
                logger.info(f"Trovato: {subdomain} (Fonte: {source})")

    async def get_additional_info(self):
        """
        Raccoglie informazioni aggiuntive per ogni sottodominio trovato.
        """
        tasks = [self.get_info(subdomain) for subdomain in self.subdomains]
        await asyncio.gather(*tasks)

    async def get_info(self, subdomain):
        """
        Ottiene informazioni come IP, porte aperte, informazioni SSL e HTTP per un sottodominio.
        """
        try:
            async with self.dns_semaphore:
                answers = await self.resolver.gethostbyname(subdomain, socket.AF_INET)
                ip = answers.addresses[0]

            self.subdomains[subdomain]["ip"] = ip

            is_internal = ipaddress.ip_address(ip).is_private
            self.subdomains[subdomain]["is_internal"] = is_internal

            open_ports = await self.check_ports(ip)
            self.subdomains[subdomain]["open_ports"] = open_ports

            if 80 in open_ports:
                self.subdomains[subdomain]["http_server"] = await self.get_http_server(subdomain)

            if 443 in open_ports:
                ssl_info = await self.get_ssl_info(subdomain)
                self.subdomains[subdomain].update(ssl_info)

        except Exception as e:
            logger.error(f"Errore ottenendo informazioni per {subdomain}: {e}")
            self.subdomains[subdomain]["info"] = f"Errore: {e}"

    async def check_ports(self, ip):
        """
        Verifica le porte comuni per vedere se sono aperte.
        """
        open_ports = []
        common_ports = [80, 443, 8080, 8443, 22, 21, 25, 587, 3306, 5432]
        tasks = [self.check_port(ip, port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        for port, is_open in zip(common_ports, results):
            if is_open:
                open_ports.append(port)
        return open_ports

    async def check_port(self, ip, port):
        """
        Verifica se una porta specifica è aperta su un IP.
        """
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def get_http_server(self, subdomain):
        """
        Ottiene l'intestazione 'Server' da un server HTTP.
        """
        try:
            async with self.session.get(f"http://{subdomain}", timeout=5) as response:
                return response.headers.get('Server', 'N/A')
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return "N/A"

    async def get_ssl_info(self, subdomain):
        """
        Ottiene informazioni sul certificato SSL di un server HTTPS.
        """
        try:
            context = ssl.create_default_context()
            async with self.session.get(f"https://{subdomain}", ssl=context, timeout=5) as response:
                connection = response.connection
                if connection and connection.transport:
                    cert = connection.transport.get_extra_info('peercert')
                    ssl_object = connection.transport.get_extra_info('ssl_object')
                    ssl_version = ssl_object.version() if ssl_object else "N/A"
                    ssl_info = {
                        "ssl_issuer": dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                        "ssl_subject": dict(x[0] for x in cert.get('subject', [])) if cert else {},
                        "ssl_version": ssl_version
                    }
                else:
                    ssl_info = {"ssl_issuer": {}, "ssl_subject": {}, "ssl_version": "N/A"}
                return ssl_info
        except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError):
            return {"ssl_issuer": {}, "ssl_subject": {}, "ssl_version": "N/A"}



    def load_default_wordlist(self):
        """
        Carica la wordlist predefinita per la forza bruta dei sottodomini.
        """
        return ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
                'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
                'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
                'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2',
                'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server',
                'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host',
                'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote',
                'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa',
                'en', 'start', 'sms', 'office', 'exchange', 'ipv4']

    def load_wordlist_from_file(self, filepath):
        """
        Carica una wordlist personalizzata da un file.
        """
        try:
            with open(filepath, 'r') as file:
                words = [line.strip() for line in file if line.strip()]
            return words
        except FileNotFoundError:
            logger.error(f"File wordlist non trovato: {filepath}")
            return self.load_default_wordlist()

class EmailEnumerator:
    def __init__(self, subdomains, verbose=False):
        self.subdomains = subdomains
        self.verbose = verbose
        self.emails = set()
        self.semaphore = asyncio.Semaphore(10)  # Limitazione delle richieste concorrenti

    async def run(self):
        async with aiohttp.ClientSession() as session:
            self.session = session
            tasks = [self.enumerate_emails(subdomain) for subdomain in self.subdomains]
            await asyncio.gather(*tasks)
        return self.emails

    async def enumerate_emails(self, subdomain):
        """
        Effettua richieste HTTP/HTTPS al sottodominio e cerca indirizzi email.
        """
        for protocol in ['http', 'https']:
            try:
                async with self.semaphore:
                    async with self.session.get(f"{protocol}://{subdomain}", timeout=10) as response:
                        content = await response.text()
                        emails = self.extract_emails(content)
                        if emails:
                            self.emails.update(emails)
                            if self.verbose:
                                print(f"{Fore.GREEN}[+] Emails trovate su {subdomain}: {emails}{Style.RESET_ALL}")
                            logger.info(f"Emails trovate su {subdomain}: {emails}")
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[-] Impossibile connettersi a {protocol}://{subdomain}: {e}{Style.RESET_ALL}")
                logger.debug(f"Errore durante il fetch di {protocol}://{subdomain}: {e}")

    def extract_emails(self, text):
        """
        Estrae indirizzi email utilizzando regex.
        """
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        return set(re.findall(email_pattern, text))

def save_results(subdomains, domain, output_format):
    """
    Salva i risultati in un file nel formato specificato.
    """
    output_file = f"{domain}.{output_format}"

    if output_format == 'txt':
        with open(output_file, 'w') as f:
            for subdomain, info in subdomains.items():
                f.write(f"Subdomain: {subdomain}\n")
                for key, value in info.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")
    elif output_format == 'json':
        with open(output_file, 'w') as f:
            json.dump(subdomains, f, indent=4)
    elif output_format == 'csv':
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['subdomain'] + list(next(iter(subdomains.values())).keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subdomain, info in subdomains.items():
                row = {'subdomain': subdomain}
                row.update(info)
                writer.writerow(row)
    elif output_format == 'html':
        # Generazione di un report HTML
        generate_html_report(subdomains, domain)
    else:
        logger.error(f"Formato di output non supportato: {output_format}")
        return

    logger.info(f"[*] Scansione completata. Risultati salvati in {output_file}")

def generate_html_report(subdomains, domain):
    """
    Genera un report in formato HTML.
    """
    output_file = f"{domain}.html"
    html_content = f"""
    <html>
    <head>
        <title>Report di scansione per {domain}</title>
    </head>
    <body>
        <h1>Report di scansione per {domain}</h1>
        <table border="1">
            <tr>
                <th>Sottodominio</th>
                <th>IP</th>
                <th>Fonte</th>
                <th>Porte Aperte</th>
                <th>SSL Info</th>
                <th>HTTP Server</th>
            </tr>
    """

    for subdomain, info in subdomains.items():
        ssl_info = info.get('ssl_issuer', {}).get('commonName', 'N/A') if info.get('ssl_issuer') else 'N/A'
        open_ports = ', '.join(map(str, info.get('open_ports', [])))
        http_server = info.get('http_server', 'N/A')
        html_content += f"""
            <tr>
                <td>{subdomain}</td>
                <td>{info.get('ip', 'N/A')}</td>
                <td>{info.get('source', 'N/A')}</td>
                <td>{open_ports}</td>
                <td>{ssl_info}</td>
                <td>{http_server}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(output_file, 'w') as f:
        f.write(html_content)
    logger.info(f"[*] Report HTML generato: {output_file}")

def display_recap(subdomains, emails_found, start_time, end_time):
    total_subdomains = len(subdomains)
    total_emails = len(emails_found)
    duration = end_time - start_time

    print(f"{Fore.CYAN}\n--- Recap ---{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] SUBDOMAIN: {total_subdomains}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] EMAIL: {total_emails}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] TIME: {duration:.2f} secondi{Style.RESET_ALL}")
    print(f"{Fore.CYAN}----------------{Style.RESET_ALL}")

async def main():
    parser = argparse.ArgumentParser(description="Orizon - The Ultra-Fast Subdomain Scanner by Luca Lorenzi")
    parser.add_argument("-d", "--domain", help="Il dominio da cercare per i sottodomini")
    parser.add_argument("-w", "--wordlist", help="Percorso alla wordlist personalizzata")
    parser.add_argument("-o", "--output", help="Formato di output (txt, json, csv, html)", default='txt')
    parser.add_argument("-v", "--verbose", help="Modalità verbosa", action='store_true')
    parser.add_argument("--vt_api_key", help="Chiave API per VirusTotal")
    parser.add_argument("--st_api_key", help="Chiave API per SecurityTrails")
    parser.add_argument("--censys_id", help="ID API per Censys")
    parser.add_argument("--censys_secret", help="Secret API per Censys")
    parser.add_argument("-e", "--email-enum", help="Esegui l'enumerazione delle email dopo la scansione dei sottodomini", action='store_true')
    parser.add_argument("--subdomains-file", help="Percorso al file .txt con i sottodomini da utilizzare per l'enumerazione delle email")
    parser.add_argument("--proxy", help="Utilizza un proxy per le richieste (es. http://127.0.0.1:8080)")
    args = parser.parse_args()

    print(BANNER)

    if not args.domain and not args.subdomains_file:
        parser.error("Devi specificare almeno un dominio (-d) o un file di sottodomini (--subdomains-file).")

    if args.domain:
        logger.info(f"{Fore.CYAN}[*] Inizio scansione per {args.domain}{Style.RESET_ALL}")
    else:
        logger.info(f"{Fore.CYAN}[*] Inizio enumerazione email per i sottodomini forniti{Style.RESET_ALL}")

    api_keys = {
        'virustotal': args.vt_api_key,
        'securitytrails': args.st_api_key,
        'censys_id': args.censys_id,
        'censys_secret': args.censys_secret
    }

    proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None

    finder = SubdomainFinder(
        args.domain,
        wordlist=SubdomainFinder.load_wordlist_from_file(SubdomainFinder, args.wordlist) if args.wordlist else None,
        output_format=args.output,
        verbose=args.verbose,
        api_keys=api_keys,
        proxies=proxies
    )

    start_time = time.time()  # Inizio del timer

    subdomains = {}
    if args.domain:
        subdomains = await finder.run()
        logger.info(f"{Fore.CYAN}[*] Totale sottodomini trovati: {len(subdomains)}{Style.RESET_ALL}")
        save_results(subdomains, args.domain, args.output)

    emails_found = set()
    if args.email_enum:
        logger.info(f"{Fore.CYAN}[*] Inizio l'enumerazione delle email.{Style.RESET_ALL}")
        if args.subdomains_file:
            try:
                with open(args.subdomains_file, 'r') as f:
                    subdomains_list = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logger.error(f"File dei sottodomini non trovato: {args.subdomains_file}")
                sys.exit(1)
        else:
            subdomains_list = list(subdomains.keys())

        email_enumerator = EmailEnumerator(subdomains_list, verbose=args.verbose)
        emails_found = await email_enumerator.run()
        logger.info(f"{Fore.CYAN}[*] Totale email trovate: {len(emails_found)}{Style.RESET_ALL}")
        email_output_file = f"{args.domain}_emails.txt" if args.domain else "emails.txt"
        with open(email_output_file, 'w') as f:
            for email in emails_found:
                f.write(email + '\n')
        logger.info(f"{Fore.CYAN}[*] Email salvate in {email_output_file}{Style.RESET_ALL}")

    end_time = time.time()  # Fine del timer

    display_recap(subdomains, emails_found, start_time, end_time)

if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("Questo script richiede Python 3.7 o superiore.")
        sys.exit(1)
    asyncio.run(main())
