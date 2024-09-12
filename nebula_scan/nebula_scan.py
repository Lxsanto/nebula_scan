import asyncio
import aiohttp
import aiodns
import time
from colorama import Fore, Style, init
import socket
import ssl
import ipaddress
import argparse

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
 ███▄    █ ▓█████  ▄▄▄▄    █    ██  ██▓    ▄▄▄       ██████  ▄████▄   ▄▄▄       ███▄    █ 
 ██ ▀█   █ ▓█   ▀ ▓█████▄  ██  ▓██▒▓██▒   ▒████▄   ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
▓██  ▀█ ██▒▒███   ▒██▒ ▄██▓██  ▒██░▒██░   ▒██  ▀█▄ ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
▓██▒  ▐▌██▒▒▓█  ▄ ▒██░█▀  ▓▓█  ░██░▒██░   ░██▄▄▄▄██  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
▒██░   ▓██░░▒████▒░▓█  ▀█▓▒▒█████▓ ░██████▒▓█   ▓██▒▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
░ ▒░   ▒ ▒ ░░ ▒░ ░░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒▒   ▓▒█░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
░ ░░   ░ ▒░ ░ ░  ░▒░▒   ░ ░░▒░ ░ ░ ░ ░ ▒  ░ ▒   ▒▒ ░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
   ░   ░ ░    ░    ░    ░  ░░░ ░ ░   ░ ░    ░   ▒   ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
         ░    ░  ░ ░         ░         ░  ░     ░  ░      ░  ░ ░            ░  ░         ░ 
                        ░                                     ░                            
{Fore.GREEN}[*] NebulaScan | BETA VERSION | - Ultra-Fast Interstellar Subdomain Scanner
{Fore.YELLOW}[*] Author: Luca Lorenzi
{Fore.MAGENTA}[*] Company: Orizon
{Style.RESET_ALL}
"""

class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = {}
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(1000)  

    async def run(self):
        start_time = time.time()
        tasks = [
            self.passive_enumeration(),
            self.bruteforce_subdomains()
        ]
        await asyncio.gather(*tasks)
        await self.get_additional_info()
        end_time = time.time()
        print(f"{Fore.YELLOW}[*] Total time: {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
        return self.subdomains

    async def passive_enumeration(self):
        tasks = [
            self.crt_sh_enumeration(),
            self.virustotal_enumeration(),
            self.alienvault_enumeration(),
            self.threatcrowd_enumeration(),
            self.hackertarget_enumeration()
        ]
        await asyncio.gather(*tasks)

    async def crt_sh_enumeration(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        await self.add_subdomain(entry['name_value'], "crt.sh")

    async def virustotal_enumeration(self):
        url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('data', []):
                        await self.add_subdomain(item['id'], "VirusTotal")

    async def alienvault_enumeration(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data.get('passive_dns', []):
                        await self.add_subdomain(entry['hostname'], "AlienVault")

    async def threatcrowd_enumeration(self):
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        for subdomain in data.get('subdomains', []):
                            await self.add_subdomain(subdomain, "ThreatCrowd")
            except Exception as e:
                print(f"{Fore.RED}[-] Error during ThreatCrowd enumeration: {str(e)}{Style.RESET_ALL}")

    async def hackertarget_enumeration(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.text()
                    for line in data.splitlines():
                        if line:
                            subdomain = line.split(',')[0]
                            await self.add_subdomain(subdomain, "HackerTarget")

    async def bruteforce_subdomains(self):
        wordlist = self.load_wordlist()
        tasks = [self.check_subdomain(subdomain) for subdomain in wordlist]
        await asyncio.gather(*tasks)

    async def check_subdomain(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        try:
            async with self.semaphore:
                answers = await self.resolver.query(full_domain, 'A')
            if answers:
                await self.add_subdomain(full_domain, "Bruteforce")
            return True
        except Exception:
            return False

    async def add_subdomain(self, subdomain, source):
        if subdomain.endswith(self.domain) and subdomain != self.domain:
            
            if subdomain.startswith('*.'):
                subdomain = subdomain[2:]
            if subdomain not in self.subdomains:
                self.subdomains[subdomain] = {"source": source}
                print(f"{Fore.GREEN}[+] Found: {subdomain} {Fore.YELLOW}(Source: {source}){Style.RESET_ALL}")

    async def get_additional_info(self):
        tasks = [self.get_info(subdomain) for subdomain in self.subdomains]
        await asyncio.gather(*tasks)

    async def get_info(self, subdomain):
        try:
            
            if subdomain.startswith('*'):
                self.subdomains[subdomain]["info"] = "Wildcard DNS record"
                return

            async with self.semaphore:
                try:
                    ip = socket.gethostbyname(subdomain)
                except socket.gaierror:
                    
                    self.subdomains[subdomain]["info"] = "Unable to resolve"
                    return

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
            print(f"{Fore.RED}[-] Error getting info for {subdomain}: {str(e)}{Style.RESET_ALL}")
            self.subdomains[subdomain]["info"] = f"Error: {str(e)}"

    async def check_ports(self, ip):
        open_ports = []
        common_ports = [80, 443, 8080, 8443, 22, 21, 25, 587, 3306, 5432]
        tasks = [self.check_port(ip, port) for port in common_ports]
        results = await asyncio.gather(*tasks)
        for port, is_open in zip(common_ports, results):
            if is_open:
                open_ports.append(port)
        return open_ports

    async def check_port(self, ip, port):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def get_http_server(self, subdomain):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{subdomain}", timeout=5) as response:
                    return response.headers.get('Server', 'N/A')
        except:
            return "N/A"

    async def get_ssl_info(self, subdomain):
        try:
            context = ssl.create_default_context()
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{subdomain}", ssl=context, timeout=5) as response:
                    cert = response.connection.transport.get_extra_info('peercert')
                    return {
                        "ssl_issuer": dict(x[0] for x in cert['issuer']),
                        "ssl_subject": dict(x[0] for x in cert['subject']),
                        "ssl_version": response.connection.transport.get_extra_info('ssl_version')
                    }
        except:
            return {"ssl_issuer": "N/A", "ssl_subject": "N/A", "ssl_version": "N/A"}

    def load_wordlist(self):
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

async def main():
    parser = argparse.ArgumentParser(description="NebulaScan - The Interstellar Subdomain Scanner")
    parser.add_argument("domain", help="The domain to search for subdomains")
    args = parser.parse_args()

    print(BANNER)

    print(f"{Fore.CYAN}[*] Starting scan for {args.domain}{Style.RESET_ALL}")
    finder = SubdomainFinder(args.domain)
    subdomains = await finder.run()

    print(f"\n{Fore.YELLOW}[*] Total subdomains found: {len(subdomains)}{Style.RESET_ALL}")
    
    
    output_file = f"{args.domain}.txt"
    with open(output_file, 'w') as f:
        for subdomain, info in subdomains.items():
            f.write(f"Subdomain: {subdomain}\n")
            for key, value in info.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")

    print(f"{Fore.MAGENTA}[*] Scan completed. Results saved to {output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())
