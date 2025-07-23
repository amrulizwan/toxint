import asyncio
import aiohttp
import requests
import dns.resolver
import whois
from ipwhois import IPWhois
import socket
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import json
import re
from urllib.parse import urlparse
import ssl
import concurrent.futures

console = Console()

class DomainEnumerator:
    def __init__(self):
        self.session = None
        self.subdomains = set()
        self.wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'app', 'portal',
            'blog', 'shop', 'store', 'news', 'support', 'help', 'docs', 'wiki', 'forum',
            'cdn', 'assets', 'static', 'img', 'images', 'video', 'media', 'files',
            'vpn', 'remote', 'secure', 'ssl', 'auth', 'login', 'oauth', 'sso',
            'mysql', 'db', 'database', 'sql', 'redis', 'mongo', 'elastic',
            'mx', 'mx1', 'mx2', 'smtp', 'pop', 'imap', 'webmail', 'email',
            'ns', 'ns1', 'ns2', 'dns', 'resolver', 'whois', 'ntp',
            'backup', 'old', 'new', 'temp', 'tmp', 'cache', 'archive',
            'mobile', 'm', 'wap', 'touch', 'amp', 'beta', 'alpha', 'demo'
        ]

    async def enumerate(self, domain):
        console.print(f"\n[red]Starting domain enumeration for: {domain}[/red]")
        
        results = {
            'domain': domain,
            'whois_data': None,
            'asn_data': None,
            'dns_data': None,
            'subdomains': [],
            'ports': [],
            'timestamp': None
        }
        
        async with aiohttp.ClientSession() as session:
            self.session = session
            
            with Progress() as progress:
                task = progress.add_task("[red]Enumerating...", total=6)
                
                progress.update(task, advance=1, description="[red]WHOIS lookup...")
                results['whois_data'] = await self.get_whois(domain)
                
                progress.update(task, advance=1, description="[red]ASN lookup...")
                results['asn_data'] = await self.get_asn(domain)
                
                progress.update(task, advance=1, description="[red]Certificate transparency...")
                await self.cert_transparency(domain)
                
                progress.update(task, advance=1, description="[red]DNS records...")
                results['dns_data'] = await self.get_dns_records(domain)
                
                progress.update(task, advance=1, description="[red]Subdomain bruteforce...")
                await self.bruteforce_subdomains(domain)
                
                progress.update(task, advance=1, description="[red]Port scanning...")
                results['ports'] = await self.port_scan(domain)
        
        results['subdomains'] = list(self.subdomains)
        results['timestamp'] = __import__('time').strftime('%Y-%m-%d %H:%M:%S')
        
        self.display_results(domain, results['whois_data'], results['asn_data'], results['dns_data'], results['ports'])
        
        return results

    async def get_whois(self, domain):
        try:
            import socket
            import asyncio
            
            console.print(f"[cyan]Performing WHOIS lookup for {domain}...[/cyan]")
            
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, self._sync_whois, domain)
            
            if not whois_data:
                whois_data = await self._alternative_whois(domain)
            
            return whois_data
            
        except Exception as e:
            console.print(f"[yellow]WHOIS lookup failed: {e}[/yellow]")
            return await self._alternative_whois(domain)
    
    def _sync_whois(self, domain):
        try:
            import whois
            return whois.whois(domain)
        except Exception as e:
            console.print(f"[yellow]Standard WHOIS failed: {e}[/yellow]")
            return None
    
    async def _alternative_whois(self, domain):
        try:
            whois_servers = {
                '.com': 'whois.verisign-grs.com',
                '.net': 'whois.verisign-grs.com',
                '.org': 'whois.pir.org',
                '.edu': 'whois.educause.edu',
                '.gov': 'whois.nic.gov',
                '.mil': 'whois.nic.mil',
                '.ac.id': 'whois.id',
                '.id': 'whois.id'
            }
            
            tld = '.' + domain.split('.')[-1]
            if domain.endswith('.ac.id'):
                tld = '.ac.id'
            
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(whois_server, 43), 
                timeout=15
            )
            
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(8192), timeout=15)
            writer.close()
            await writer.wait_closed()
            
            whois_text = data.decode('utf-8', errors='ignore')
            return self._parse_whois_text(whois_text)
            
        except Exception as e:
            console.print(f"[yellow]Alternative WHOIS failed: {e}[/yellow]")
            return None
    
    def _parse_whois_text(self, whois_text):
        parsed = {}
        
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Registry Expiry Date:\s*(.+)',
            'updated_date': r'Updated Date:\s*(.+)',
            'status': r'Domain Status:\s*(.+)',
            'name_servers': r'Name Server:\s*(.+)',
            'emails': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, whois_text, re.IGNORECASE)
            if matches:
                if key == 'emails':
                    parsed[key] = list(set(matches))
                elif key == 'name_servers':
                    parsed[key] = matches
                else:
                    parsed[key] = matches[0].strip()
        
        return parsed

    async def get_asn(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            obj = IPWhois(ip)
            return obj.lookup_rdap()
        except:
            return None

    async def cert_transparency(self, domain):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for cert in data:
                        name = cert.get('name_value', '')
                        if name and name not in self.subdomains:
                            self.subdomains.add(name.strip())
        except:
            pass

    async def get_dns_records(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        return records

    async def bruteforce_subdomains(self, domain):
        enhanced_subdomains = await self._enhanced_subdomain_bruteforce(domain)
        zone_transfer_data = await self._dns_zone_transfer(domain)
        cache_snooping = await self._dns_cache_snooping(domain)
        amplification_check = await self._dns_amplification_check(domain)
        
        for subdomain_info in enhanced_subdomains:
            self.subdomains.add(subdomain_info['subdomain'])
        
        if zone_transfer_data:
            console.print(f"[red]⚠️  DNS Zone Transfer vulnerability found![/red]")
            for record in zone_transfer_data[:10]:
                if '.' in record['name']:
                    self.subdomains.add(f"{record['name']}.{domain}")
        
        if cache_snooping:
            console.print(f"[yellow]DNS cache contains {len(cache_snooping)} cached records[/yellow]")
            for cached in cache_snooping:
                self.subdomains.add(cached['domain'])
        
        if amplification_check:
            console.print(f"[red]⚠️  DNS Amplification vulnerabilities found on {len(amplification_check)} servers![/red]")
        
        self.results = {
            'enhanced_subdomains': enhanced_subdomains,
            'zone_transfer': zone_transfer_data,
            'cache_snooping': cache_snooping,
            'amplification_check': amplification_check
        }

    async def _enhanced_subdomain_bruteforce(self, domain):
        console.print(f"[red]🔍 Advanced Subdomain Brute Force for {domain}[/red]")
        
        extended_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autoconfig', 'autodiscover', 'stage', 'staging', 'dev', 'development',
            'test', 'testing', 'sandbox', 'api', 'app', 'admin', 'administrator', 'secure', 'security',
            'vpn', 'ssl', 'sftp', 'ssh', 'remote', 'blog', 'forum', 'forums', 'shop', 'store',
            'news', 'media', 'static', 'cdn', 'img', 'images', 'video', 'videos', 'download',
            'files', 'support', 'help', 'docs', 'documentation', 'wiki', 'kb', 'demo', 'preview',
            'beta', 'alpha', 'gamma', 'delta', 'mobile', 'm', 'wap', 'portal', 'old', 'new',
            'backup', 'bak', 'mirror', 'archive', 'git', 'svn', 'repo', 'repository', 'jenkins',
            'ci', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'phpmyadmin', 'mysql',
            'db', 'database', 'sql', 'oracle', 'postgres', 'mongo', 'redis', 'elastic', 'kibana',
            'grafana', 'prometheus', 'nagios', 'zabbix', 'monitoring', 'stats', 'analytics',
            'metrics', 'logs', 'log', 'sentry', 'error', 'errors', 'exception', 'exceptions',
            'webcam', 'camera', 'cctv', 'video', 'stream', 'live', 'broadcast', 'radio',
            'podcast', 'music', 'audio', 'voice', 'call', 'conference', 'meet', 'zoom',
            'teams', 'slack', 'discord', 'telegram', 'whatsapp', 'messenger', 'chat',
            'social', 'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'tiktok',
            'training', 'course', 'learn', 'education', 'school', 'university', 'college',
            'library', 'book', 'ebook', 'magazine', 'journal', 'article', 'research',
            'career', 'job', 'jobs', 'recruitment', 'hr', 'payroll', 'finance', 'accounting',
            'billing', 'invoice', 'payment', 'pay', 'bank', 'wallet', 'money', 'credit',
            'card', 'debit', 'loan', 'insurance', 'tax', 'legal', 'law', 'lawyer',
            'crm', 'erp', 'inventory', 'warehouse', 'shipping', 'delivery', 'tracking',
            'order', 'orders', 'cart', 'checkout', 'product', 'products', 'catalog',
            'price', 'pricing', 'quote', 'quotes', 'estimate', 'calculator', 'tool',
            'tools', 'utility', 'utilities', 'service', 'services', 'feature', 'features'
        ] + self.wordlist
        
        found_subdomains = []
        tasks = []
        
        semaphore = asyncio.Semaphore(50)
        
        async def check_subdomain(subdomain):
            async with semaphore:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyname, full_domain
                    )
                    return {'subdomain': full_domain, 'ip': result}
                except:
                    return None
        
        tasks = [check_subdomain(sub) for sub in extended_wordlist]
        
        with console.status("[red]Brute forcing subdomains..."):
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                found_subdomains.append(result)
        
        return found_subdomains

    async def _dns_zone_transfer(self, domain):
        console.print(f"[red]🔍 DNS Zone Transfer Attack for {domain}[/red]")
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(ns) for ns in ns_records]
            
            zone_data = []
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns.rstrip('.'), domain))
                    if zone:
                        console.print(f"[red]⚠️  Zone transfer successful from {ns}![/red]")
                        for name, node in zone.nodes.items():
                            rdatasets = node.rdatasets
                            for rdataset in rdatasets:
                                for rdata in rdataset:
                                    zone_data.append({
                                        'name': str(name),
                                        'type': dns.rdatatype.to_text(rdataset.rdtype),
                                        'value': str(rdata)
                                    })
                except Exception:
                    continue
            
            return zone_data
            
        except Exception as e:
            return []

    async def _dns_cache_snooping(self, domain, dns_server='8.8.8.8'):
        console.print(f"[red]🔍 DNS Cache Snooping for {domain}[/red]")
        
        common_records = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'mobile']
        cached_records = []
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for record in common_records:
            try:
                full_domain = f"{record}.{domain}"
                answer = resolver.resolve(full_domain, 'A', search=False)
                cached_records.append({
                    'domain': full_domain,
                    'cached': True,
                    'ips': [str(ip) for ip in answer]
                })
            except:
                continue
        
        return cached_records

    async def _dns_amplification_check(self, domain):
        console.print(f"[red]🔍 DNS Amplification Vulnerability Check for {domain}[/red]")
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(ns) for ns in ns_records]
            
            vulnerable_servers = []
            
            for ns in nameservers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [socket.gethostbyname(ns.rstrip('.'))]
                    resolver.timeout = 5
                    
                    query = dns.message.make_query('.', dns.rdatatype.ANY)
                    query.flags |= dns.flags.RD
                    
                    response = dns.query.udp(query, resolver.nameservers[0], timeout=5)
                    
                    if len(response.to_wire()) > len(query.to_wire()) * 2:
                        vulnerable_servers.append({
                            'server': ns,
                            'amplification_ratio': len(response.to_wire()) / len(query.to_wire()),
                            'vulnerable': True
                        })
                
                except Exception:
                    continue
            
            return vulnerable_servers
            
        except Exception:
            return []

    async def port_scan(self, domain):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        async def scan_port(port):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, port), timeout=3
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except:
                pass
        
        tasks = [scan_port(port) for port in common_ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        return sorted(open_ports)

    def display_results(self, domain, whois_data, asn_data, dns_data, ports):
        console.print(f"\n[red]═══ DOMAIN INTELLIGENCE REPORT FOR {domain.upper()} ═══[/red]")
        
        if whois_data:
            table = Table(title="🔍 WHOIS Information", border_style="red")
            table.add_column("Field", style="cyan", width=20)
            table.add_column("Value", style="white")
            
            if isinstance(whois_data, dict):
                for field, value in whois_data.items():
                    if value and value != 'N/A':
                        if isinstance(value, list):
                            value = ', '.join(str(v) for v in value[:3])
                        table.add_row(field.replace('_', ' ').title(), str(value)[:100])
            else:
                fields = ['registrar', 'creation_date', 'expiration_date', 'emails', 'name_servers']
                for field in fields:
                    try:
                        value = getattr(whois_data, field, None)
                        if value:
                            if isinstance(value, list) and value:
                                value = ', '.join(str(v) for v in value[:3])
                            table.add_row(field.replace('_', ' ').title(), str(value)[:100])
                    except:
                        continue
            
            if table.rows:
                console.print(table)
            else:
                console.print("[yellow]⚠️  No WHOIS data available[/yellow]")
        else:
            console.print("[yellow]⚠️  WHOIS lookup failed[/yellow]")
        
        if asn_data:
            table = Table(title="🌐 ASN Information", border_style="blue")
            table.add_column("Field", style="cyan", width=20)
            table.add_column("Value", style="white")
            
            try:
                asn_info = asn_data.get('asn_description', 'N/A')
                asn_country = asn_data.get('asn_country_code', 'N/A')
                asn_number = asn_data.get('asn', 'N/A')
                
                if asn_number != 'N/A':
                    table.add_row("ASN Number", str(asn_number))
                if asn_info != 'N/A':
                    table.add_row("ASN Description", str(asn_info)[:100])
                if asn_country != 'N/A':
                    table.add_row("Country", str(asn_country))
                
                if table.rows:
                    console.print(table)
                else:
                    console.print("[yellow]⚠️  No ASN data available[/yellow]")
            except:
                console.print("[yellow]⚠️  ASN lookup failed[/yellow]")
        else:
            console.print("[yellow]⚠️  ASN lookup failed[/yellow]")
        
        if dns_data:
            table = Table(title="📋 DNS Records", border_style="green")
            table.add_column("Type", style="cyan", width=8)
            table.add_column("Records", style="white")
            
            for record_type, records in dns_data.items():
                if records:
                    records_str = '\n'.join(str(r) for r in records[:5])
                    if len(records) > 5:
                        records_str += f"\n... and {len(records) - 5} more"
                    table.add_row(record_type, records_str)
            
            if table.rows:
                console.print(table)
            else:
                console.print("[yellow]⚠️  No DNS records found[/yellow]")
        else:
            console.print("[yellow]⚠️  DNS lookup failed[/yellow]")
        
        if self.subdomains:
            table = Table(title="🎯 Discovered Subdomains", border_style="green")
            table.add_column("Subdomain", style="green")
            table.add_column("Status", style="white")
            
            subdomain_list = sorted(list(self.subdomains))[:20]
            for subdomain in subdomain_list:
                clean_subdomain = subdomain.replace('\n', '').strip()
                if clean_subdomain and '.' in clean_subdomain:
                    table.add_row(clean_subdomain, "✅ Found")
            
            if table.rows:
                console.print(table)
                if len(self.subdomains) > 20:
                    console.print(f"[dim white]... and {len(self.subdomains) - 20} more subdomains found[/dim white]")
            else:
                console.print("[yellow]⚠️  No subdomains discovered[/yellow]")
        else:
            console.print("[yellow]⚠️  No subdomains discovered[/yellow]")
        
        if ports:
            table = Table(title="🔓 Open Ports", border_style="red")
            table.add_column("Port", style="cyan", width=8)
            table.add_column("Service", style="white")
            table.add_column("Status", style="green")
            
            services = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
                       80: 'HTTP', 110: 'POP3', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
                       1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 
                       8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'}
            
            for port in sorted(ports):
                service = services.get(port, 'Unknown')
                table.add_row(str(port), service, "🟢 Open")
            
            console.print(table)
        else:
            console.print("[yellow]⚠️  No open ports found or port scan failed[/yellow]")
        
        console.print(f"\n[green]✅ Domain enumeration completed for {domain}[/green]")
        console.print(f"[dim white]Found {len(self.subdomains)} subdomains, {len(ports) if ports else 0} open ports[/dim white]")
