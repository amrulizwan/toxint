import asyncio
import aiohttp
import dns.resolver
import json
import socket
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
import time
import random

console = Console()

class EnhancedSubdomainEnum:
    def __init__(self):
        self.found_subdomains = set()
        self.alive_subdomains = []
        self.session = None
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        self.massive_wordlist = [
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
            'training', 'course', 'learn', 'education', 'school', 'university', 'college',
            'career', 'job', 'jobs', 'recruitment', 'hr', 'payroll', 'finance', 'accounting',
            'billing', 'invoice', 'payment', 'pay', 'bank', 'wallet', 'money', 'credit',
            'crm', 'erp', 'inventory', 'warehouse', 'shipping', 'delivery', 'tracking',
            'order', 'orders', 'cart', 'checkout', 'product', 'products', 'catalog',
            'price', 'pricing', 'quote', 'quotes', 'estimate', 'calculator', 'tool',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'dev1', 'dev2', 'test1', 'test2',
            'staging1', 'staging2', 'prod', 'production', 'live', 'www1', 'www2', 'web', 'web1',
            'web2', 'app1', 'app2', 'api1', 'api2', 'mail1', 'mail2', 'smtp1', 'smtp2',
            'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'pop3', 'imap',
            'webmail1', 'webmail2', 'exchange', 'owa', 'outlook', 'office', 'intranet',
            'extranet', 'portal1', 'portal2', 'login', 'auth', 'sso', 'ldap', 'ad',
            'dc', 'dc1', 'dc2', 'pdc', 'bdc', 'rodc', 'file', 'files1', 'files2',
            'share', 'shared', 'public', 'private', 'restricted', 'guest', 'ftp1', 'ftp2',
            'sftp1', 'sftp2', 'backup1', 'backup2', 'archive1', 'archive2', 'old1', 'old2'
        ]
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def crtsh_subdomain_enum(self, domain):
        console.print(f"[red]🔍 Querying Certificate Transparency (crt.sh) for {domain}[/red]")
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    try:
                        response_text = await response.text()
                        
                        if not response_text or response_text.strip() == '':
                            console.print("[yellow]Empty response from crt.sh[/yellow]")
                            return
                        
                        # Try to parse as JSON
                        try:
                            data = json.loads(response_text)
                        except json.JSONDecodeError:
                            console.print("[yellow]Invalid JSON response from crt.sh[/yellow]")
                            return
                        
                        if data and isinstance(data, list):
                            found_count = 0
                            for cert in data:
                                if cert and isinstance(cert, dict):
                                    name_value = cert.get('name_value')
                                    if name_value:
                                        names = name_value.split('\n')
                                        for name in names:
                                            name = name.strip().lower()
                                            if name.endswith(f'.{domain}') and '*' not in name:
                                                self.found_subdomains.add(name)
                                                found_count += 1
                            
                            if found_count > 0:
                                console.print(f"[green]Found {found_count} subdomains from crt.sh[/green]")
                            else:
                                console.print("[yellow]No valid subdomains found in crt.sh response[/yellow]")
                        else:
                            console.print("[yellow]No CT log data found or invalid data format[/yellow]")
                            
                    except Exception as parse_error:
                        console.print(f"[yellow]Failed to parse crt.sh response: {str(parse_error)[:100]}[/yellow]")
                else:
                    console.print(f"[yellow]crt.sh returned status {response.status}[/yellow]")
                    
        except asyncio.TimeoutError:
            console.print(f"[yellow]crt.sh query timed out[/yellow]")
        except Exception as e:
            console.print(f"[yellow]crt.sh query failed: {str(e)[:100]}[/yellow]")

    async def dnsdumpster_scraping(self, domain):
        console.print(f"[red]🔍 Scraping DNSDumpster for {domain}[/red]")
        
        try:
            url = "https://dnsdumpster.com/"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    if html:
                        import re
                        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
                        
                        if csrf_token:
                            token = csrf_token.group(1)
                            
                            data = {
                                'csrfmiddlewaretoken': token,
                                'targetip': domain,
                                'user': 'free'
                            }
                            
                            headers = {
                                **self.headers,
                                'Referer': url,
                                'Origin': 'https://dnsdumpster.com'
                            }
                            
                            async with self.session.post(url, data=data, headers=headers) as resp:
                                if resp.status == 200:
                                    result_html = await resp.text()
                                    
                                    if result_html:
                                        subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain)
                                        subdomains = re.findall(subdomain_pattern, result_html)
                                        
                                        for subdomain_tuple in subdomains:
                                            if subdomain_tuple:
                                                subdomain = subdomain_tuple[0] if isinstance(subdomain_tuple, tuple) else subdomain_tuple
                                                if subdomain and subdomain.endswith(f'.{domain}'):
                                                    self.found_subdomains.add(subdomain.lower())
                                        
                                        console.print(f"[green]Found additional subdomains from DNSDumpster[/green]")
                                else:
                                    console.print(f"[yellow]DNSDumpster returned status {resp.status}[/yellow]")
                        else:
                            console.print("[yellow]Could not find CSRF token[/yellow]")
                    else:
                        console.print("[yellow]Empty response from DNSDumpster[/yellow]")
                else:
                    console.print(f"[yellow]DNSDumpster returned status {response.status}[/yellow]")
                
        except Exception as e:
            console.print(f"[yellow]DNSDumpster scraping failed: {e}[/yellow]")

    async def chaos_subdomain_enum(self, domain):
        console.print(f"[red]🔍 Querying Chaos API for {domain}[/red]")
        
        try:
            url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
            
            async with self.session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    try:
                        response_text = await response.text()
                        
                        if not response_text or response_text.strip() == '':
                            console.print("[yellow]Empty response from Chaos API[/yellow]")
                            return
                        
                        # Try to parse as JSON
                        try:
                            data = json.loads(response_text)
                        except json.JSONDecodeError:
                            console.print("[yellow]Invalid JSON response from Chaos API[/yellow]")
                            return
                        
                        if data and isinstance(data, dict):
                            subdomains = data.get('subdomains', [])
                            
                            if subdomains and isinstance(subdomains, list):
                                found_count = 0
                                for subdomain in subdomains:
                                    if subdomain and isinstance(subdomain, str):
                                        full_subdomain = f"{subdomain}.{domain}"
                                        self.found_subdomains.add(full_subdomain.lower())
                                        found_count += 1
                                
                                if found_count > 0:
                                    console.print(f"[green]Found {found_count} subdomains from Chaos[/green]")
                                else:
                                    console.print("[yellow]No valid subdomains found in Chaos response[/yellow]")
                            else:
                                console.print("[yellow]No subdomains found in Chaos response[/yellow]")
                        else:
                            console.print("[yellow]Invalid response format from Chaos API[/yellow]")
                            
                    except Exception as parse_error:
                        console.print(f"[yellow]Failed to parse Chaos response: {str(parse_error)[:100]}[/yellow]")
                else:
                    console.print(f"[yellow]Chaos API returned status {response.status}[/yellow]")
                    
        except asyncio.TimeoutError:
            console.print(f"[yellow]Chaos API query timed out[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Chaos API query failed: {str(e)[:100]}[/yellow]")

    async def rapid_dns_enum(self, domain):
        console.print(f"[red]🔍 Querying RapidDNS for {domain}[/red]")
        
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            
            async with self.session.get(url, headers=self.headers, timeout=15) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    if html and len(html.strip()) > 0:
                        import re
                        pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(domain)
                        matches = re.findall(pattern, html)
                        
                        found_count = 0
                        for match in matches:
                            if match:
                                try:
                                    if isinstance(match, tuple):
                                        subdomain = ''.join(match) + '.' + domain
                                    else:
                                        subdomain = str(match)
                                    
                                    if subdomain and subdomain.endswith(f'.{domain}') and subdomain != f'.{domain}':
                                        self.found_subdomains.add(subdomain.lower())
                                        found_count += 1
                                except Exception:
                                    continue
                        
                        if found_count > 0:
                            console.print(f"[green]Found {found_count} additional subdomains from RapidDNS[/green]")
                        else:
                            console.print("[yellow]No new subdomains found from RapidDNS[/yellow]")
                    else:
                        console.print("[yellow]Empty response from RapidDNS[/yellow]")
                else:
                    console.print(f"[yellow]RapidDNS returned status {response.status}[/yellow]")
                    
        except asyncio.TimeoutError:
            console.print(f"[yellow]RapidDNS query timed out[/yellow]")
        except Exception as e:
            console.print(f"[yellow]RapidDNS query failed: {str(e)[:100]}[/yellow]")

    async def brute_force_subdomains(self, domain, wordlist_size="medium"):
        console.print(f"[red]🔍 Brute Force Attack on {domain} (mode: {wordlist_size})[/red]")
        
        if wordlist_size == "small":
            wordlist = self.massive_wordlist[:50]
        elif wordlist_size == "large":
            wordlist = self.massive_wordlist + [f"sub{i}" for i in range(100)] + [f"test{i}" for i in range(50)]
        else:
            wordlist = self.massive_wordlist[:100]  # Limit to prevent timeout issues
        
        semaphore = asyncio.Semaphore(20)  # Reduce concurrent requests
        
        async def check_subdomain(subdomain):
            async with semaphore:
                try:
                    full_domain = f"{subdomain}.{domain}"
                    
                    # Add small delay to prevent overwhelming
                    await asyncio.sleep(random.uniform(0.1, 0.3))
                    
                    # Use asyncio.wait_for with timeout
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 1
                        resolver.lifetime = 1
                        
                        # Use shorter timeout for the entire operation
                        result = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, 
                                lambda: resolver.resolve(full_domain, 'A')
                            ),
                            timeout=2
                        )
                        
                        if result:
                            self.found_subdomains.add(full_domain.lower())
                            return full_domain
                        else:
                            return None
                            
                    except (asyncio.TimeoutError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                        return None
                    except Exception:
                        return None
                        
                except Exception:
                    return None
        
        # Process in smaller batches to prevent overwhelming
        batch_size = 50
        found_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(f"[red]Brute forcing {len(wordlist)} subdomains...", total=len(wordlist))
            
            for i in range(0, len(wordlist), batch_size):
                batch = wordlist[i:i + batch_size]
                batch_tasks = [check_subdomain(subdomain) for subdomain in batch]
                
                try:
                    # Use wait_for with timeout for the entire batch
                    batch_results = await asyncio.wait_for(
                        asyncio.gather(*batch_tasks, return_exceptions=True),
                        timeout=30  # 30 seconds max per batch
                    )
                    
                    batch_found = len([r for r in batch_results if r and not isinstance(r, Exception)])
                    found_count += batch_found
                    
                except asyncio.TimeoutError:
                    console.print(f"[yellow]Batch {i//batch_size + 1} timed out[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Batch {i//batch_size + 1} failed: {str(e)[:50]}[/yellow]")
                
                progress.update(task, advance=len(batch))
            
            console.print(f"[green]Brute force found {found_count} new subdomains[/green]")

    async def check_subdomain_alive(self, subdomain):
        try:
            async with self.session.get(f"http://{subdomain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                return {
                    'subdomain': subdomain,
                    'status_code': response.status,
                    'title': await self.extract_title(response),
                    'server': response.headers.get('Server', 'Unknown'),
                    'scheme': 'http'
                }
        except:
            try:
                async with self.session.get(f"https://{subdomain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                    return {
                        'subdomain': subdomain,
                        'status_code': response.status,
                        'title': await self.extract_title(response),
                        'server': response.headers.get('Server', 'Unknown'),
                        'scheme': 'https'
                    }
            except:
                return None

    async def extract_title(self, response):
        try:
            html = await response.text()
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else 'No Title'
        except:
            return 'Unknown'

    async def comprehensive_subdomain_discovery(self, domain, brute_mode="medium", check_alive=True):
        console.print(f"[red]🚀 Starting Comprehensive Subdomain Discovery for {domain}[/red]")
        
        tasks = [
            self.crtsh_subdomain_enum(domain),
            self.dnsdumpster_scraping(domain),
            self.chaos_subdomain_enum(domain),
            self.rapid_dns_enum(domain),
            self.brute_force_subdomains(domain, brute_mode)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        unique_subdomains = sorted(list(self.found_subdomains))
        console.print(f"[green]Total unique subdomains found: {len(unique_subdomains)}[/green]")
        
        if check_alive and unique_subdomains:
            console.print(f"[red]🌐 Checking which subdomains are alive...[/red]")
            
            alive_tasks = [self.check_subdomain_alive(sub) for sub in unique_subdomains[:50]]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True
            ) as progress:
                task = progress.add_task("[red]Checking alive subdomains...", total=len(alive_tasks))
                
                alive_results = await asyncio.gather(*alive_tasks, return_exceptions=True)
                self.alive_subdomains = [r for r in alive_results if r and not isinstance(r, Exception)]
                
                progress.update(task, completed=len(alive_tasks))
        
        return {
            'all_subdomains': unique_subdomains,
            'alive_subdomains': self.alive_subdomains,
            'total_found': len(unique_subdomains),
            'total_alive': len(self.alive_subdomains)
        }

    def display_results(self, results):
        console.print(f"\n[red]═══ ENHANCED SUBDOMAIN ENUMERATION REPORT ═══[/red]")
        
        all_subdomains = results['all_subdomains']
        alive_subdomains = results['alive_subdomains']
        
        if all_subdomains:
            table = Table(title="🔍 All Discovered Subdomains", border_style="cyan")
            table.add_column("Subdomain", style="white")
            table.add_column("Status", style="green")
            
            alive_set = {sub['subdomain'] for sub in alive_subdomains}
            
            for subdomain in all_subdomains[:100]:
                status = "🟢 ALIVE" if subdomain in alive_set else "🔘 Unknown"
                table.add_row(subdomain, status)
            
            console.print(table)
        
        if alive_subdomains:
            table = Table(title="🌐 Live Subdomains with Details", border_style="green")
            table.add_column("Subdomain", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Title", style="white")
            table.add_column("Server", style="yellow")
            table.add_column("Scheme", style="blue")
            
            for sub in alive_subdomains:
                table.add_row(
                    sub['subdomain'],
                    str(sub['status_code']),
                    sub['title'][:50] + "..." if len(sub['title']) > 50 else sub['title'],
                    sub['server'],
                    sub['scheme'].upper()
                )
            
            console.print(table)
        
        summary_text = f"""
[green]📊 Summary Statistics:[/green]
Total Subdomains Found: {results['total_found']}
Live Subdomains: {results['total_alive']}
Discovery Rate: {(results['total_alive'] / max(results['total_found'], 1) * 100):.1f}%

[yellow]🔧 Data Sources Used:[/yellow]
• Certificate Transparency (crt.sh)
• DNSDumpster Scraping
• Chaos ProjectDiscovery API
• RapidDNS Database
• Custom Brute Force Engine
        """
        
        console.print(Panel(summary_text, title="Discovery Summary", border_style="green"))
        
        console.print(f"\n[dim white]💡 Tip: Use these subdomains for further enumeration and testing[/dim white]")
        console.print(f"[dim white]⚠️  Always ensure you have permission before testing live subdomains[/dim white]")
