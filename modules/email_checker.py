import asyncio
import aiohttp
import requests
import hashlib
import json
import re
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from .free_breach_sources import FreeBreachSources, GoogleDorkSearcher

console = Console()

class EmailChecker:
    def __init__(self):
        self.breach_data = []
        self.account_data = []
        self.free_sources = FreeBreachSources()
        self.dork_searcher = GoogleDorkSearcher()

    async def check(self, email):
        console.print(f"[red]Investigating email: {email}[/red]")
        
        results = {
            'email': email,
            'breaches': [],
            'social_accounts': [],
            'gravatar': None,
            'validation': None,
            'timestamp': __import__('time').strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with Progress() as progress:
            task = progress.add_task("[red]Checking...", total=5)
            
            progress.update(task, advance=1, description="[red]Free breach databases...")
            await self.check_free_breaches(email)
            
            progress.update(task, advance=1, description="[red]HIBP (if available)...")
            await self.check_hibp(email)
            
            progress.update(task, advance=1, description="[red]Gravatar lookup...")
            await self.check_gravatar(email)
            
            progress.update(task, advance=1, description="[red]Social accounts...")
            await self.check_social_accounts(email)
            
            progress.update(task, advance=1, description="[red]Email validation...")
            await self.validate_email(email)
        
        results['breaches'] = self.breaches
        results['social_accounts'] = self.social_accounts
        results['gravatar'] = getattr(self, 'gravatar_data', None)
        results['validation'] = getattr(self, 'validation_result', None)
        
        self.display_results(email)
        
        return results

    async def check_free_breaches(self, email):
        try:
            console.print("[cyan]Checking free breach databases...[/cyan]")
            
            free_results = await self.free_sources.search_all_free_sources(email)
            
            for result in free_results:
                self.breach_data.append({
                    'name': result.get('source', 'Unknown'),
                    'domain': result.get('breach_name', result.get('bucket', 'Unknown')),
                    'breach_date': result.get('added', 'Unknown'),
                    'description': result.get('note', 'Found in free database'),
                    'data_classes': self.extract_data_classes(result)
                })
            
            if not free_results:
                console.print("[green]No results found in free breach databases[/green]")
                
            dork_urls = self.dork_searcher.generate_search_urls(email)
            self.account_data.append({
                'service': 'Google Dorks',
                'status': f'{len(dork_urls)} search queries generated',
                'note': 'Manual search recommended for comprehensive results'
            })
                
        except Exception as e:
            console.print(f"[yellow]Free breach check failed: {str(e)}[/yellow]")
    
    def extract_data_classes(self, result):
        data_classes = ['Email']
        
        if result.get('passwords_found', 0) > 0:
            data_classes.append('Passwords')
        if result.get('hashes_found', 0) > 0:
            data_classes.append('Password Hashes')
        if 'credentials' in result.get('note', '').lower():
            data_classes.append('Credentials')
        
        return data_classes

    async def check_hibp(self, email):
        try:
            import os
            api_key = os.getenv('HIBP_API_KEY')
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'User-Agent': 'TOXINT-OSINT-Tool',
            }
            
            if api_key:
                headers['hibp-api-key'] = api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        breaches = await response.json()
                        for breach in breaches:
                            self.breach_data.append({
                                'name': breach.get('Name', 'Unknown'),
                                'domain': breach.get('Domain', 'Unknown'),
                                'breach_date': breach.get('BreachDate', 'Unknown'),
                                'description': breach.get('Description', 'No description'),
                                'data_classes': breach.get('DataClasses', [])
                            })
                    elif response.status == 404:
                        console.print("[green]No breaches found in HIBP database[/green]")
                    elif response.status == 401:
                        console.print("[yellow]HIBP API requires authentication (free tier available)[/yellow]")
                        self.account_data.append({
                            'service': 'HIBP',
                            'status': 'API Key Required',
                            'note': 'Visit haveibeenpwned.com for manual check'
                        })
                    else:
                        console.print(f"[yellow]HIBP API error: {response.status}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]HIBP check failed: {str(e)}[/yellow]")

    async def check_gravatar(self, email):
        try:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(gravatar_url) as response:
                    if response.status == 200:
                        self.account_data.append({
                            'service': 'Gravatar',
                            'status': 'Found',
                            'url': f"https://www.gravatar.com/{email_hash}",
                            'profile_url': gravatar_url
                        })
                    else:
                        self.account_data.append({
                            'service': 'Gravatar',
                            'status': 'Not Found',
                            'url': gravatar_url
                        })
        except Exception as e:
            console.print(f"[yellow]Gravatar check failed: {str(e)}[/yellow]")

    async def check_social_accounts(self, email):
        platforms = {
            'GitHub': f"https://github.com/{email.split('@')[0]}",
            'Google': f"https://plus.google.com/+{email}",
            'Skype': f"https://join.skype.com/invite/{email}",
        }
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            for platform, url in platforms.items():
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            self.account_data.append({
                                'service': platform,
                                'status': 'Possible Match',
                                'url': url
                            })
                        else:
                            self.account_data.append({
                                'service': platform,
                                'status': 'Not Found',
                                'url': url
                            })
                except:
                    self.account_data.append({
                        'service': platform,
                        'status': 'Error',
                        'url': url
                    })

    async def validate_email(self, email):
        domain = email.split('@')[1] if '@' in email else None
        
        if domain:
            try:
                import dns.resolver
                
                mx_records = []
                try:
                    mx_answers = dns.resolver.resolve(domain, 'MX')
                    mx_records = [str(rdata) for rdata in mx_answers]
                except:
                    pass
                
                a_records = []
                try:
                    a_answers = dns.resolver.resolve(domain, 'A')
                    a_records = [str(rdata) for rdata in a_answers]
                except:
                    pass
                
                self.account_data.append({
                    'service': 'Domain Validation',
                    'status': 'Valid Domain' if (mx_records or a_records) else 'Invalid Domain',
                    'mx_records': mx_records[:3],
                    'a_records': a_records[:3]
                })
                
            except ImportError:
                self.account_data.append({
                    'service': 'Domain Validation',
                    'status': 'DNS module not available',
                })

    def display_results(self, email):
        console.print(f"\n[red]═══ EMAIL INTELLIGENCE REPORT ═══[/red]")
        
        if self.breach_data:
            table = Table(title="🚨 SECURITY BREACHES FOUND", border_style="red")
            table.add_column("Breach Name", style="red bold")
            table.add_column("Domain", style="cyan")
            table.add_column("Date", style="yellow")
            table.add_column("Compromised Data", style="white")
            
            for breach in self.breach_data:
                data_classes = breach.get('data_classes', [])
                if isinstance(data_classes, list):
                    data_types = ", ".join(str(item) for item in data_classes[:5])
                    if len(data_classes) > 5:
                        data_types += "..."
                else:
                    data_types = str(data_classes)
                
                table.add_row(
                    str(breach.get('name', 'Unknown')),
                    str(breach.get('domain', 'Unknown')),
                    str(breach.get('breach_date', 'Unknown')),
                    data_types
                )
            
            console.print(table)
            console.print(f"[red]⚠️  This email was found in {len(self.breach_data)} data breaches![/red]")
        else:
            console.print("[green]✅ No breaches found in HIBP database[/green]")
        
        if self.account_data:
            table = Table(title="Account Discovery", border_style="blue")
            table.add_column("Service", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("URL", style="blue")
            table.add_column("Additional Info", style="dim white")
            
            for account in self.account_data:
                additional = ""
                if 'mx_records' in account and account['mx_records']:
                    if isinstance(account['mx_records'], list):
                        additional = f"MX: {', '.join(str(mx) for mx in account['mx_records'][:3])}"
                    else:
                        additional = f"MX: {str(account['mx_records'])}"
                elif 'profile_url' in account:
                    additional = "Profile available"
                elif 'note' in account:
                    additional = str(account['note'])
                
                table.add_row(
                    str(account.get('service', 'Unknown')),
                    str(account.get('status', 'Unknown')),
                    str(account.get('url', 'N/A')),
                    additional
                )
            
            console.print(table)
        
        if self.breach_data:
            console.print(f"\n[yellow]Recommendation: Change passwords and enable 2FA on all associated accounts[/yellow]")
        
        console.print(f"\n[cyan]💡 Additional Manual Search Recommendations:[/cyan]")
        dork_urls = self.dork_searcher.generate_search_urls(email)
        
        console.print(f"[dim white]Try these Google Dorks for comprehensive search:[/dim white]")
        for i, dork in enumerate(dork_urls[:5]):
            console.print(f"[dim white]{i+1}. {dork['dork']}[/dim white]")
        
        console.print(f"\n[dim white]Free breach check alternatives:[/dim white]")
        console.print(f"[dim white]• Visit scylla.sh manually[/dim white]")
        console.print(f"[dim white]• Check haveibeenpwned.com (free web interface)[/dim white]")
        console.print(f"[dim white]• Search paste sites manually[/dim white]")
        
        console.print(f"\n[green]Email investigation complete[/green]")
