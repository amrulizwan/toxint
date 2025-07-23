import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
import json
import re
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class WebsiteHarvester:
    def __init__(self):
        self.data = {}

    async def harvest(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        console.print(f"[red]Harvesting website: {url}[/red]")
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            with Progress() as progress:
                task = progress.add_task("[red]Harvesting...", total=8)
                
                progress.update(task, advance=1, description="[red]Basic info...")
                await self.get_basic_info(session, url)
                
                progress.update(task, advance=1, description="[red]Headers...")
                await self.get_headers(session, url)
                
                progress.update(task, advance=1, description="[red]Meta tags...")
                await self.get_meta_tags(session, url)
                
                progress.update(task, advance=1, description="[red]Technology stack...")
                await self.detect_technologies(session, url)
                
                progress.update(task, advance=1, description="[red]Security headers...")
                await self.check_security_headers(session, url)
                
                progress.update(task, advance=1, description="[red]Common files...")
                await self.check_common_files(session, url)
                
                progress.update(task, advance=1, description="[red]Social links...")
                await self.extract_social_links(session, url)
                
                progress.update(task, advance=1, description="[red]Contact info...")
                await self.extract_contact_info(session, url)
        
        self.display_results(url)

    async def get_basic_info(self, session, url):
        try:
            async with session.get(url) as response:
                self.data['Basic Info'] = {
                    'Status Code': response.status,
                    'Content Type': response.headers.get('content-type', 'Unknown'),
                    'Server': response.headers.get('server', 'Unknown'),
                    'Content Length': response.headers.get('content-length', 'Unknown'),
                    'Last Modified': response.headers.get('last-modified', 'Unknown'),
                }
                
                content = await response.text()
                self.data['content'] = content
                
        except Exception as e:
            console.print(f"[red]Error getting basic info: {e}[/red]")

    async def get_headers(self, session, url):
        try:
            async with session.head(url) as response:
                headers = dict(response.headers)
                
                security_headers = [
                    'strict-transport-security', 'content-security-policy',
                    'x-frame-options', 'x-content-type-options',
                    'x-xss-protection', 'referrer-policy'
                ]
                
                self.data['HTTP Headers'] = {}
                for header, value in headers.items():
                    if len(str(value)) < 100:
                        self.data['HTTP Headers'][header] = value
                
        except Exception as e:
            console.print(f"[red]Error getting headers: {e}[/red]")

    async def get_meta_tags(self, session, url):
        if 'content' not in self.data:
            return
            
        try:
            soup = BeautifulSoup(self.data['content'], 'html.parser')
            
            self.data['Meta Tags'] = {}
            
            title = soup.find('title')
            if title:
                self.data['Meta Tags']['Title'] = title.get_text().strip()
            
            meta_tags = soup.find_all('meta')
            for tag in meta_tags:
                name = tag.get('name') or tag.get('property') or tag.get('http-equiv')
                content = tag.get('content')
                
                if name and content and len(content) < 200:
                    self.data['Meta Tags'][name] = content
            
            links = soup.find_all('link')
            for link in links:
                rel = link.get('rel')
                href = link.get('href')
                
                if rel and href:
                    if 'Links' not in self.data:
                        self.data['Links'] = {}
                    
                    rel_str = ' '.join(rel) if isinstance(rel, list) else rel
                    if rel_str in ['canonical', 'alternate', 'shortlink']:
                        self.data['Links'][rel_str] = href
            
        except Exception as e:
            console.print(f"[red]Error parsing meta tags: {e}[/red]")

    async def detect_technologies(self, session, url):
        if 'content' not in self.data:
            return
            
        technologies = []
        content = self.data['content'].lower()
        headers = self.data.get('HTTP Headers', {})
        
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-json/'],
            'Drupal': ['drupal', 'sites/default/files'],
            'Joomla': ['joomla', 'option=com_'],
            'React': ['react', '__react'],
            'Angular': ['ng-app', 'angular'],
            'Vue.js': ['vue.js', '__vue__'],
            'jQuery': ['jquery', '$.fn.jquery'],
            'Bootstrap': ['bootstrap', 'btn-primary'],
            'Laravel': ['laravel_session', '_token'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Flask': ['flask', 'werkzeug'],
            'Express': ['express', 'x-powered-by'],
            'Apache': ['apache'],
            'Nginx': ['nginx'],
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Google Analytics': ['google-analytics', 'gtag'],
            'Google Tag Manager': ['googletagmanager'],
            'Facebook Pixel': ['facebook.net/tr', 'fbevents.js'],
        }
        
        for tech, signatures in tech_signatures.items():
            for signature in signatures:
                if signature in content or any(signature in str(v).lower() for v in headers.values()):
                    technologies.append(tech)
                    break
        
        if technologies:
            self.data['Technologies'] = {'Detected': technologies}

    async def check_security_headers(self, session, url):
        headers = self.data.get('HTTP Headers', {})
        
        security_analysis = {}
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented', 
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Referrer-Policy': 'Referrer policy not set'
        }
        
        for header, warning in security_headers.items():
            header_lower = header.lower()
            found = any(header_lower == h.lower() for h in headers.keys())
            
            if found:
                security_analysis[header] = '✅ Present'
            else:
                security_analysis[header] = f'❌ {warning}'
        
        self.data['Security Analysis'] = security_analysis

    async def check_common_files(self, session, url):
        common_files = [
            'robots.txt', 'sitemap.xml', 'security.txt', '.well-known/security.txt',
            'humans.txt', 'crossdomain.xml', 'clientaccesspolicy.xml'
        ]
        
        found_files = {}
        
        for file in common_files:
            try:
                file_url = urljoin(url, file)
                async with session.get(file_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        found_files[file] = {
                            'status': 'Found',
                            'size': len(content),
                            'preview': content[:200] + '...' if len(content) > 200 else content
                        }
                    else:
                        found_files[file] = {'status': f'Not Found ({response.status})'}
            except:
                found_files[file] = {'status': 'Error checking'}
        
        self.data['Common Files'] = found_files

    async def extract_social_links(self, session, url):
        if 'content' not in self.data:
            return
            
        try:
            soup = BeautifulSoup(self.data['content'], 'html.parser')
            
            social_patterns = {
                'Facebook': r'facebook\.com/[^/\s"\']+',
                'Twitter': r'twitter\.com/[^/\s"\']+',
                'LinkedIn': r'linkedin\.com/(?:in|company)/[^/\s"\']+',
                'Instagram': r'instagram\.com/[^/\s"\']+',
                'YouTube': r'youtube\.com/(?:channel|user|c)/[^/\s"\']+',
                'GitHub': r'github\.com/[^/\s"\']+',
                'TikTok': r'tiktok\.com/@[^/\s"\']+',
            }
            
            social_links = {}
            
            all_links = soup.find_all('a', href=True)
            content_text = self.data['content']
            
            for platform, pattern in social_patterns.items():
                matches = re.findall(pattern, content_text, re.IGNORECASE)
                if matches:
                    social_links[platform] = list(set(matches))
            
            if social_links:
                self.data['Social Media'] = social_links
                
        except Exception as e:
            console.print(f"[red]Error extracting social links: {e}[/red]")

    async def extract_contact_info(self, session, url):
        if 'content' not in self.data:
            return
            
        try:
            content = self.data['content']
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            phone_pattern = r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
            
            emails = re.findall(email_pattern, content)
            phones = re.findall(phone_pattern, content)
            
            contact_info = {}
            
            if emails:
                contact_info['Emails'] = list(set(emails))
            
            if phones:
                contact_info['Phones'] = list(set(phones))
            
            if contact_info:
                self.data['Contact Information'] = contact_info
                
        except Exception as e:
            console.print(f"[red]Error extracting contact info: {e}[/red]")

    def display_results(self, url):
        console.print(f"\n[red]═══ WEBSITE INTELLIGENCE REPORT ═══[/red]")
        
        for category, data in self.data.items():
            if category == 'content':
                continue
                
            if data and isinstance(data, dict):
                table = Table(title=category, border_style="red")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                for key, value in data.items():
                    if isinstance(value, list):
                        value = ', '.join(str(v) for v in value)
                    elif isinstance(value, dict):
                        value = json.dumps(value, indent=2)
                    
                    value_str = str(value)
                    if len(value_str) > 100:
                        value_str = value_str[:100] + "..."
                    
                    table.add_row(str(key), value_str)
                
                console.print(table)
                console.print()
        
        console.print(f"[green]Website harvesting complete[/green]")
