import asyncio
import aiohttp
import socket
import requests
from ipwhois import IPWhois
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

class IPAnalyzer:
    def __init__(self):
        self.ip_data = {}

    async def analyze(self, ip_address):
        console.print(f"[red]Analyzing IP address: {ip_address}[/red]")
        
        if not self.validate_ip(ip_address):
            console.print("[red]Invalid IP address format[/red]")
            return
        
        with Progress() as progress:
            task = progress.add_task("[red]Analyzing...", total=7)
            
            progress.update(task, advance=1, description="[red]Basic info...")
            await self.get_basic_info(ip_address)
            
            progress.update(task, advance=1, description="[red]WHOIS lookup...")
            await self.get_whois_data(ip_address)
            
            progress.update(task, advance=1, description="[red]Geolocation...")
            await self.get_geolocation(ip_address)
            
            progress.update(task, advance=1, description="[red]Reverse DNS...")
            await self.get_reverse_dns(ip_address)
            
            progress.update(task, advance=1, description="[red]Port scanning...")
            await self.port_scan(ip_address)
            
            progress.update(task, advance=1, description="[red]Threat intelligence...")
            await self.check_threat_intel(ip_address)
            
            progress.update(task, advance=1, description="[red]Service detection...")
            await self.detect_services(ip_address)
        
        self.display_results(ip_address)

    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    async def get_basic_info(self, ip):
        try:
            self.ip_data['Basic Info'] = {
                'IP Address': ip,
                'Type': 'Public' if not self.is_private_ip(ip) else 'Private',
                'Version': 'IPv4' if '.' in ip else 'IPv6'
            }
        except Exception as e:
            console.print(f"[red]Error getting basic info: {e}[/red]")

    def is_private_ip(self, ip):
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]
        
        try:
            ip_int = int(socket.inet_aton(ip).hex(), 16)
            for start, end in private_ranges:
                start_int = int(socket.inet_aton(start).hex(), 16)
                end_int = int(socket.inet_aton(end).hex(), 16)
                if start_int <= ip_int <= end_int:
                    return True
        except:
            pass
        return False

    async def get_whois_data(self, ip):
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            
            whois_info = {}
            
            if 'asn_description' in results:
                whois_info['ASN Description'] = results['asn_description']
            
            if 'asn' in results:
                whois_info['ASN'] = results['asn']
            
            if 'asn_country_code' in results:
                whois_info['Country Code'] = results['asn_country_code']
            
            if 'network' in results and results['network']:
                network = results['network']
                whois_info['Network Range'] = network.get('cidr', 'Unknown')
                whois_info['Network Name'] = network.get('name', 'Unknown')
                
                if 'remarks' in network and network['remarks']:
                    whois_info['Remarks'] = network['remarks'][0].get('description', 'None')
            
            if 'objects' in results:
                contacts = []
                for obj_key, obj_data in results['objects'].items():
                    if 'contact' in obj_data and 'email' in obj_data['contact']:
                        email = obj_data['contact']['email']
                        if isinstance(email, list):
                            contacts.extend(email)
                        else:
                            contacts.append(email)
                
                if contacts:
                    whois_info['Contacts'] = list(set(contacts))[:3]
            
            self.ip_data['WHOIS Data'] = whois_info
            
        except Exception as e:
            console.print(f"[yellow]WHOIS lookup failed: {e}[/yellow]")

    async def get_geolocation(self, ip):
        providers = [
            ('ipapi.co', f'https://ipapi.co/{ip}/json/'),
            ('ipinfo.io', f'https://ipinfo.io/{ip}/json'),
            ('ip-api.com', f'http://ip-api.com/json/{ip}')
        ]
        
        for provider, url in providers:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            geo_info = {}
                            
                            if provider == 'ipapi.co':
                                geo_info = {
                                    'Country': data.get('country_name', 'Unknown'),
                                    'Country Code': data.get('country_code', 'Unknown'),
                                    'Region': data.get('region', 'Unknown'),
                                    'City': data.get('city', 'Unknown'),
                                    'Postal Code': data.get('postal', 'Unknown'),
                                    'Latitude': data.get('latitude', 'Unknown'),
                                    'Longitude': data.get('longitude', 'Unknown'),
                                    'ISP': data.get('org', 'Unknown'),
                                    'Timezone': data.get('timezone', 'Unknown'),
                                    'Source': provider
                                }
                            elif provider == 'ipinfo.io':
                                geo_info = {
                                    'Country': data.get('country', 'Unknown'),
                                    'Region': data.get('region', 'Unknown'),
                                    'City': data.get('city', 'Unknown'),
                                    'Postal Code': data.get('postal', 'Unknown'),
                                    'Location': data.get('loc', 'Unknown'),
                                    'ISP': data.get('org', 'Unknown'),
                                    'Timezone': data.get('timezone', 'Unknown'),
                                    'Source': provider
                                }
                            elif provider == 'ip-api.com':
                                geo_info = {
                                    'Country': data.get('country', 'Unknown'),
                                    'Country Code': data.get('countryCode', 'Unknown'),
                                    'Region': data.get('regionName', 'Unknown'),
                                    'City': data.get('city', 'Unknown'),
                                    'Postal Code': data.get('zip', 'Unknown'),
                                    'Latitude': data.get('lat', 'Unknown'),
                                    'Longitude': data.get('lon', 'Unknown'),
                                    'ISP': data.get('isp', 'Unknown'),
                                    'Organization': data.get('org', 'Unknown'),
                                    'Timezone': data.get('timezone', 'Unknown'),
                                    'Source': provider
                                }
                            
                            if geo_info and geo_info.get('Country') != 'Unknown':
                                self.ip_data['Geolocation'] = geo_info
                                return
                            
            except Exception as e:
                continue
        
        console.print("[yellow]Geolocation lookup failed for all providers[/yellow]")

    async def get_reverse_dns(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.ip_data['Reverse DNS'] = {
                'Hostname': hostname,
                'Status': 'Resolved'
            }
        except Exception as e:
            self.ip_data['Reverse DNS'] = {
                'Hostname': 'No reverse DNS record',
                'Status': 'Not resolved'
            }

    async def port_scan(self, ip):
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 
            1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017
        ]
        
        open_ports = []
        semaphore = asyncio.Semaphore(50)
        
        async def scan_port(port):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=3
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    service = self.get_service_name(port)
                    open_ports.append({'port': port, 'service': service})
                except:
                    pass
        
        tasks = [scan_port(port) for port in common_ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        if open_ports:
            self.ip_data['Open Ports'] = open_ports
        else:
            self.ip_data['Open Ports'] = [{'port': 'None', 'service': 'No open ports detected'}]

    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')

    async def check_threat_intel(self, ip):
        threat_sources = [
            ('AbuseIPDB', f'https://api.abuseipdb.com/api/v2/check'),
            ('VirusTotal', f'https://www.virustotal.com/vtapi/v2/ip-address/report')
        ]
        
        threat_data = {}
        
        for source, base_url in threat_sources:
            try:
                if source == 'AbuseIPDB':
                    import os
                    api_key = os.getenv('ABUSEIPDB_API_KEY', 'your-abuseipdb-api-key-here')
                    headers = {
                        'Key': api_key,
                        'Accept': 'application/json'
                    }
                    params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(base_url, headers=headers, params=params, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'data' in data:
                                    abuse_data = data['data']
                                    threat_data[source] = {
                                        'Confidence': f"{abuse_data.get('abuseConfidencePercentage', 0)}%",
                                        'Reports': abuse_data.get('totalReports', 0),
                                        'Last Reported': abuse_data.get('lastReportedAt', 'Never'),
                                        'Country': abuse_data.get('countryCode', 'Unknown')
                                    }
                
                elif source == 'VirusTotal':
                    import os
                    api_key = os.getenv('VIRUSTOTAL_API_KEY', 'your-virustotal-api-key-here')
                    params = {
                        'apikey': api_key,
                        'ip': ip
                    }
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(base_url, params=params, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                if data.get('response_code') == 1:
                                    threat_data[source] = {
                                        'Detected URLs': data.get('detected_urls', [])[:3],
                                        'Resolutions': data.get('resolutions', [])[:3]
                                    }
                
            except Exception as e:
                threat_data[source] = {'Error': str(e)[:100]}
        
        if threat_data:
            self.ip_data['Threat Intelligence'] = threat_data

    async def detect_services(self, ip):
        if 'Open Ports' not in self.ip_data:
            return
        
        services_detected = []
        
        for port_info in self.ip_data['Open Ports']:
            port = port_info.get('port')
            if port == 'None':
                continue
                
            try:
                service_info = await self.banner_grab(ip, port)
                if service_info:
                    services_detected.append({
                        'port': port,
                        'service': port_info.get('service'),
                        'banner': service_info
                    })
            except:
                pass
        
        if services_detected:
            self.ip_data['Service Detection'] = services_detected

    async def banner_grab(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=5
            )
            
            writer.write(b'\r\n')
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()
            await writer.wait_closed()
            
            banner = data.decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else None
            
        except:
            return None

    def display_results(self, ip):
        console.print(f"\n[red]═══ IP ADDRESS INTELLIGENCE REPORT ═══[/red]")
        
        for category, data in self.ip_data.items():
            if data:
                table = Table(title=category, border_style="red")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            if all(isinstance(item, dict) for item in value):
                                for i, item in enumerate(value):
                                    for sub_key, sub_value in item.items():
                                        table.add_row(f"{key} {i+1} - {sub_key}", str(sub_value))
                            else:
                                table.add_row(key, ', '.join(str(v) for v in value))
                        else:
                            table.add_row(str(key), str(value))
                elif isinstance(data, list):
                    for i, item in enumerate(data):
                        if isinstance(item, dict):
                            for key, value in item.items():
                                table.add_row(f"Item {i+1} - {key}", str(value))
                        else:
                            table.add_row(f"Item {i+1}", str(item))
                
                console.print(table)
                console.print()
        
        if 'Threat Intelligence' in self.ip_data:
            console.print("[yellow]⚠️  Check threat intelligence results for potential security risks[/yellow]")
        
        if 'Geolocation' in self.ip_data:
            geo = self.ip_data['Geolocation']
            if 'Latitude' in geo and 'Longitude' in geo:
                lat, lon = geo['Latitude'], geo['Longitude']
                console.print(f"[green]📍 Location: https://maps.google.com/?q={lat},{lon}[/green]")
        
        console.print(f"[green]IP analysis complete[/green]")
