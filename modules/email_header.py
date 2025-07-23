import re
import email
import socket
from email.header import decode_header
from rich.console import Console
from rich.table import Table
import ipaddress

console = Console()

class EmailHeaderAnalyzer:
    def __init__(self):
        self.analysis = {}

    def analyze(self, filepath):
        console.print(f"[red]Analyzing email headers: {filepath}[/red]")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                email_content = f.read()
        except:
            try:
                with open(filepath, 'r', encoding='latin-1') as f:
                    email_content = f.read()
            except Exception as e:
                console.print(f"[red]Error reading file: {e}[/red]")
                return
        
        self.parse_headers(email_content)
        self.analyze_routing()
        self.detect_spoofing()
        self.analyze_authentication()
        self.check_suspicious_patterns()
        
        self.display_results()

    def parse_headers(self, email_content):
        try:
            msg = email.message_from_string(email_content)
            
            self.analysis['Basic Headers'] = {}
            
            basic_headers = [
                'From', 'To', 'Subject', 'Date', 'Message-ID',
                'Return-Path', 'Reply-To', 'Sender', 'X-Mailer'
            ]
            
            for header in basic_headers:
                value = msg.get(header)
                if value:
                    decoded_value = self.decode_header_value(value)
                    self.analysis['Basic Headers'][header] = decoded_value
            
            received_headers = msg.get_all('Received')
            if received_headers:
                self.analysis['Received Headers'] = []
                for i, received in enumerate(received_headers):
                    self.analysis['Received Headers'].append({
                        'hop': i + 1,
                        'header': received[:200] + "..." if len(received) > 200 else received
                    })
            
            authentication_headers = [
                'Authentication-Results', 'DKIM-Signature', 'SPF',
                'ARC-Authentication-Results', 'ARC-Message-Signature'
            ]
            
            auth_data = {}
            for header in authentication_headers:
                value = msg.get(header)
                if value:
                    auth_data[header] = value[:300] + "..." if len(value) > 300 else value
            
            if auth_data:
                self.analysis['Authentication'] = auth_data
            
            x_headers = {}
            for header, value in msg.items():
                if header.startswith('X-'):
                    x_headers[header] = value[:200] + "..." if len(value) > 200 else value
            
            if x_headers:
                self.analysis['X-Headers'] = x_headers
                
        except Exception as e:
            console.print(f"[red]Error parsing headers: {e}[/red]")

    def decode_header_value(self, value):
        try:
            decoded_parts = decode_header(value)
            decoded_string = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    decoded_string += part
            return decoded_string
        except:
            return value

    def analyze_routing(self):
        if 'Received Headers' not in self.analysis:
            return
        
        routing_analysis = {}
        
        ip_addresses = []
        servers = []
        timestamps = []
        
        for hop_data in self.analysis['Received Headers']:
            header = hop_data['header']
            
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            for ip in ip_matches:
                try:
                    ipaddress.ip_address(ip)
                    if not ipaddress.ip_address(ip).is_private:
                        ip_addresses.append(ip)
                except:
                    pass
            
            server_matches = re.findall(r'by\s+([^\s]+)', header, re.IGNORECASE)
            servers.extend(server_matches)
            
            timestamp_matches = re.findall(r';\s*(.+?)(?:\r|\n|$)', header)
            timestamps.extend(timestamp_matches)
        
        if ip_addresses:
            routing_analysis['Source IPs'] = list(set(ip_addresses))
            
            for ip in routing_analysis['Source IPs'][:3]:
                geo_info = self.geolocate_ip(ip)
                if geo_info:
                    routing_analysis[f'IP {ip} Location'] = geo_info
        
        if servers:
            routing_analysis['Mail Servers'] = list(set(servers))[:5]
        
        if timestamps:
            routing_analysis['Timestamps'] = timestamps[:3]
        
        routing_analysis['Total Hops'] = len(self.analysis['Received Headers'])
        
        self.analysis['Routing Analysis'] = routing_analysis

    def geolocate_ip(self, ip):
        try:
            import requests
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')} ({data.get('isp', 'Unknown ISP')})"
        except:
            pass
        return None

    def detect_spoofing(self):
        spoofing_indicators = []
        
        basic_headers = self.analysis.get('Basic Headers', {})
        
        from_header = basic_headers.get('From', '')
        return_path = basic_headers.get('Return-Path', '')
        sender = basic_headers.get('Sender', '')
        
        if from_header and return_path:
            from_domain = re.search(r'@([^>\s]+)', from_header)
            return_domain = re.search(r'@([^>\s]+)', return_path)
            
            if from_domain and return_domain:
                if from_domain.group(1).lower() != return_domain.group(1).lower():
                    spoofing_indicators.append("From and Return-Path domains don't match")
        
        if sender and from_header:
            if sender.lower() != from_header.lower():
                spoofing_indicators.append("Sender differs from From header")
        
        routing = self.analysis.get('Routing Analysis', {})
        source_ips = routing.get('Source IPs', [])
        
        if source_ips and from_header:
            from_domain = re.search(r'@([^>\s]+)', from_header)
            if from_domain:
                try:
                    domain_ip = socket.gethostbyname(from_domain.group(1))
                    if domain_ip not in source_ips:
                        spoofing_indicators.append("Source IP doesn't match From domain")
                except:
                    pass
        
        auth_headers = self.analysis.get('Authentication', {})
        
        if 'SPF' in auth_headers or 'Authentication-Results' in auth_headers:
            auth_results = auth_headers.get('Authentication-Results', '')
            if 'spf=fail' in auth_results.lower():
                spoofing_indicators.append("SPF authentication failed")
            if 'dkim=fail' in auth_results.lower():
                spoofing_indicators.append("DKIM authentication failed")
            if 'dmarc=fail' in auth_results.lower():
                spoofing_indicators.append("DMARC authentication failed")
        
        received_headers = self.analysis.get('Received Headers', [])
        if len(received_headers) < 2:
            spoofing_indicators.append("Unusually short email path (possible direct injection)")
        elif len(received_headers) > 10:
            spoofing_indicators.append("Unusually long email path (possible relay abuse)")
        
        if spoofing_indicators:
            self.analysis['Spoofing Indicators'] = spoofing_indicators
        else:
            self.analysis['Spoofing Indicators'] = ["No obvious spoofing indicators detected"]

    def analyze_authentication(self):
        auth_analysis = {}
        
        auth_headers = self.analysis.get('Authentication', {})
        
        if 'DKIM-Signature' in auth_headers:
            dkim = auth_headers['DKIM-Signature']
            
            domain_match = re.search(r'd=([^;]+)', dkim)
            if domain_match:
                auth_analysis['DKIM Domain'] = domain_match.group(1)
            
            selector_match = re.search(r's=([^;]+)', dkim)
            if selector_match:
                auth_analysis['DKIM Selector'] = selector_match.group(1)
            
            algorithm_match = re.search(r'a=([^;]+)', dkim)
            if algorithm_match:
                auth_analysis['DKIM Algorithm'] = algorithm_match.group(1)
        
        if 'Authentication-Results' in auth_headers:
            auth_results = auth_headers['Authentication-Results']
            
            spf_result = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_result:
                auth_analysis['SPF Result'] = spf_result.group(1)
            
            dkim_result = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_result:
                auth_analysis['DKIM Result'] = dkim_result.group(1)
            
            dmarc_result = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_result:
                auth_analysis['DMARC Result'] = dmarc_result.group(1)
        
        if auth_analysis:
            self.analysis['Authentication Analysis'] = auth_analysis

    def check_suspicious_patterns(self):
        suspicious_patterns = []
        
        basic_headers = self.analysis.get('Basic Headers', {})
        
        subject = basic_headers.get('Subject', '')
        if subject:
            if re.search(r'\b(urgent|winner|congratulations|claim|prize|lottery)\b', subject, re.IGNORECASE):
                suspicious_patterns.append("Subject contains common spam keywords")
            
            if len(re.findall(r'[!]', subject)) > 3:
                suspicious_patterns.append("Excessive exclamation marks in subject")
            
            if re.search(r'[A-Z]{5,}', subject):
                suspicious_patterns.append("Excessive capital letters in subject")
        
        from_header = basic_headers.get('From', '')
        if from_header:
            if re.search(r'[0-9]{4,}', from_header):
                suspicious_patterns.append("From address contains suspicious number patterns")
            
            if re.search(r'noreply|no-reply|donotreply', from_header, re.IGNORECASE):
                suspicious_patterns.append("From address appears to be no-reply")
        
        x_headers = self.analysis.get('X-Headers', {})
        
        for header, value in x_headers.items():
            if 'spam' in header.lower() or 'bulk' in header.lower():
                suspicious_patterns.append(f"Suspicious header detected: {header}")
        
        routing = self.analysis.get('Routing Analysis', {})
        source_ips = routing.get('Source IPs', [])
        
        for ip in source_ips:
            try:
                ip_addr = ipaddress.ip_address(ip)
                if ip_addr.is_private:
                    suspicious_patterns.append(f"Private IP address in routing: {ip}")
            except:
                pass
        
        mailer = basic_headers.get('X-Mailer', '')
        if mailer:
            suspicious_mailers = ['phpmailer', 'sendmail', 'mailchimp', 'bulk']
            if any(sus in mailer.lower() for sus in suspicious_mailers):
                suspicious_patterns.append(f"Potentially automated mailer: {mailer}")
        
        if suspicious_patterns:
            self.analysis['Suspicious Patterns'] = suspicious_patterns
        else:
            self.analysis['Suspicious Patterns'] = ["No obvious suspicious patterns detected"]

    def display_results(self):
        console.print(f"\n[red]═══ EMAIL HEADER FORENSICS REPORT ═══[/red]")
        
        for category, data in self.analysis.items():
            if data:
                table = Table(title=category, border_style="red")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            value_str = '\n'.join(str(v) for v in value)
                        else:
                            value_str = str(value)
                        
                        if len(value_str) > 100:
                            value_str = value_str[:100] + "..."
                        
                        table.add_row(str(key), value_str)
                        
                elif isinstance(data, list):
                    if category == 'Received Headers':
                        for hop in data:
                            table.add_row(f"Hop {hop['hop']}", hop['header'])
                    else:
                        for i, item in enumerate(data):
                            table.add_row(f"Item {i+1}", str(item))
                
                console.print(table)
                console.print()
        
        spoofing = self.analysis.get('Spoofing Indicators', [])
        if any('fail' in indicator.lower() or 'mismatch' in indicator.lower() or 'injection' in indicator.lower() for indicator in spoofing):
            console.print("[red]⚠️  POTENTIAL SPOOFING DETECTED - Verify email authenticity![/red]")
        
        suspicious = self.analysis.get('Suspicious Patterns', [])
        if len(suspicious) > 1 and "No obvious suspicious patterns detected" not in suspicious:
            console.print("[yellow]⚠️  Multiple suspicious patterns detected - Exercise caution![/yellow]")
        
        console.print(f"[green]Email header analysis complete[/green]")
