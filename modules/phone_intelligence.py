import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
import asyncio
import aiohttp
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class PhoneIntelligence:
    def __init__(self):
        self.session = None
        self.results = {}
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def parse_number(self, phone_number, region=None):
        console.print(f"[red]📞 Analyzing Phone Number: {phone_number}[/red]")
        
        try:
            parsed = phonenumbers.parse(phone_number, region)
            
            if not phonenumbers.is_valid_number(parsed):
                console.print("[yellow]⚠️  Invalid phone number format[/yellow]")
                return None
            
            basic_info = {
                'original': phone_number,
                'international': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                'national': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'number_type': phonenumbers.number_type(parsed),
                'is_possible': phonenumbers.is_possible_number(parsed),
                'is_valid': phonenumbers.is_valid_number(parsed)
            }
            
            location_info = geocoder.description_for_number(parsed, "en")
            carrier_info = carrier.name_for_number(parsed, "en")
            timezone_info = timezone.time_zones_for_number(parsed)
            
            basic_info.update({
                'location': location_info,
                'carrier': carrier_info,
                'timezones': list(timezone_info)
            })
            
            return basic_info, parsed
            
        except phonenumbers.NumberParseException as e:
            console.print(f"[red]Parse error: {e}[/red]")
            return None

    async def get_number_type_details(self, parsed_number):
        number_type = phonenumbers.number_type(parsed_number)
        
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "Universal Access Number",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
        }
        
        return type_mapping.get(number_type, "Unknown")

    async def scan_social_media(self, phone_number):
        console.print(f"[red]🔍 Scanning Social Media for: {phone_number}[/red]")
        
        clean_number = re.sub(r'[^\d+]', '', phone_number)
        
        social_platforms = {
            'whatsapp': f"https://wa.me/{clean_number}",
            'telegram': f"https://t.me/{clean_number}",
            'viber': f"viber://add?number={clean_number}",
            'signal': f"https://signal.me/#p/{clean_number}"
        }
        
        found_accounts = []
        
        for platform, url in social_platforms.items():
            try:
                async with self.session.head(url, timeout=10) as response:
                    if response.status in [200, 301, 302]:
                        found_accounts.append({
                            'platform': platform,
                            'url': url,
                            'status': 'Found',
                            'response_code': response.status
                        })
                    else:
                        found_accounts.append({
                            'platform': platform,
                            'url': url,
                            'status': 'Not Found',
                            'response_code': response.status
                        })
            except Exception:
                found_accounts.append({
                    'platform': platform,
                    'url': url,
                    'status': 'Error',
                    'response_code': 'N/A'
                })
        
        return found_accounts

    async def check_truecaller(self, phone_number):
        console.print(f"[red]🔍 Checking Truecaller for: {phone_number}[/red]")
        
        try:
            search_url = f"https://www.truecaller.com/search?q={phone_number}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            async with self.session.get(search_url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    name_match = re.search(r'"name":"([^"]+)"', html)
                    location_match = re.search(r'"location":"([^"]+)"', html)
                    carrier_match = re.search(r'"carrier":"([^"]+)"', html)
                    
                    if name_match or location_match or carrier_match:
                        return {
                            'service': 'Truecaller',
                            'name': name_match.group(1) if name_match else None,
                            'location': location_match.group(1) if location_match else None,
                            'carrier': carrier_match.group(1) if carrier_match else None,
                            'found': True
                        }
            
            return {'service': 'Truecaller', 'found': False}
            
        except Exception as e:
            return {'service': 'Truecaller', 'error': str(e), 'found': False}

    async def check_whocalld(self, phone_number):
        console.print(f"[red]🔍 Checking WhoCallsD for: {phone_number}[/red]")
        
        try:
            api_url = f"https://whocalld.com/api/v2/lookup/{phone_number}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with self.session.get(api_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('success'):
                        return {
                            'service': 'WhoCallsD',
                            'name': data.get('name'),
                            'type': data.get('type'),
                            'reputation': data.get('reputation'),
                            'reports': data.get('reports'),
                            'found': True
                        }
            
            return {'service': 'WhoCallsD', 'found': False}
            
        except Exception as e:
            return {'service': 'WhoCallsD', 'error': str(e), 'found': False}

    async def check_spam_databases(self, phone_number):
        console.print(f"[red]🔍 Checking Spam Databases for: {phone_number}[/red]")
        
        spam_results = []
        
        spam_sources = [
            {
                'name': 'ShouldIAnswer',
                'url': f"https://www.shouldianswer.com/phone-number/{phone_number}",
                'pattern': r'rating.*?(\d+\.?\d*)'
            },
            {
                'name': 'CallerSmart',
                'url': f"https://www.callersmart.com/number/{phone_number}",
                'pattern': r'reputation.*?(\w+)'
            },
            {
                'name': 'SpamCalls',
                'url': f"https://spamcalls.net/{phone_number}",
                'pattern': r'spam.*?(\w+)'
            }
        ]
        
        for source in spam_sources:
            try:
                async with self.session.get(source['url'], timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        
                        match = re.search(source['pattern'], html, re.IGNORECASE)
                        if match:
                            spam_results.append({
                                'source': source['name'],
                                'rating': match.group(1),
                                'url': source['url'],
                                'found': True
                            })
                        else:
                            spam_results.append({
                                'source': source['name'],
                                'found': False
                            })
            except Exception:
                spam_results.append({
                    'source': source['name'],
                    'error': 'Connection failed',
                    'found': False
                })
        
        return spam_results

    async def hlr_lookup(self, phone_number):
        console.print(f"[red]🔍 HLR Lookup for: {phone_number}[/red]")
        
        try:
            api_url = f"https://free-lookup.herokuapp.com/api/lookup/{phone_number}"
            
            async with self.session.get(api_url, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return {
                        'service': 'HLR Lookup',
                        'network': data.get('network_name'),
                        'country': data.get('country_name'),
                        'status': data.get('status'),
                        'mcc': data.get('mcc'),
                        'mnc': data.get('mnc'),
                        'found': True
                    }
            
            return {'service': 'HLR Lookup', 'found': False}
            
        except Exception as e:
            return {'service': 'HLR Lookup', 'error': str(e), 'found': False}

    def generate_variations(self, phone_number):
        console.print(f"[red]🔄 Generating Number Variations for: {phone_number}[/red]")
        
        clean_number = re.sub(r'[^\d]', '', phone_number)
        
        variations = []
        
        if len(clean_number) >= 10:
            last_digits = clean_number[-10:]
            
            variations.extend([
                f"+1{last_digits}",
                f"1{last_digits}",
                f"({last_digits[:3]}) {last_digits[3:6]}-{last_digits[6:]}",
                f"{last_digits[:3]}-{last_digits[3:6]}-{last_digits[6:]}",
                f"{last_digits[:3]}.{last_digits[3:6]}.{last_digits[6:]}",
                f"{last_digits[:3]} {last_digits[3:6]} {last_digits[6:]}",
                last_digits
            ])
        
        if clean_number.startswith('1') and len(clean_number) == 11:
            without_country = clean_number[1:]
            variations.extend([
                f"({without_country[:3]}) {without_country[3:6]}-{without_country[6:]}",
                f"{without_country[:3]}-{without_country[3:6]}-{without_country[6:]}",
                without_country
            ])
        
        return list(set(variations))

    async def comprehensive_analysis(self, phone_number, region=None):
        basic_result = self.parse_number(phone_number, region)
        
        if not basic_result:
            return None
        
        basic_info, parsed_number = basic_result
        
        console.print("[red]🔍 Running Comprehensive Analysis...[/red]")
        
        tasks = [
            self.scan_social_media(phone_number),
            self.check_truecaller(phone_number),
            self.check_whocalld(phone_number),
            self.check_spam_databases(phone_number),
            self.hlr_lookup(phone_number)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        social_media = results[0] if not isinstance(results[0], Exception) else []
        truecaller = results[1] if not isinstance(results[1], Exception) else {}
        whocalld = results[2] if not isinstance(results[2], Exception) else {}
        spam_check = results[3] if not isinstance(results[3], Exception) else []
        hlr_info = results[4] if not isinstance(results[4], Exception) else {}
        
        number_type_detail = await self.get_number_type_details(parsed_number)
        variations = self.generate_variations(phone_number)
        
        comprehensive_result = {
            'basic_info': basic_info,
            'number_type_detail': number_type_detail,
            'social_media': social_media,
            'truecaller': truecaller,
            'whocalld': whocalld,
            'spam_check': spam_check,
            'hlr_info': hlr_info,
            'variations': variations
        }
        
        return comprehensive_result

    def display_results(self, analysis_result):
        if not analysis_result:
            console.print("[red]No analysis results to display[/red]")
            return
        
        console.print(f"\n[red]═══ PHONE NUMBER INTELLIGENCE REPORT ═══[/red]")
        
        basic_info = analysis_result['basic_info']
        
        table = Table(title="📞 Basic Information", border_style="cyan")
        table.add_column("Field", style="white")
        table.add_column("Value", style="green")
        
        table.add_row("Original", basic_info['original'])
        table.add_row("International Format", basic_info['international'])
        table.add_row("National Format", basic_info['national'])
        table.add_row("E164 Format", basic_info['e164'])
        table.add_row("Country Code", str(basic_info['country_code']))
        table.add_row("Type", analysis_result['number_type_detail'])
        table.add_row("Location", basic_info['location'])
        table.add_row("Carrier", basic_info['carrier'])
        table.add_row("Timezones", ', '.join(basic_info['timezones']))
        
        console.print(table)
        
        social_media = analysis_result['social_media']
        if social_media:
            table = Table(title="📱 Social Media Presence", border_style="blue")
            table.add_column("Platform", style="cyan")
            table.add_column("Status", style="white")
            table.add_column("URL", style="dim white")
            
            for social in social_media:
                status_color = "green" if social['status'] == 'Found' else "red"
                table.add_row(
                    social['platform'].title(),
                    f"[{status_color}]{social['status']}[/{status_color}]",
                    social['url']
                )
            
            console.print(table)
        
        truecaller = analysis_result['truecaller']
        if truecaller.get('found'):
            panel_text = f"""
[green]Name:[/green] {truecaller.get('name', 'N/A')}
[green]Location:[/green] {truecaller.get('location', 'N/A')}
[green]Carrier:[/green] {truecaller.get('carrier', 'N/A')}
            """
            console.print(Panel(panel_text, title="📋 Truecaller Info", border_style="green"))
        
        spam_check = analysis_result['spam_check']
        spam_found = [s for s in spam_check if s.get('found')]
        if spam_found:
            table = Table(title="⚠️ Spam Database Results", border_style="red")
            table.add_column("Source", style="cyan")
            table.add_column("Rating/Info", style="yellow")
            
            for spam in spam_found:
                table.add_row(spam['source'], spam.get('rating', 'Reported'))
            
            console.print(table)
        
        hlr_info = analysis_result['hlr_info']
        if hlr_info.get('found'):
            panel_text = f"""
[green]Network:[/green] {hlr_info.get('network', 'N/A')}
[green]Country:[/green] {hlr_info.get('country', 'N/A')}
[green]Status:[/green] {hlr_info.get('status', 'N/A')}
[green]MCC/MNC:[/green] {hlr_info.get('mcc', 'N/A')}/{hlr_info.get('mnc', 'N/A')}
            """
            console.print(Panel(panel_text, title="📡 HLR Information", border_style="yellow"))
        
        variations = analysis_result['variations']
        if variations:
            table = Table(title="🔄 Number Variations", border_style="magenta")
            table.add_column("Format", style="white")
            
            for variation in variations[:10]:
                table.add_row(variation)
            
            console.print(table)
        
        console.print(f"\n[green]✅ Analysis completed successfully[/green]")
        console.print(f"[dim white]💡 Tip: Use variations for cross-platform searches[/dim white]")
        console.print(f"[dim white]⚠️  Results may vary based on data availability[/dim white]")
