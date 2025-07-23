#!/usr/bin/env python3

import click
import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.table import Table
from colorama import init, Fore, Back, Style
import pyfiglet
import sys

# Load environment variables from config.env
config_path = Path(__file__).parent / 'config.env'
if config_path.exists():
    load_dotenv(config_path)
else:
    print(f"⚠️ Configuration file not found: {config_path}")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.domain_enum import DomainEnumerator
from modules.username_enum import UsernameEnumerator
from modules.metadata_extractor import MetadataExtractor
from modules.email_checker import EmailChecker
from modules.website_harvester import WebsiteHarvester
from modules.geo_analyzer import GeoAnalyzer
from modules.forum_crawler import ForumCrawler
from modules.ip_analyzer import IPAnalyzer
from modules.people_search import PeopleSearch
from modules.email_header import EmailHeaderAnalyzer
from modules.hash_reversal import HashReversalEngine
from modules.smart_auto_profiler import SmartAutoProfiler

init(autoreset=True)
console = Console()

def show_banner():
    banner = pyfiglet.figlet_format("TOXINT", font="slant")
    threat_text = Text("Threat-Oriented eXternal Intelligence Toolkit", style="bold red")
    version_text = Text("v3.0.0 | Enhanced OSINT Arsenal with Smart Auto-Profiler", style="dim white")
    github_text = Text("github.com/amrulizwan/toxint", style="blue")
    
    # Show config status
    config_status = "✅ Config Loaded" if os.getenv('HIBP_API_KEY') != 'your-hibp-api-key-here' else "⚠️ Default Config"
    status_text = Text(f"Status: {config_status}", style="yellow")
    
    console.print(Panel.fit(
        f"[red]{banner}[/red]\n{threat_text}\n{version_text}\n{github_text}\n{status_text}",
        border_style="red",
        padding=(1, 2)
    ))

def show_menu():
    table = Table(border_style="red")
    table.add_column("ID", style="cyan bold", width=4)
    table.add_column("Module", style="white bold", width=30)
    table.add_column("Description", style="dim white")
    
    modules = [
        ("01", "Domain Footprint", "Enumerate domains, subdomains, WHOIS, ASN"),
        ("02", "Username Hunter", "Search usernames across multiple platforms"),
        ("03", "Metadata Ripper", "Extract hidden metadata from files"),
        ("04", "Email Breach Scanner", "Check email breaches and public accounts"),
        ("05", "Website Harvester", "Extract website metadata and tech stack"),
        ("06", "Geo Intelligence", "Location analysis from images and data"),
        ("07", "Forum Crawler", "Deep forum analysis and identity correlation"),
        ("08", "IP Analyzer", "Comprehensive IP address intelligence"),
        ("09", "People Search", "Advanced people search and social mapping"),
        ("10", "Email Header Forensics", "Deep email header analysis"),
        ("11", "Metadata Remover", "Advanced metadata cleaning and removal"),
        ("12", "WiFi Geolocation", "BSSID geolocation and WiFi intelligence"),
        ("13", "Phone Intelligence", "Phone number OSINT and social media"),
        ("14", "Hash Reversal Engine", "Offline rainbow table & online hash cracking"),
        ("15", "🔥 Smart Auto-Profiler", "Intelligent comprehensive target analysis + 9 report types")
    ]
    
    for module in modules:
        table.add_row(*module)
    
    console.print(table)

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        show_banner()
        show_menu()
        
        choice = console.input("\n[bold red]Select module (01-15) or 'q' to quit: [/bold red]")
        
        if choice.lower() == 'q':
            console.print("[red]Exiting TOXINT...[/red]")
            sys.exit(0)
        
        module_map = {
            "01": "domain",
            "02": "username", 
            "03": "metadata",
            "04": "email",
            "05": "website",
            "06": "geo",
            "07": "forum",
            "08": "ip",
            "09": "people",
            "10": "header",
            "11": "metadata_remover_menu",
            "12": "wifi_geolocation_menu", 
            "13": "phone_intelligence_menu",
            "14": "hash_reversal_menu",
            "15": "smart_auto_profiler_menu"
        }
        
        if choice in module_map:
            ctx.invoke(globals()[module_map[choice]])
        else:
            console.print("[red]Invalid selection![/red]")

@cli.command()
def domain():
    target = console.input("[cyan]Enter target domain: [/cyan]")
    enumerator = DomainEnumerator()
    asyncio.run(enumerator.enumerate(target))

@cli.command()
def username():
    target = console.input("[cyan]Enter username to search: [/cyan]")
    enumerator = UsernameEnumerator()
    asyncio.run(enumerator.search(target))

@cli.command()
def metadata():
    filepath = console.input("[cyan]Enter file path: [/cyan]")
    extractor = MetadataExtractor()
    extractor.extract(filepath)

@cli.command()
def email():
    target = console.input("[cyan]Enter email address: [/cyan]")
    checker = EmailChecker()
    asyncio.run(checker.check(target))

@cli.command()
def website():
    target = console.input("[cyan]Enter website URL: [/cyan]")
    harvester = WebsiteHarvester()
    asyncio.run(harvester.harvest(target))

@cli.command()
def geo():
    source = console.input("[cyan]Enter image path or coordinates: [/cyan]")
    analyzer = GeoAnalyzer()
    analyzer.analyze(source)

@cli.command()
def forum():
    target = console.input("[cyan]Enter forum URL or username: [/cyan]")
    crawler = ForumCrawler()
    asyncio.run(crawler.crawl(target))

@cli.command()
def ip():
    target = console.input("[cyan]Enter IP address: [/cyan]")
    analyzer = IPAnalyzer()
    asyncio.run(analyzer.analyze(target))

@cli.command()
def people():
    target = console.input("[cyan]Enter full name or handle: [/cyan]")
    searcher = PeopleSearch()
    asyncio.run(searcher.search(target))

@cli.command()
def header():
    filepath = console.input("[cyan]Enter email header file path: [/cyan]")
    analyzer = EmailHeaderAnalyzer()
    analyzer.analyze(filepath)

@cli.command()
def metadata_remover_menu():
    console.print("[red]═══ METADATA REMOVER ═══[/red]")
    console.print("[white]1. Single file cleanup[/white]")
    console.print("[white]2. Batch directory cleanup[/white]")
    console.print("[white]3. Compare metadata[/white]")
    
    choice = console.input("[cyan]Select option: [/cyan]")
    
    if choice == "1":
        filepath = console.input("[cyan]Enter file path: [/cyan]")
        output_dir = console.input("[cyan]Enter output directory (optional): [/cyan]") or None
        
        from modules.metadata_remover import MetadataRemover
        remover = MetadataRemover()
        cleaned_path = remover.remove_metadata(filepath, output_dir)
        remover.display_results()
        
    elif choice == "2":
        directory = console.input("[cyan]Enter directory path: [/cyan]")
        recursive = console.input("[cyan]Recursive? (y/N): [/cyan]").lower() == 'y'
        
        from modules.metadata_remover import MetadataRemover
        remover = MetadataRemover()
        remover.batch_clean(directory, recursive)
        
    elif choice == "3":
        original = console.input("[cyan]Enter original file path: [/cyan]")
        cleaned = console.input("[cyan]Enter cleaned file path: [/cyan]")
        
        from modules.metadata_remover import MetadataRemover
        remover = MetadataRemover()
        remover.compare_metadata(original, cleaned)

@cli.command()
def wifi_geolocation_menu():
    console.print("[red]═══ WIFI GEOLOCATION ═══[/red]")
    console.print("[white]1. Scan local WiFi networks[/white]")
    console.print("[white]2. Geolocate specific BSSID[/white]")
    console.print("[white]3. Batch geolocate multiple BSSIDs[/white]")
    
    choice = console.input("[cyan]Select option: [/cyan]")
    
    import asyncio
    from modules.wifi_geolocation import WifiGeolocation
    
    if choice == "1":
        async def scan_local():
            async with WifiGeolocation() as geo:
                networks = await geo.scan_local_wifi()
                geolocations = []
                
                if networks:
                    batch_geo = console.input("[cyan]Geolocate all found networks? (y/N): [/cyan]").lower() == 'y'
                    if batch_geo:
                        bssid_list = [n['bssid'] for n in networks if n.get('bssid')]
                        geolocations = await geo.batch_geolocate(bssid_list)
                
                accuracy_info = None
                if len(geolocations) > 1:
                    accuracy_info = geo.calculate_location_accuracy(geolocations)
                
                geo.display_results(networks, geolocations, accuracy_info)
        
        asyncio.run(scan_local())
        
    elif choice == "2":
        bssid = console.input("[cyan]Enter BSSID (e.g., 00:11:22:33:44:55): [/cyan]")
        
        async def single_geo():
            async with WifiGeolocation() as geo:
                result = await geo.geolocate_bssid(bssid)
                if result:
                    geolocations = [{'bssid': bssid, 'location': result}]
                    geo.display_results([], geolocations)
        
        asyncio.run(single_geo())
        
    elif choice == "3":
        bssids_input = console.input("[cyan]Enter BSSIDs separated by commas: [/cyan]")
        bssids = [b.strip() for b in bssids_input.split(',')]
        
        async def batch_geo():
            async with WifiGeolocation() as geo:
                geolocations = await geo.batch_geolocate(bssids)
                
                accuracy_info = None
                if len(geolocations) > 1:
                    accuracy_info = geo.calculate_location_accuracy(geolocations)
                
                geo.display_results([], geolocations, accuracy_info)
        
        asyncio.run(batch_geo())

@cli.command()
def phone_intelligence_menu():
    console.print("[red]═══ PHONE INTELLIGENCE ═══[/red]")
    console.print("[white]1. Basic phone number analysis[/white]")
    console.print("[white]2. Comprehensive analysis[/white]")
    console.print("[white]3. Generate number variations[/white]")
    
    choice = console.input("[cyan]Select option: [/cyan]")
    
    phone_number = console.input("[cyan]Enter phone number: [/cyan]")
    region = console.input("[cyan]Enter region code (optional, e.g., US, ID): [/cyan]") or None
    
    import asyncio
    from modules.phone_intelligence import PhoneIntelligence
    
    if choice == "1":
        async def basic_analysis():
            async with PhoneIntelligence() as intel:
                basic_result = intel.parse_number(phone_number, region)
                if basic_result:
                    basic_info, parsed_number = basic_result
                    
                    table = Table(title="Phone Number Info", border_style="cyan")
                    table.add_column("Field", style="white")
                    table.add_column("Value", style="green")
                    
                    for key, value in basic_info.items():
                        if key not in ['timezones']:
                            table.add_row(key.replace('_', ' ').title(), str(value))
                    
                    console.print(table)
        
        asyncio.run(basic_analysis())
        
    elif choice == "2":
        async def comprehensive_analysis():
            async with PhoneIntelligence() as intel:
                result = await intel.comprehensive_analysis(phone_number, region)
                intel.display_results(result)
        
        asyncio.run(comprehensive_analysis())
        
    elif choice == "3":
        async def variations():
            async with PhoneIntelligence() as intel:
                var_list = intel.generate_variations(phone_number)
                console.print(f"\n[yellow]Generated {len(var_list)} variations:[/yellow]")
                for var in var_list:
                    console.print(f"  {var}")
        
        asyncio.run(variations())

@cli.command()
@click.argument('file_path')
@click.option('--output-dir', '-o', help='Output directory for cleaned files')
@click.option('--batch', '-b', is_flag=True, help='Batch clean directory')
@click.option('--recursive', '-r', is_flag=True, help='Recursive directory cleaning')
@click.option('--compare', '-c', is_flag=True, help='Compare metadata before/after')
def metadata_remover(file_path, output_dir, batch, recursive, compare):
    from modules.metadata_remover import MetadataRemover
    
    remover = MetadataRemover()
    
    if batch:
        remover.batch_clean(file_path, recursive)
    else:
        cleaned_path = remover.remove_metadata(file_path, output_dir)
        
        if cleaned_path and compare:
            remover.compare_metadata(file_path, cleaned_path)
    
    remover.display_results()

@cli.command()
@click.argument('bssids', nargs=-1)
@click.option('--scan-local', '-s', is_flag=True, help='Scan local WiFi networks')
@click.option('--batch', '-b', is_flag=True, help='Batch geolocate all BSSIDs')
def wifi_geolocation(bssids, scan_local, batch):
    import asyncio
    from modules.wifi_geolocation import WifiGeolocation
    
    async def run_wifi_geo():
        async with WifiGeolocation() as geo:
            networks = []
            geolocations = []
            
            if scan_local:
                networks = await geo.scan_local_wifi()
                console.print(f"[green]Found {len(networks)} networks[/green]")
                
                if networks and batch:
                    bssid_list = [n['bssid'] for n in networks if n.get('bssid')]
                    geolocations = await geo.batch_geolocate(bssid_list)
            
            if bssids:
                if batch:
                    geolocations.extend(await geo.batch_geolocate(list(bssids)))
                else:
                    for bssid in bssids:
                        result = await geo.geolocate_bssid(bssid)
                        if result:
                            geolocations.append({'bssid': bssid, 'location': result})
            
            accuracy_info = None
            if len(geolocations) > 1:
                accuracy_info = geo.calculate_location_accuracy(geolocations)
            
            geo.display_results(networks, geolocations, accuracy_info)
    
    asyncio.run(run_wifi_geo())

@cli.command()
@click.argument('phone_number')
@click.option('--region', '-r', help='Region code for parsing (e.g., US, ID)')
@click.option('--variations', '-v', is_flag=True, help='Generate number variations')
@click.option('--comprehensive', '-c', is_flag=True, help='Run comprehensive analysis')
def phone_intelligence(phone_number, region, variations, comprehensive):
    import asyncio
    from modules.phone_intelligence import PhoneIntelligence
    
    async def run_phone_intel():
        async with PhoneIntelligence() as intel:
            if comprehensive:
                result = await intel.comprehensive_analysis(phone_number, region)
                intel.display_results(result)
            else:
                basic_result = intel.parse_number(phone_number, region)
                if basic_result:
                    basic_info, parsed_number = basic_result
                    
                    if variations:
                        var_list = intel.generate_variations(phone_number)
                        console.print(f"\n[yellow]Generated {len(var_list)} variations[/yellow]")
                        for var in var_list:
                            console.print(f"  {var}")
                    
                    console.print(f"\n[green]Basic analysis completed[/green]")
                    
                    table = Table(title="Phone Number Info", border_style="cyan")
                    table.add_column("Field", style="white")
                    table.add_column("Value", style="green")
                    
                    for key, value in basic_info.items():
                        if key not in ['timezones']:
                            table.add_row(key.replace('_', ' ').title(), str(value))
                    
                    console.print(table)
    
    asyncio.run(run_phone_intel())

@cli.command()
def hash_reversal_menu():
    console.print("[red]═══ HASH REVERSAL ENGINE ═══[/red]")
    console.print("[white]1. Single hash cracking[/white]")
    console.print("[white]2. Batch hash cracking from file[/white]")
    console.print("[white]3. Generate rainbow table[/white]")
    console.print("[white]4. Extract hashes from file[/white]")
    
    choice = console.input("[cyan]Select option: [/cyan]")
    
    engine = HashReversalEngine()
    
    if choice == "1":
        hash_input = console.input("[cyan]Enter hash to crack: [/cyan]")
        
        async def single_crack():
            result = await engine.comprehensive_crack(hash_input)
            engine.display_results([result])
        
        asyncio.run(single_crack())
        
    elif choice == "2":
        filepath = console.input("[cyan]Enter file path with hashes (one per line): [/cyan]")
        
        async def batch_crack():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    hashes = [line.strip() for line in f if line.strip()]
                
                results = []
                for hash_value in hashes:
                    result = await engine.comprehensive_crack(hash_value)
                    results.append(result)
                
                engine.display_results(results)
                
            except Exception as e:
                console.print(f"[red]Error reading file: {e}[/red]")
        
        asyncio.run(batch_crack())
        
    elif choice == "3":
        algorithm = console.input("[cyan]Enter algorithm (md5/sha1/sha256/sha512): [/cyan]").lower()
        wordlist = console.input("[cyan]Enter wordlist file path: [/cyan]")
        max_entries = console.input("[cyan]Max entries (default 100000): [/cyan]")
        
        try:
            max_entries = int(max_entries) if max_entries else 100000
        except ValueError:
            max_entries = 100000
        
        engine.generate_rainbow_table(algorithm, wordlist, max_entries)
        
    elif choice == "4":
        filepath = console.input("[cyan]Enter file path to extract hashes from: [/cyan]")
        
        hashes = engine.extract_hashes_from_file(filepath)
        
        if hashes:
            console.print(f"[green]Found {len(hashes)} hashes[/green]")
            
            crack_choice = console.input("[cyan]Crack all found hashes? (y/N): [/cyan]").lower()
            
            if crack_choice == 'y':
                async def crack_extracted():
                    results = []
                    for hash_info in hashes:
                        result = await engine.comprehensive_crack(hash_info['hash'])
                        results.append(result)
                    
                    engine.display_results(results)
                
                asyncio.run(crack_extracted())

@cli.command()
def smart_auto_profiler_menu():
    console.print("[red]═══ SMART AUTO-PROFILER ═══[/red]")
    console.print("[white]1. Comprehensive target profiling[/white]")
    console.print("[white]2. Domain-focused analysis[/white]")
    console.print("[white]3. Person-focused analysis[/white]")
    console.print("[white]4. 🔥 Advanced Multi-Data Analysis[/white]")
    
    choice = console.input("[cyan]Select analysis type: [/cyan]")
    
    if choice == "4":
        console.print("\n[yellow]💡 Advanced Multi-Data Analysis[/yellow]")
        console.print("[dim white]Enter multiple pieces of information about ONE target, separated by commas.[/dim white]")
        console.print("[dim white]Examples:[/dim white]")
        console.print("[dim white]• user@domain.com, username123, +1234567890, First Last[/dim white]")
        console.print("[dim white]• testuser, test@sample.com, sample.com, +62123456789[/dim white]")
        console.print("[dim white]• alice_test, alice@company.com, company.com, Alice Test[/dim white]")
        
        target = console.input("\n[cyan]Enter target with multiple data (comma-separated): [/cyan]")
    else:
        target = console.input("[cyan]Enter target (domain, email, name, etc.): [/cyan]")
    
    async def run_profiler():
        async with SmartAutoProfiler() as profiler:
            if choice == "1":
                results = await profiler.comprehensive_profile(target)
            elif choice == "2":
                results = await profiler.domain_focused_analysis(target)
            elif choice == "3":
                results = await profiler.person_focused_analysis(target)
            elif choice == "4":
                results = await profiler.comprehensive_profile(target)
                results = await profiler.multi_data_profile(target)
            else:
                console.print("[red]Invalid choice![/red]")
                return
    
    asyncio.run(run_profiler())

if __name__ == "__main__":
    cli()
