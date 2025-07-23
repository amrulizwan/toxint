import hashlib
import os
import re
import json
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
import time
import requests

console = Console()

class HashReversalEngine:
    def __init__(self):
        self.rainbow_tables = {}
        self.hash_cache = {}
        self.supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        self.common_passwords_file = 'wordlists/common_passwords.txt'
        self.cracked_hashes = {}
        
        self.online_services = {
            'hashes.com': {
                'url': 'https://hashes.com/en/api/identifier',
                'method': 'GET',
                'free_limit': 100
            },
            'md5decrypt.net': {
                'url': 'https://md5decrypt.net/en/Api/api.php',
                'method': 'GET',
                'free_limit': 50
            },
            'hashkiller.io': {
                'url': 'https://hashkiller.io/api/hash/',
                'method': 'GET',
                'free_limit': 20
            }
        }
        
        self.load_rainbow_tables()

    def identify_hash_type(self, hash_string):
        hash_string = hash_string.strip().lower()
        
        hash_patterns = {
            'md5': (32, r'^[a-f0-9]{32}$'),
            'sha1': (40, r'^[a-f0-9]{40}$'),
            'sha224': (56, r'^[a-f0-9]{56}$'),
            'sha256': (64, r'^[a-f0-9]{64}$'),
            'sha384': (96, r'^[a-f0-9]{96}$'),
            'sha512': (128, r'^[a-f0-9]{128}$'),
            'ntlm': (32, r'^[a-f0-9]{32}$'),
            'mysql': (16, r'^\*[A-F0-9]{40}$')
        }
        
        possible_types = []
        
        for hash_type, (length, pattern) in hash_patterns.items():
            if len(hash_string) == length and re.match(pattern, hash_string):
                possible_types.append(hash_type)
        
        if len(hash_string) == 32:
            return ['md5', 'ntlm']
        elif len(hash_string) == 40:
            return ['sha1']
        elif len(hash_string) == 64:
            return ['sha256']
        elif len(hash_string) == 128:
            return ['sha512']
        else:
            return ['unknown']

    def generate_rainbow_table(self, algorithm, wordlist_file, max_entries=100000):
        console.print(f"[red]🌈 Generating rainbow table for {algorithm.upper()}[/red]")
        
        if algorithm not in self.supported_algorithms:
            console.print(f"[red]Unsupported algorithm: {algorithm}[/red]")
            return False
        
        if not os.path.exists(wordlist_file):
            console.print(f"[red]Wordlist file not found: {wordlist_file}[/red]")
            return False
        
        rainbow_table = {}
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                with Progress() as progress:
                    task = progress.add_task(f"[red]Generating {algorithm} hashes...", total=max_entries)
                    
                    count = 0
                    for line in f:
                        if count >= max_entries:
                            break
                        
                        password = line.strip()
                        if password and len(password) <= 50:
                            
                            if algorithm == 'md5':
                                hash_obj = hashlib.md5(password.encode('utf-8'))
                            elif algorithm == 'sha1':
                                hash_obj = hashlib.sha1(password.encode('utf-8'))
                            elif algorithm == 'sha256':
                                hash_obj = hashlib.sha256(password.encode('utf-8'))
                            elif algorithm == 'sha512':
                                hash_obj = hashlib.sha512(password.encode('utf-8'))
                            
                            hash_value = hash_obj.hexdigest()
                            rainbow_table[hash_value] = password
                            
                            count += 1
                            progress.update(task, advance=1)
            
            self.rainbow_tables[algorithm] = rainbow_table
            
            table_file = f'rainbow_tables/{algorithm}_table.json'
            os.makedirs('rainbow_tables', exist_ok=True)
            
            with open(table_file, 'w', encoding='utf-8') as f:
                json.dump(rainbow_table, f, indent=2)
            
            console.print(f"[green]✅ Generated {len(rainbow_table)} {algorithm} hashes[/green]")
            console.print(f"[green]💾 Saved to: {table_file}[/green]")
            
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to generate rainbow table: {e}[/red]")
            return False

    def load_rainbow_tables(self):
        console.print("[red]📚 Loading rainbow tables...[/red]")
        
        tables_dir = 'rainbow_tables'
        if not os.path.exists(tables_dir):
            os.makedirs(tables_dir)
            console.print("[yellow]No rainbow tables found. Generate them first.[/yellow]")
            return
        
        for algorithm in self.supported_algorithms:
            table_file = os.path.join(tables_dir, f'{algorithm}_table.json')
            
            if os.path.exists(table_file):
                try:
                    with open(table_file, 'r', encoding='utf-8') as f:
                        self.rainbow_tables[algorithm] = json.load(f)
                    
                    console.print(f"[green]✅ Loaded {len(self.rainbow_tables[algorithm])} {algorithm} hashes[/green]")
                    
                except Exception as e:
                    console.print(f"[yellow]Failed to load {algorithm} table: {e}[/yellow]")

    def offline_crack(self, hash_string):
        hash_string = hash_string.strip().lower()
        possible_types = self.identify_hash_type(hash_string)
        
        for hash_type in possible_types:
            if hash_type in self.rainbow_tables:
                if hash_string in self.rainbow_tables[hash_type]:
                    return {
                        'hash': hash_string,
                        'plaintext': self.rainbow_tables[hash_type][hash_string],
                        'algorithm': hash_type,
                        'method': 'rainbow_table',
                        'cracked': True
                    }
        
        return None

    async def online_crack(self, hash_string):
        hash_string = hash_string.strip().lower()
        
        for service_name, service_info in self.online_services.items():
            try:
                if service_name == 'hashes.com':
                    result = await self.check_hashes_com(hash_string)
                elif service_name == 'md5decrypt.net':
                    result = await self.check_md5decrypt(hash_string)
                elif service_name == 'hashkiller.io':
                    result = await self.check_hashkiller(hash_string)
                else:
                    continue
                
                if result and result.get('cracked'):
                    return result
                
                await asyncio.sleep(1)
                
            except Exception as e:
                console.print(f"[yellow]Online service {service_name} failed: {e}[/yellow]")
                continue
        
        return None

    async def check_hashes_com(self, hash_string):
        try:
            import aiohttp
            
            url = f"https://hashes.com/en/api/identifier"
            data = {'hashes': hash_string}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('success') and result.get('hashes'):
                            hash_data = result['hashes'][0]
                            if hash_data.get('plaintext'):
                                return {
                                    'hash': hash_string,
                                    'plaintext': hash_data['plaintext'],
                                    'algorithm': hash_data.get('hashtype', 'unknown'),
                                    'method': 'hashes.com',
                                    'cracked': True
                                }
            
            return None
            
        except Exception as e:
            return None

    async def check_md5decrypt(self, hash_string):
        try:
            import aiohttp
            
            url = f"https://md5decrypt.net/en/Api/api.php?hash={hash_string}&hash_type=md5&email=test@test.com&code=123"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        
                        if text and text != "Not found.":
                            return {
                                'hash': hash_string,
                                'plaintext': text.strip(),
                                'algorithm': 'md5',
                                'method': 'md5decrypt.net',
                                'cracked': True
                            }
            
            return None
            
        except Exception as e:
            return None

    async def check_hashkiller(self, hash_string):
        try:
            import aiohttp
            
            url = f"https://hashkiller.io/api/hash/{hash_string}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        if result.get('success') and result.get('plaintext'):
                            return {
                                'hash': hash_string,
                                'plaintext': result['plaintext'],
                                'algorithm': result.get('type', 'unknown'),
                                'method': 'hashkiller.io',
                                'cracked': True
                            }
            
            return None
            
        except Exception as e:
            return None

    def dictionary_attack(self, hash_string, wordlist_file):
        console.print(f"[red]📖 Dictionary attack on {hash_string[:16]}...[/red]")
        
        hash_string = hash_string.strip().lower()
        possible_types = self.identify_hash_type(hash_string)
        
        if not os.path.exists(wordlist_file):
            console.print(f"[red]Wordlist file not found: {wordlist_file}[/red]")
            return None
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            
            for hash_type in possible_types:
                if hash_type in self.supported_algorithms:
                    
                    with Progress() as progress:
                        task = progress.add_task(f"[red]Testing {hash_type} against {len(words)} words...", total=len(words))
                        
                        for word in words:
                            if hash_type == 'md5':
                                test_hash = hashlib.md5(word.encode('utf-8')).hexdigest()
                            elif hash_type == 'sha1':
                                test_hash = hashlib.sha1(word.encode('utf-8')).hexdigest()
                            elif hash_type == 'sha256':
                                test_hash = hashlib.sha256(word.encode('utf-8')).hexdigest()
                            elif hash_type == 'sha512':
                                test_hash = hashlib.sha512(word.encode('utf-8')).hexdigest()
                            else:
                                continue
                            
                            if test_hash == hash_string:
                                return {
                                    'hash': hash_string,
                                    'plaintext': word,
                                    'algorithm': hash_type,
                                    'method': 'dictionary_attack',
                                    'cracked': True
                                }
                            
                            progress.update(task, advance=1)
            
            return None
            
        except Exception as e:
            console.print(f"[red]Dictionary attack failed: {e}[/red]")
            return None

    def extract_hashes_from_file(self, filepath):
        console.print(f"[red]🔍 Extracting hashes from: {filepath}[/red]")
        
        if not os.path.exists(filepath):
            console.print(f"[red]File not found: {filepath}[/red]")
            return []
        
        hash_patterns = {
            'md5': r'\b[a-f0-9]{32}\b',
            'sha1': r'\b[a-f0-9]{40}\b',
            'sha256': r'\b[a-f0-9]{64}\b',
            'sha512': r'\b[a-f0-9]{128}\b'
        }
        
        found_hashes = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for hash_type, pattern in hash_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    hash_value = match.group().lower()
                    
                    found_hashes.append({
                        'hash': hash_value,
                        'type': hash_type,
                        'position': match.start(),
                        'context': content[max(0, match.start()-20):match.end()+20]
                    })
            
            unique_hashes = []
            seen_hashes = set()
            
            for hash_info in found_hashes:
                if hash_info['hash'] not in seen_hashes:
                    unique_hashes.append(hash_info)
                    seen_hashes.add(hash_info['hash'])
            
            console.print(f"[green]Found {len(unique_hashes)} unique hashes in file[/green]")
            return unique_hashes
            
        except Exception as e:
            console.print(f"[red]Failed to extract hashes: {e}[/red]")
            return []

    async def comprehensive_crack(self, hash_string):
        console.print(f"[red]🔐 Comprehensive hash cracking for: {hash_string[:16]}...[/red]")
        
        if hash_string in self.hash_cache:
            return self.hash_cache[hash_string]
        
        hash_types = self.identify_hash_type(hash_string)
        console.print(f"[yellow]Detected hash types: {', '.join(hash_types)}[/yellow]")
        
        offline_result = self.offline_crack(hash_string)
        if offline_result:
            self.hash_cache[hash_string] = offline_result
            return offline_result
        
        console.print("[yellow]Offline crack failed, trying online services...[/yellow]")
        online_result = await self.online_crack(hash_string)
        if online_result:
            self.hash_cache[hash_string] = online_result
            return online_result
        
        console.print("[yellow]Online services failed, trying dictionary attack...[/yellow]")
        if os.path.exists(self.common_passwords_file):
            dict_result = self.dictionary_attack(hash_string, self.common_passwords_file)
            if dict_result:
                self.hash_cache[hash_string] = dict_result
                return dict_result
        
        failed_result = {
            'hash': hash_string,
            'plaintext': None,
            'algorithm': hash_types[0] if hash_types else 'unknown',
            'method': 'failed',
            'cracked': False
        }
        
        self.hash_cache[hash_string] = failed_result
        return failed_result

    def display_results(self, results):
        console.print(f"\n[red]═══ HASH REVERSAL ENGINE REPORT ═══[/red]")
        
        if not results:
            console.print("[yellow]No hashes to process[/yellow]")
            return
        
        cracked_hashes = [r for r in results if r.get('cracked')]
        failed_hashes = [r for r in results if not r.get('cracked')]
        
        if cracked_hashes:
            table = Table(title="🔓 Successfully Cracked Hashes", border_style="green")
            table.add_column("Hash (truncated)", style="cyan")
            table.add_column("Plaintext", style="white")
            table.add_column("Algorithm", style="yellow")
            table.add_column("Method", style="green")
            
            for result in cracked_hashes:
                hash_display = result['hash'][:16] + "..." if len(result['hash']) > 16 else result['hash']
                
                table.add_row(
                    hash_display,
                    result['plaintext'][:30] + "..." if len(result['plaintext']) > 30 else result['plaintext'],
                    result['algorithm'].upper(),
                    result['method'].replace('_', ' ').title()
                )
            
            console.print(table)
        
        if failed_hashes:
            table = Table(title="🔒 Failed to Crack", border_style="red")
            table.add_column("Hash (truncated)", style="cyan")
            table.add_column("Algorithm", style="yellow")
            table.add_column("Status", style="red")
            
            for result in failed_hashes:
                hash_display = result['hash'][:16] + "..." if len(result['hash']) > 16 else result['hash']
                
                table.add_row(
                    hash_display,
                    result['algorithm'].upper(),
                    "Failed to crack"
                )
            
            console.print(table)
        
        summary_text = f"""
[green]📊 Cracking Summary:[/green]
Total Hashes: {len(results)}
Successfully Cracked: {len(cracked_hashes)}
Failed to Crack: {len(failed_hashes)}
Success Rate: {(len(cracked_hashes) / len(results) * 100):.1f}%

[yellow]🔧 Methods Used:[/yellow]
• Rainbow Table Lookup
• Online Hash Databases
• Dictionary Attack
• Pattern Recognition
        """
        
        console.print(Panel(summary_text, title="Hash Reversal Summary", border_style="green"))
        
        console.print(f"\n[dim white]💡 Tip: Increase rainbow table size for better offline success rate[/dim white]")
        console.print(f"[dim white]⚠️  Always use responsibly and only on authorized systems[/dim white]")
