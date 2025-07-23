import asyncio
import aiohttp
import requests
import re
from urllib.parse import quote

class FreeBreachSources:
    def __init__(self):
        self.sources = {
            'scylla_sh': {
                'name': 'Scylla.sh',
                'url': 'https://scylla.sh/search?q=email:{}',
                'method': 'GET',
                'free': True,
                'active': True
            },
            'leakcheck': {
                'name': 'LeakCheck.io',
                'url': 'https://leakcheck.io/api/public?check={}',
                'method': 'GET', 
                'free': True,
                'active': True
            },
            'weleakinfo': {
                'name': 'WeLeakInfo',
                'url': 'https://weleakinfo.to/v2/search',
                'method': 'POST',
                'free': False,
                'active': False
            },
            'snusbase': {
                'name': 'Snusbase',
                'url': 'https://snusbase.com/v1/search',
                'method': 'POST',
                'free': False,
                'active': True
            },
            'ghostproject': {
                'name': 'GhostProject',
                'url': 'https://ghostproject.fr/api/search/{}',
                'method': 'GET',
                'free': True,
                'active': False
            },
            'pwndb': {
                'name': 'PwnDB',
                'url': 'http://pwndb2am4tzkvold.onion/search',
                'method': 'POST',
                'free': True,
                'active': False,
                'tor_required': True
            }
        }

    async def check_scylla(self, email):
        try:
            url = f"https://scylla.sh/search?q=email:{quote(email)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if email.lower() in content.lower():
                            password_matches = re.findall(r'"password":"([^"]*)"', content)
                            hash_matches = re.findall(r'"hash":"([^"]*)"', content)
                            
                            results = []
                            if password_matches or hash_matches:
                                results.append({
                                    'source': 'Scylla.sh',
                                    'email': email,
                                    'passwords_found': len(password_matches),
                                    'hashes_found': len(hash_matches),
                                    'note': 'Credentials found in database'
                                })
                            return results
        except:
            pass
        return []

    async def check_leakcheck_public(self, email):
        try:
            url = f"https://leakcheck.io/api/public?check={quote(email)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        results = []
                        if data.get('found') and data.get('sources'):
                            for source in data['sources']:
                                results.append({
                                    'source': f'LeakCheck - {source}',
                                    'email': email,
                                    'breach_name': source,
                                    'note': 'Found in breach database'
                                })
                        return results
        except:
            pass
        return []

    async def check_intelligence_x(self, email):
        try:
            url = f"https://2.intelx.io/phonebook/search?term={quote(email)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        results = []
                        if isinstance(data, dict) and data.get('records'):
                            for record in data['records'][:10]:
                                results.append({
                                    'source': 'Intelligence X',
                                    'email': email,
                                    'bucket': record.get('bucket', 'Unknown'),
                                    'added': record.get('added', 'Unknown'),
                                    'note': 'Found in Intelligence X database'
                                })
                        return results
        except:
            pass
        return []

    async def check_dehashed_preview(self, email):
        try:
            url = f"https://dehashed.com/search?query=email:{quote(email)}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=15) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        results = []
                        if 'results found' in content.lower():
                            results_match = re.search(r'(\d+)\s+results?\s+found', content, re.IGNORECASE)
                            if results_match:
                                count = int(results_match.group(1))
                                if count > 0:
                                    results.append({
                                        'source': 'DeHashed (Preview)',
                                        'email': email,
                                        'results_count': count,
                                        'note': f'Found {count} potential matches (requires subscription for details)'
                                    })
                        return results
        except:
            pass
        return []

    async def check_pastebin_dumps(self, email):
        try:
            sources = [
                f"https://psbdmp.ws/api/search/{quote(email)}",
                f"https://ghostbin.co/search.php?search={quote(email)}"
            ]
            
            results = []
            for url in sources:
                try:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, headers=headers, timeout=10) as response:
                            if response.status == 200:
                                if 'psbdmp.ws' in url:
                                    data = await response.json()
                                    if isinstance(data, dict) and data.get('data'):
                                        results.append({
                                            'source': 'Pastebin Dumps (psbdmp)',
                                            'email': email,
                                            'dumps_found': len(data['data']),
                                            'note': f'Found in {len(data["data"])} paste dumps'
                                        })
                                else:
                                    content = await response.text()
                                    if email.lower() in content.lower():
                                        results.append({
                                            'source': 'GhostBin',
                                            'email': email,
                                            'note': 'Potential match found in paste site'
                                        })
                except:
                    continue
            
            return results
        except:
            pass
        return []

    async def search_all_free_sources(self, email):
        all_results = []
        
        tasks = [
            self.check_leakcheck_public(email),
            self.check_intelligence_x(email),
            self.check_dehashed_preview(email),
            self.check_pastebin_dumps(email),
            self.check_scylla(email)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_results.extend(result)
        
        return all_results

class GoogleDorkSearcher:
    def __init__(self):
        self.dorks = [
            'site:pastebin.com "{}"',
            'site:paste.org.ru "{}"',
            'site:slexy.org "{}"',
            'site:snipplr.com "{}"',
            'site:snipt.net "{}"',
            'site:textsnip.com "{}"',
            'site:bitpaste.app "{}"',
            'site:justpaste.it "{}"',
            'site:heypasteit.com "{}"',
            'site:hastebin.com "{}"',
            'site:dpaste.org "{}"',
            'site:controlc.com "{}"',
            'site:codepad.org "{}"',
            'site:ideone.com "{}"',
            'site:github.com "{}"',
            'site:gitlab.com "{}"',
            'site:bitbucket.org "{}"',
            'filetype:sql "{}"',
            'filetype:log "{}"',
            'filetype:txt "{}" password',
            'filetype:csv "{}"',
            'intext:"{}" password',
            'intext:"{}" leak',
            'intext:"{}" breach',
            'intext:"{}" dump'
        ]
    
    def generate_search_urls(self, email):
        urls = []
        for dork in self.dorks:
            query = dork.format(email)
            google_url = f"https://www.google.com/search?q={quote(query)}"
            bing_url = f"https://www.bing.com/search?q={quote(query)}"
            duckduckgo_url = f"https://duckduckgo.com/?q={quote(query)}"
            
            urls.append({
                'dork': query,
                'google': google_url,
                'bing': bing_url,
                'duckduckgo': duckduckgo_url
            })
        
        return urls
