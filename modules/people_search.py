import asyncio
import aiohttp
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import networkx as nx
import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import re
import json
import time

console = Console()

class PeopleSearch:
    def __init__(self):
        self.search_results = {}
        self.social_graph = nx.Graph()

    async def search(self, query):
        console.print(f"[red]Searching for: {query}[/red]")
        
        results = {
            'query': query,
            'social_platforms': [],
            'professional_networks': [],
            'public_records': [],
            'search_engines': [],
            'people_engines': [],
            'social_graph': None,
            'timestamp': __import__('time').strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with Progress() as progress:
            task = progress.add_task("[red]Searching...", total=6)
            
            progress.update(task, advance=1, description="[red]Social platforms...")
            await self.search_social_platforms(query)
            
            progress.update(task, advance=1, description="[red]Professional networks...")
            await self.search_professional_networks(query)
            
            progress.update(task, advance=1, description="[red]Public records...")
            await self.search_public_records(query)
            
            progress.update(task, advance=1, description="[red]Search engines...")
            await self.search_engines(query)
            
            progress.update(task, advance=1, description="[red]People search engines...")
            await self.people_search_engines(query)
            
            progress.update(task, advance=1, description="[red]Building social graph...")
            self.build_social_graph()
        
        results.update(self.search_results)
        results['social_graph'] = self.social_graph.nodes() if self.social_graph else []
        
        self.display_results(query)
        
        return results

    async def search_social_platforms(self, query):
        platforms = {
            'Facebook': f"https://www.facebook.com/public/{query.replace(' ', '-')}",
            'LinkedIn': f"https://www.linkedin.com/pub/dir/{query.split()[0] if ' ' in query else query}/{query.split()[-1] if ' ' in query else ''}",
            'Twitter': f"https://twitter.com/search?q={query.replace(' ', '%20')}&src=typed_query&f=user",
            'Instagram': f"https://www.instagram.com/{query.replace(' ', '').lower()}/",
            'TikTok': f"https://www.tiktok.com/@{query.replace(' ', '').lower()}",
            'YouTube': f"https://www.youtube.com/results?search_query={query.replace(' ', '+')}"
        }
        
        found_profiles = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            for platform, url in platforms.items():
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            profile_data = self.extract_profile_data(platform, content, query)
                            if profile_data:
                                found_profiles.append({
                                    'platform': platform,
                                    'url': url,
                                    'data': profile_data
                                })
                except:
                    pass
        
        if found_profiles:
            self.search_results['Social Platforms'] = found_profiles

    def extract_profile_data(self, platform, content, query):
        query_lower = query.lower()
        content_lower = content.lower()
        
        if platform == 'Facebook':
            if 'facebook.com' in content_lower and query_lower in content_lower:
                return {'status': 'Potential match found', 'confidence': 'Medium'}
        
        elif platform == 'LinkedIn':
            if 'linkedin.com' in content_lower and any(word in content_lower for word in query_lower.split()):
                return {'status': 'Professional profile found', 'confidence': 'High'}
        
        elif platform == 'Twitter':
            if 'twitter.com' in content_lower and query_lower in content_lower:
                followers_match = re.search(r'(\d+(?:,\d+)*)\s*followers?', content_lower)
                following_match = re.search(r'(\d+(?:,\d+)*)\s*following', content_lower)
                
                return {
                    'status': 'Twitter account found',
                    'followers': followers_match.group(1) if followers_match else 'Unknown',
                    'following': following_match.group(1) if following_match else 'Unknown',
                    'confidence': 'Medium'
                }
        
        elif platform == 'Instagram':
            if 'instagram.com' in content_lower and query_lower.replace(' ', '') in content_lower:
                return {'status': 'Instagram profile found', 'confidence': 'Medium'}
        
        return None

    async def search_professional_networks(self, query):
        professional_sites = {
            'AngelList': f"https://angel.co/{query.replace(' ', '-').lower()}",
            'Crunchbase': f"https://www.crunchbase.com/person/{query.replace(' ', '-').lower()}",
            'GitHub': f"https://github.com/{query.replace(' ', '').lower()}",
            'Stack Overflow': f"https://stackoverflow.com/users/{query.replace(' ', '')}",
            'ResearchGate': f"https://www.researchgate.net/profile/{query.replace(' ', '-')}",
            'Academia.edu': f"https://{query.split()[0].lower()}.academia.edu/" if ' ' in query else f"https://{query.lower()}.academia.edu/",
            'ORCID': f"https://orcid.org/{query}",
            'Google Scholar': f"https://scholar.google.com/citations?user={query}"
        }
        
        found_professional = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            for site, url in professional_sites.items():
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            if self.validate_professional_profile(site, content, query):
                                found_professional.append({
                                    'site': site,
                                    'url': url,
                                    'status': 'Profile found'
                                })
                except:
                    pass
        
        if found_professional:
            self.search_results['Professional Networks'] = found_professional

    def validate_professional_profile(self, site, content, query):
        content_lower = content.lower()
        query_words = query.lower().split()
        
        if site == 'GitHub':
            return 'repositories' in content_lower and any(word in content_lower for word in query_words)
        elif site == 'LinkedIn':
            return 'experience' in content_lower and any(word in content_lower for word in query_words)
        elif site == 'Stack Overflow':
            return 'reputation' in content_lower and any(word in content_lower for word in query_words)
        else:
            return any(word in content_lower for word in query_words) and len(content) > 5000

    async def search_public_records(self, query):
        if ' ' not in query:
            console.print("[yellow]Public records search requires full name[/yellow]")
            return
        
        first_name, last_name = query.split()[0], query.split()[-1]
        
        public_record_sites = {
            'WhitePages': f"https://www.whitepages.com/name/{first_name}-{last_name}",
            'Spokeo': f"https://www.spokeo.com/{first_name}-{last_name}",
            'TruePeopleSearch': f"https://www.truepeoplesearch.com/results?name={first_name}%20{last_name}",
            'FastPeopleSearch': f"https://www.fastpeoplesearch.com/name/{first_name}-{last_name}"
        }
        
        found_records = []
        
        for site, url in public_record_sites.items():
            found_records.append({
                'site': site,
                'url': url,
                'note': 'Manual verification required'
            })
        
        self.search_results['Public Records'] = found_records

    async def search_engines(self, query):
        search_queries = [
            f'"{query}"',
            f'"{query}" site:linkedin.com',
            f'"{query}" site:facebook.com',
            f'"{query}" site:twitter.com',
            f'"{query}" contact OR email OR phone',
            f'"{query}" resume OR CV',
            f'"{query}" company OR work OR job'
        ]
        
        search_results = []
        
        for search_query in search_queries:
            search_results.append({
                'query': search_query,
                'google_url': f"https://www.google.com/search?q={search_query.replace(' ', '+').replace(':', '%3A')}",
                'bing_url': f"https://www.bing.com/search?q={search_query.replace(' ', '+').replace(':', '%3A')}",
                'duckduckgo_url': f"https://duckduckgo.com/?q={search_query.replace(' ', '+').replace(':', '%3A')}"
            })
        
        self.search_results['Search Engine Queries'] = search_results

    async def people_search_engines(self, query):
        people_search_engines = {
            'Pipl': f"https://pipl.com/search/?q={query.replace(' ', '+')}",
            'ThatsThem': f"https://thatsthem.com/name/{query.replace(' ', '-')}",
            'BeenVerified': f"https://www.beenverified.com/people/{query.replace(' ', '-')}",
            'Intelius': f"https://www.intelius.com/people-search/{query.replace(' ', '-')}",
            'PeopleFinder': f"https://www.peoplefinder.com/people/{query.replace(' ', '-')}",
            'Radaris': f"https://radaris.com/p/{query.split()[0]}/{query.split()[-1]}/" if ' ' in query else f"https://radaris.com/ng/search?ff={query}",
            'MyLife': f"https://www.mylife.com/people/{query.replace(' ', '-')}",
            'PeopleSearch': f"https://www.peoplesearch.com/people/{query.replace(' ', '-')}"
        }
        
        found_engines = []
        
        for engine, url in people_search_engines.items():
            found_engines.append({
                'engine': engine,
                'url': url,
                'note': 'May require subscription or payment'
            })
        
        self.search_results['People Search Engines'] = found_engines

    def build_social_graph(self):
        try:
            main_node = "Target Person"
            self.social_graph.add_node(main_node)
            
            for category, results in self.search_results.items():
                if category in ['Social Platforms', 'Professional Networks']:
                    for result in results:
                        platform = result.get('platform', result.get('site', 'Unknown'))
                        self.social_graph.add_node(platform)
                        self.social_graph.add_edge(main_node, platform)
                        
                        if 'data' in result and result['data']:
                            for key, value in result['data'].items():
                                if key in ['followers', 'following', 'connections']:
                                    node_name = f"{platform}_{key}"
                                    self.social_graph.add_node(node_name)
                                    self.social_graph.add_edge(platform, node_name)
            
        except Exception as e:
            console.print(f"[yellow]Error building social graph: {e}[/yellow]")

    def save_social_graph(self, filename="social_graph.png"):
        try:
            if len(self.social_graph.nodes()) > 1:
                plt.figure(figsize=(12, 8))
                pos = nx.spring_layout(self.social_graph, k=3, iterations=50)
                
                nx.draw(self.social_graph, pos, 
                       with_labels=True, 
                       node_color='lightcoral',
                       node_size=3000,
                       font_size=8,
                       font_weight='bold',
                       arrows=True,
                       edge_color='gray')
                
                plt.title("Social Media & Professional Network Graph", size=16)
                plt.tight_layout()
                plt.savefig(filename, dpi=300, bbox_inches='tight')
                plt.close()
                
                console.print(f"[green]Social graph saved as {filename}[/green]")
        except Exception as e:
            console.print(f"[yellow]Error saving social graph: {e}[/yellow]")

    def display_results(self, query):
        console.print(f"\n[red]═══ PEOPLE SEARCH INTELLIGENCE REPORT ═══[/red]")
        
        total_results = 0
        
        for category, results in self.search_results.items():
            if results:
                table = Table(title=category, border_style="red")
                
                if category == 'Social Platforms':
                    table.add_column("Platform", style="cyan")
                    table.add_column("URL", style="blue")
                    table.add_column("Data", style="white")
                    
                    for result in results:
                        data_str = ""
                        if result.get('data'):
                            data_parts = []
                            for key, value in result['data'].items():
                                data_parts.append(f"{key}: {value}")
                            data_str = " | ".join(data_parts)
                        
                        table.add_row(
                            result['platform'],
                            result['url'][:80] + "..." if len(result['url']) > 80 else result['url'],
                            data_str
                        )
                        total_results += 1
                
                elif category == 'Professional Networks':
                    table.add_column("Site", style="cyan")
                    table.add_column("URL", style="blue")
                    table.add_column("Status", style="green")
                    
                    for result in results:
                        table.add_row(
                            result['site'],
                            result['url'][:80] + "..." if len(result['url']) > 80 else result['url'],
                            result['status']
                        )
                        total_results += 1
                
                elif category == 'Search Engine Queries':
                    table.add_column("Query", style="cyan")
                    table.add_column("Google", style="blue")
                    table.add_column("Bing", style="blue")
                    table.add_column("DuckDuckGo", style="blue")
                    
                    for result in results[:5]:
                        table.add_row(
                            result['query'][:40] + "..." if len(result['query']) > 40 else result['query'],
                            "Search",
                            "Search", 
                            "Search"
                        )
                
                else:
                    table.add_column("Source", style="cyan")
                    table.add_column("URL", style="blue")
                    table.add_column("Note", style="dim white")
                    
                    for result in results[:10]:
                        source = result.get('site', result.get('engine', 'Unknown'))
                        table.add_row(
                            source,
                            result['url'][:80] + "..." if len(result['url']) > 80 else result['url'],
                            result.get('note', '')
                        )
                
                console.print(table)
                console.print()
        
        console.print(f"[green]Search complete - Found {total_results} potential matches across multiple platforms[/green]")
        
        if len(self.social_graph.nodes()) > 1:
            self.save_social_graph()
        
        console.print(f"[yellow]Recommendation: Manually verify results and cross-reference information[/yellow]")
