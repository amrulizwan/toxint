import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import difflib

console = Console()

class ForumCrawler:
    def __init__(self):
        self.posts = []
        self.user_data = {}
        self.patterns = []

    async def crawl(self, target):
        if target.startswith(('http://', 'https://')):
            await self.crawl_forum_url(target)
        else:
            await self.search_username_in_forums(target)
        
        self.analyze_patterns()
        self.display_results()
        
        # Return structured results for Smart Auto-Profiler
        results = {
            'target': target,
            'found_profiles': self.user_data,
            'posts': self.posts,
            'patterns': self.patterns,
            'total_profiles': len(self.user_data),
            'total_posts': len(self.posts),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return results

    async def crawl_forum_url(self, url):
        console.print(f"[red]Crawling forum: {url}[/red]")
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            await self.extract_forum_data(session, url)

    async def search_username_in_forums(self, username):
        console.print(f"[red]Searching username across forums: {username}[/red]")
        
        forums = [
            'https://reddit.com/user/{}',
            'https://stackoverflow.com/users/{}',
            'https://github.com/{}/discussions',
            'https://discourse.org/u/{}',
            'https://community.cloudflare.com/u/{}',
            'https://forum.ubuntu.com/memberlist.php?mode=viewprofile&u={}',
            'https://linustechtips.com/profile/{}-*/',
            'https://forums.malwarebytes.com/profile/{}-*/',
            'https://www.reddit.com/r/all/search/?q=author%3A{}&sort=new',
        ]
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            with Progress() as progress:
                task = progress.add_task("[red]Searching forums...", total=len(forums))
                
                for forum_url in forums:
                    try:
                        url = forum_url.format(username)
                        await self.check_forum_presence(session, url, username)
                        progress.update(task, advance=1)
                    except:
                        progress.update(task, advance=1)

    async def check_forum_presence(self, session, url, username):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    if self.validate_forum_profile(content, username):
                        domain = urlparse(url).netloc
                        
                        profile_data = await self.extract_profile_info(content, url)
                        
                        self.user_data[domain] = {
                            'url': url,
                            'status': 'Found',
                            'profile_data': profile_data
                        }
                        
                        await self.extract_user_posts(session, url, username)
        except:
            pass

    def validate_forum_profile(self, content, username):
        content_lower = content.lower()
        username_lower = username.lower()
        
        negative_indicators = [
            'user not found', 'profile not found', '404', 'page not found',
            'account suspended', 'user banned', 'does not exist'
        ]
        
        for indicator in negative_indicators:
            if indicator in content_lower:
                return False
        
        positive_indicators = [
            username_lower, f'@{username_lower}', f'user/{username_lower}',
            'posts', 'joined', 'member since', 'reputation', 'karma'
        ]
        
        return any(indicator in content_lower for indicator in positive_indicators)

    async def extract_profile_info(self, content, url):
        soup = BeautifulSoup(content, 'html.parser')
        profile_data = {}
        
        join_date_patterns = [
            r'joined:?\s*([a-zA-Z]+\s+\d{1,2},?\s+\d{4})',
            r'member since:?\s*([a-zA-Z]+\s+\d{1,2},?\s+\d{4})',
            r'registered:?\s*([a-zA-Z]+\s+\d{1,2},?\s+\d{4})'
        ]
        
        for pattern in join_date_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                profile_data['Join Date'] = match.group(1)
                break
        
        post_count_patterns = [
            r'(\d+)\s*posts?',
            r'posts?:?\s*(\d+)',
            r'messages?:?\s*(\d+)'
        ]
        
        for pattern in post_count_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                profile_data['Post Count'] = match.group(1)
                break
        
        reputation_patterns = [
            r'reputation:?\s*(\d+)',
            r'karma:?\s*(\d+)',
            r'points?:?\s*(\d+)'
        ]
        
        for pattern in reputation_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                profile_data['Reputation'] = match.group(1)
                break
        
        bio_elements = soup.find_all(['div', 'p'], class_=re.compile(r'bio|about|description', re.I))
        for element in bio_elements:
            text = element.get_text().strip()
            if text and len(text) > 20 and len(text) < 500:
                profile_data['Bio'] = text
                break
        
        return profile_data

    async def extract_user_posts(self, session, profile_url, username):
        domain = urlparse(profile_url).netloc
        
        post_urls = []
        
        if 'reddit.com' in domain:
            post_urls.append(f"https://www.reddit.com/user/{username}/submitted.json?limit=25")
        elif 'stackoverflow.com' in domain:
            user_id = re.search(r'/users/(\d+)/', profile_url)
            if user_id:
                post_urls.append(f"https://api.stackexchange.com/2.3/users/{user_id.group(1)}/posts?site=stackoverflow")
        
        for url in post_urls:
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        await self.parse_post_data(data, domain, username)
            except:
                pass

    async def parse_post_data(self, data, domain, username):
        if 'reddit.com' in domain and 'data' in data:
            for post in data['data']['children']:
                post_data = post['data']
                self.posts.append({
                    'platform': 'Reddit',
                    'username': username,
                    'title': post_data.get('title', ''),
                    'content': post_data.get('selftext', ''),
                    'timestamp': post_data.get('created_utc', 0),
                    'subreddit': post_data.get('subreddit', ''),
                    'score': post_data.get('score', 0),
                    'url': f"https://reddit.com{post_data.get('permalink', '')}"
                })
        
        elif 'stackoverflow.com' in domain and 'items' in data:
            for item in data['items']:
                self.posts.append({
                    'platform': 'Stack Overflow',
                    'username': username,
                    'title': item.get('title', ''),
                    'content': '',
                    'timestamp': item.get('creation_date', 0),
                    'tags': item.get('tags', []),
                    'score': item.get('score', 0),
                    'url': f"https://stackoverflow.com/questions/{item.get('question_id', '')}"
                })

    async def extract_forum_data(self, session, url):
        try:
            async with session.get(url) as response:
                if response.status != 200:
                    console.print(f"[red]Error accessing forum: {response.status}[/red]")
                    return
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                await self.extract_forum_structure(soup, url)
                await self.extract_recent_posts(session, soup, url)
                
        except Exception as e:
            console.print(f"[red]Error crawling forum: {e}[/red]")

    async def extract_forum_structure(self, soup, base_url):
        forum_data = {}
        
        title = soup.find('title')
        if title:
            forum_data['Title'] = title.get_text().strip()
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            forum_data['Description'] = meta_desc.get('content', '')
        
        categories = soup.find_all(['div', 'section'], class_=re.compile(r'category|forum|board', re.I))
        if categories:
            forum_data['Categories'] = len(categories)
        
        self.user_data['Forum Info'] = forum_data

    async def extract_recent_posts(self, session, soup, base_url):
        post_links = soup.find_all('a', href=re.compile(r'/(post|topic|thread|discussion)/'))
        
        for i, link in enumerate(post_links[:10]):
            if i >= 5:
                break
                
            href = link.get('href')
            if href:
                post_url = urljoin(base_url, href)
                await self.extract_single_post(session, post_url)

    async def extract_single_post(self, session, url):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    title = soup.find(['h1', 'h2'], class_=re.compile(r'title|subject|topic', re.I))
                    title_text = title.get_text().strip() if title else 'Unknown'
                    
                    posts = soup.find_all(['div', 'article'], class_=re.compile(r'post|message|comment', re.I))
                    
                    for post in posts[:3]:
                        author = post.find(['span', 'a'], class_=re.compile(r'author|user|username', re.I))
                        author_text = author.get_text().strip() if author else 'Anonymous'
                        
                        content_elem = post.find(['div', 'p'], class_=re.compile(r'content|body|text', re.I))
                        content_text = content_elem.get_text().strip() if content_elem else ''
                        
                        if content_text and len(content_text) > 20:
                            self.posts.append({
                                'platform': 'Forum',
                                'username': author_text,
                                'title': title_text,
                                'content': content_text[:500],
                                'url': url,
                                'timestamp': 0
                            })
        except:
            pass

    def analyze_patterns(self):
        if not self.posts:
            return
        
        console.print("[cyan]Analyzing posting patterns...[/cyan]")
        
        usernames = [post['username'] for post in self.posts]
        unique_users = list(set(usernames))
        
        writing_styles = {}
        for post in self.posts:
            username = post['username']
            content = post.get('content', '')
            
            if username not in writing_styles:
                writing_styles[username] = []
            
            if content:
                writing_styles[username].append(content)
        
        similar_users = []
        for i, user1 in enumerate(unique_users):
            for user2 in unique_users[i+1:]:
                if user1 in writing_styles and user2 in writing_styles:
                    similarity = self.calculate_writing_similarity(
                        writing_styles[user1],
                        writing_styles[user2]
                    )
                    
                    if similarity > 0.7:
                        similar_users.append({
                            'user1': user1,
                            'user2': user2,
                            'similarity': similarity
                        })
        
        if similar_users:
            self.patterns = similar_users

    def calculate_writing_similarity(self, texts1, texts2):
        if not texts1 or not texts2:
            return 0
        
        sample1 = ' '.join(texts1[:5])
        sample2 = ' '.join(texts2[:5])
        
        if not sample1 or not sample2:
            return 0
        
        similarity = difflib.SequenceMatcher(None, sample1.lower(), sample2.lower()).ratio()
        return similarity

    def display_results(self):
        console.print(f"\n[red]═══ FORUM INTELLIGENCE REPORT ═══[/red]")
        
        if self.user_data:
            for platform, data in self.user_data.items():
                table = Table(title=f"Platform: {platform}", border_style="red")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                table.add_row(f"{key} - {sub_key}", str(sub_value))
                        else:
                            table.add_row(str(key), str(value))
                
                console.print(table)
                console.print()
        
        if self.posts:
            table = Table(title="Recent Posts/Content", border_style="blue")
            table.add_column("Platform", style="cyan")
            table.add_column("Username", style="yellow")
            table.add_column("Title/Topic", style="white")
            table.add_column("Content Preview", style="dim white")
            
            for post in self.posts[:10]:
                content_preview = post.get('content', '')[:100] + "..." if len(post.get('content', '')) > 100 else post.get('content', '')
                
                table.add_row(
                    post.get('platform', 'Unknown'),
                    post.get('username', 'Unknown'),
                    post.get('title', 'No title')[:50],
                    content_preview
                )
            
            console.print(table)
        
        if self.patterns:
            table = Table(title="🔍 Potential Identity Correlations", border_style="yellow")
            table.add_column("User 1", style="cyan")
            table.add_column("User 2", style="cyan")
            table.add_column("Similarity", style="white")
            table.add_column("Analysis", style="dim white")
            
            for pattern in self.patterns:
                similarity_pct = f"{pattern['similarity']:.1%}"
                analysis = "High writing style similarity - possible same person"
                
                table.add_row(
                    pattern['user1'],
                    pattern['user2'], 
                    similarity_pct,
                    analysis
                )
            
            console.print(table)
        
        console.print(f"[green]Forum analysis complete - Found {len(self.posts)} posts across {len(self.user_data)} platforms[/green]")
