import asyncio
import aiohttp
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import json
import re
from urllib.parse import quote

console = Console()

class UsernameEnumerator:
    def __init__(self):
        self.platforms = {
            'GitHub': 'https://github.com/{}',
            'Twitter': 'https://twitter.com/{}',
            'Instagram': 'https://instagram.com/{}',
            'Reddit': 'https://reddit.com/user/{}',
            'LinkedIn': 'https://linkedin.com/in/{}',
            'Facebook': 'https://facebook.com/{}',
            'TikTok': 'https://tiktok.com/@{}',
            'YouTube': 'https://youtube.com/@{}',
            'Twitch': 'https://twitch.tv/{}',
            'Pinterest': 'https://pinterest.com/{}',
            'Snapchat': 'https://snapchat.com/add/{}',
            'Discord': 'https://discord.com/users/{}',
            'Telegram': 'https://t.me/{}',
            'Steam': 'https://steamcommunity.com/id/{}',
            'DeviantArt': 'https://{}.deviantart.com',
            'Behance': 'https://behance.net/{}',
            'Dribbble': 'https://dribbble.com/{}',
            'Medium': 'https://medium.com/@{}',
            'Spotify': 'https://open.spotify.com/user/{}',
            'SoundCloud': 'https://soundcloud.com/{}',
            'Flickr': 'https://flickr.com/people/{}',
            'Tumblr': 'https://{}.tumblr.com',
            'Vimeo': 'https://vimeo.com/{}',
            'GitLab': 'https://gitlab.com/{}',
            'BitBucket': 'https://bitbucket.org/{}',
            'Stack Overflow': 'https://stackoverflow.com/users/{}',
            'Patreon': 'https://patreon.com/{}',
            'OnlyFans': 'https://onlyfans.com/{}',
            'Clubhouse': 'https://clubhouse.com/@{}',
            'Parler': 'https://parler.com/profile/{}',
            'VKontakte': 'https://vk.com/{}',
            'Weibo': 'https://weibo.com/{}',
            'WhatsApp': 'https://wa.me/{}',
            'Signal': 'https://signal.me/#p/{}',
            'Kik': 'https://kik.me/{}',
            'WeChat': 'https://u.wechat.com/{}',
            'Line': 'https://line.me/ti/p/{}',
            'Viber': 'https://viber.com/{}',
            'Skype': 'https://join.skype.com/invite/{}',
            'Zoom': 'https://zoom.us/profile/{}',
            'Slack': 'https://{}.slack.com',
            'Microsoft Teams': 'https://teams.microsoft.com/l/chat/0/0?users={}',
            'Apple ID': 'https://appleid.apple.com/{}',
            'Google': 'https://plus.google.com/+{}',
            'Amazon': 'https://amazon.com/gp/profile/amzn1.account.{}',
            'eBay': 'https://ebay.com/usr/{}',
            'Etsy': 'https://etsy.com/people/{}',
            'Airbnb': 'https://airbnb.com/users/show/{}',
            'Uber': 'https://riders.uber.com/profile/{}',
            'Lyft': 'https://lyft.com/profile/{}',
            'Netflix': 'https://netflix.com/browse/{}',
            'Hulu': 'https://hulu.com/profiles/{}',
            'Disney+': 'https://disneyplus.com/profile/{}',
            'HBO Max': 'https://hbomax.com/profile/{}',
            'Twitch Prime': 'https://twitch.tv/prime/{}',
            'Riot Games': 'https://riot.com/{}',
            'Epic Games': 'https://epicgames.com/{}',
            'Origin': 'https://origin.com/{}',
            'Uplay': 'https://uplay.com/{}',
            'PlayStation': 'https://my.playstation.com/profile/{}',
            'Xbox Live': 'https://live.xbox.com/Profile?gamertag={}',
            'Nintendo': 'https://nintendo.com/{}',
            'Roblox': 'https://roblox.com/users/{}/profile',
            'Minecraft': 'https://namemc.com/profile/{}',
            'Fortnite': 'https://fortnitetracker.com/profile/all/{}',
            'PUBG': 'https://pubg.op.gg/user/{}',
            'Apex Legends': 'https://apex.tracker.gg/profile/pc/{}',
            'Call of Duty': 'https://cod.tracker.gg/modern-warfare/profile/battlenet/{}/overview',
            'Valorant': 'https://tracker.gg/valorant/profile/riot/{}/overview',
            'League of Legends': 'https://na.op.gg/summoner/userName={}',
            'Dota 2': 'https://dotabuff.com/players/{}',
            'Counter-Strike': 'https://steamcommunity.com/id/{}',
            'Overwatch': 'https://playoverwatch.com/career/pc/{}',
            'World of Warcraft': 'https://worldofwarcraft.com/character/us/stormrage/{}',
            'Final Fantasy XIV': 'https://na.finalfantasyxiv.com/lodestone/character/{}/',
            'Elder Scrolls Online': 'https://elderscrollsonline.com/{}',
            'Guild Wars 2': 'https://gw2efficiency.com/account/overview/{}',
            'Path of Exile': 'https://pathofexile.com/account/view-profile/{}',
            'Diablo': 'https://us.diablo3.com/profile/{}-1234/',
            'StarCraft II': 'https://starcraft2.com/profile/1/1/{}',
            'Hearthstone': 'https://hearthstone.com/{}',
            'Magic: The Gathering Arena': 'https://mtgarena.com/{}',
            'Pokémon GO': 'https://pokemongo.com/{}',
            'Clash of Clans': 'https://clashofclans.com/{}',
            'Clash Royale': 'https://clashroyale.com/{}',
            'Brawl Stars': 'https://brawlstars.com/{}',
            'Candy Crush': 'https://candycrush.com/{}',
            'Angry Birds': 'https://angrybirds.com/{}',
            'Farmville': 'https://farmville.com/{}',
            'Words with Friends': 'https://wordswithfriends.com/{}',
            'Scrabble GO': 'https://scrabblego.com/{}',
            'Chess.com': 'https://chess.com/member/{}',
            'Lichess': 'https://lichess.org/@/{}',
            'Poker Stars': 'https://pokerstars.com/{}',
            'Full Tilt Poker': 'https://fulltiltpoker.com/{}',
            '888poker': 'https://888poker.com/{}',
            'PartyPoker': 'https://partypoker.com/{}',
            'PokerGO': 'https://pokergo.com/{}',
            'World Series of Poker': 'https://wsop.com/{}',
            'European Poker Tour': 'https://pokerstars.com/ept/{}',
            'World Poker Tour': 'https://worldpokertour.com/{}',
            'PokerStars Championship': 'https://pokerstars.com/championship/{}',
            'Unibet Poker': 'https://unibet.com/poker/{}',
            'Bet365 Poker': 'https://poker.bet365.com/{}',
            'William Hill Poker': 'https://poker.williamhill.com/{}',
            'Ladbrokes Poker': 'https://poker.ladbrokes.com/{}',
            'Coral Poker': 'https://poker.coral.co.uk/{}',
            'Sky Poker': 'https://skypoker.com/{}',
            'Grosvenor Poker': 'https://grosvenorpoker.com/{}',
            'PokerStars Sports': 'https://pokerstars.com/sports/{}',
            'Bet365 Sports': 'https://sports.bet365.com/{}',
            'William Hill Sports': 'https://sports.williamhill.com/{}',
            'Ladbrokes Sports': 'https://sports.ladbrokes.com/{}',
            'Coral Sports': 'https://sports.coral.co.uk/{}',
            'Sky Sports': 'https://skysports.com/{}',
            'BBC Sport': 'https://bbc.co.uk/sport/{}',
            'ESPN': 'https://espn.com/{}',
            'Fox Sports': 'https://foxsports.com/{}',
            'NBC Sports': 'https://nbcsports.com/{}',
            'CBS Sports': 'https://cbssports.com/{}',
            'Sports Illustrated': 'https://si.com/{}',
            'The Athletic': 'https://theathletic.com/{}',
            'Bleacher Report': 'https://bleacherreport.com/{}',
            'Yahoo Sports': 'https://sports.yahoo.com/{}',
            'Google Sports': 'https://google.com/sports/{}',
            'Microsoft Sports': 'https://msn.com/sports/{}',
            'Apple Sports': 'https://apple.com/sports/{}',
            'Amazon Sports': 'https://amazon.com/sports/{}',
            'Netflix Sports': 'https://netflix.com/sports/{}',
            'Hulu Sports': 'https://hulu.com/sports/{}',
            'Disney+ Sports': 'https://disneyplus.com/sports/{}',
            'HBO Max Sports': 'https://hbomax.com/sports/{}',
            'Paramount+ Sports': 'https://paramountplus.com/sports/{}',
            'Peacock Sports': 'https://peacocktv.com/sports/{}',
            'Discovery+ Sports': 'https://discoveryplus.com/sports/{}',
            'Crunchyroll': 'https://crunchyroll.com/user/{}',
            'Funimation': 'https://funimation.com/{}',
            'VRV': 'https://vrv.co/{}',
            'Anime Planet': 'https://anime-planet.com/users/{}',
            'MyAnimeList': 'https://myanimelist.net/profile/{}',
            'Anilist': 'https://anilist.co/user/{}',
            'Kitsu': 'https://kitsu.io/users/{}',
            'MangaDex': 'https://mangadex.org/user/{}',
            'Viz Media': 'https://viz.com/{}',
            'Shonen Jump': 'https://shonenjump.viz.com/{}',
            'Comic Vine': 'https://comicvine.gamespot.com/profile/{}/',
            'DC Comics': 'https://dccomics.com/{}',
            'Marvel Comics': 'https://marvel.com/{}',
            'Image Comics': 'https://imagecomics.com/{}',
            'Dark Horse Comics': 'https://darkhorse.com/{}',
            'IDW Publishing': 'https://idwpublishing.com/{}',
            'Valiant Comics': 'https://valiantentertainment.com/{}',
            'Dynamite Entertainment': 'https://dynamite.com/{}',
            'BOOM! Studios': 'https://boom-studios.com/{}',
            'Oni Press': 'https://onipress.com/{}',
            'First Second Books': 'https://firstsecondbooks.com/{}',
            'Top Shelf Productions': 'https://topshelfcomix.com/{}',
            'Fantagraphics': 'https://fantagraphics.com/{}',
            'Drawn & Quarterly': 'https://drawnandquarterly.com/{}',
            'Koyama Press': 'https://koyamapress.com/{}',
            'Nobrow Press': 'https://nobrow.net/{}',
            'SelfMadeHero': 'https://selfmadehero.com/{}',
            'Magnetic Press': 'https://magneticpress.com/{}',
            'Archaia': 'https://archaia.com/{}',
            'Avatar Press': 'https://avatarpress.com/{}',
            'CrossGen': 'https://crossgen.com/{}',
            'Vertigo': 'https://vertigo.com/{}',
            'WildStorm': 'https://wildstorm.com/{}',
            'Milestone Media': 'https://milestonemedia.com/{}',
            'Charlton Comics': 'https://charltoncomics.com/{}',
            'Fawcett Publications': 'https://fawcettpublications.com/{}',
            'Quality Comics': 'https://qualitycomics.com/{}',
            'EC Comics': 'https://eccomics.com/{}',
            'Atlas Comics': 'https://atlascomics.com/{}',
            'Timely Publications': 'https://timelypublications.com/{}',
            'All-American Publications': 'https://allamericanpublications.com/{}',
            'National Comics Publications': 'https://nationalcomicspublications.com/{}',
            'Detective Comics': 'https://detectivecomics.com/{}',
        }
        self.found_accounts = []
        self.not_found = []

    async def search(self, username):
        console.print(f"\n[red]Hunting username: {username}[/red]")
        
        results = {
            'username': username,
            'found_accounts': [],
            'not_found': [],
            'timestamp': __import__('time').strftime('%Y-%m-%d %H:%M:%S'),
            'total_platforms': len(self.platforms)
        }
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as session:
            
            with Progress() as progress:
                task = progress.add_task("[red]Scanning platforms...", total=len(self.platforms))
                
                semaphore = asyncio.Semaphore(20)
                tasks = []
                
                for platform, url_template in self.platforms.items():
                    tasks.append(self.check_platform(session, semaphore, platform, url_template, username, progress, task))
                
                await asyncio.gather(*tasks, return_exceptions=True)
        
        results['found_accounts'] = self.found_accounts
        results['not_found'] = self.not_found
        
        self.display_results(username)
        
        return results

    async def check_platform(self, session, semaphore, platform, url_template, username, progress, task):
        async with semaphore:
            try:
                url = url_template.format(username)
                
                async with session.get(url, allow_redirects=True) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if self.validate_profile(platform, content, username):
                            profile_data = await self.extract_profile_data(session, platform, url, content)
                            self.found_accounts.append({
                                'platform': platform,
                                'url': url,
                                'status': 'Found',
                                'data': profile_data
                            })
                        else:
                            self.not_found.append({'platform': platform, 'url': url, 'status': 'Not Found'})
                    else:
                        self.not_found.append({'platform': platform, 'url': url, 'status': f'HTTP {response.status}'})
                        
            except Exception as e:
                self.not_found.append({'platform': platform, 'url': url_template.format(username), 'status': f'Error: {str(e)[:50]}'})
            
            progress.update(task, advance=1)

    def validate_profile(self, platform, content, username):
        content_lower = content.lower()
        username_lower = username.lower()
        
        negative_indicators = [
            'page not found', '404', 'user not found', 'profile not found',
            'account suspended', 'account deleted', 'user does not exist',
            'sorry, that page doesn\'t exist', 'this account doesn\'t exist',
            'the page you requested cannot be found'
        ]
        
        for indicator in negative_indicators:
            if indicator in content_lower:
                return False
        
        positive_indicators = [
            username_lower, f'@{username_lower}', f'user/{username_lower}',
            f'profile/{username_lower}', f'{username_lower}\'s profile'
        ]
        
        for indicator in positive_indicators:
            if indicator in content_lower:
                return True
        
        if platform.lower() in ['github', 'gitlab', 'bitbucket']:
            return 'repositories' in content_lower or 'commits' in content_lower
        elif platform.lower() in ['twitter', 'instagram', 'tiktok']:
            return 'followers' in content_lower or 'following' in content_lower
        elif platform.lower() == 'linkedin':
            return 'experience' in content_lower or 'connections' in content_lower
        elif platform.lower() == 'reddit':
            return 'karma' in content_lower or 'post karma' in content_lower
        
        return len(content) > 5000

    async def extract_profile_data(self, session, platform, url, content):
        data = {}
        
        try:
            if platform.lower() == 'github':
                data.update(self.extract_github_data(content))
            elif platform.lower() == 'twitter':
                data.update(self.extract_twitter_data(content))
            elif platform.lower() == 'instagram':
                data.update(self.extract_instagram_data(content))
            elif platform.lower() == 'linkedin':
                data.update(self.extract_linkedin_data(content))
            
            bio_patterns = [
                r'<meta name="description" content="([^"]*)"',
                r'<meta property="og:description" content="([^"]*)"',
                r'"description":"([^"]*)"',
                r'<p class="bio">([^<]*)</p>',
                r'<div class="biography">([^<]*)</div>'
            ]
            
            for pattern in bio_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match and not data.get('bio'):
                    data['bio'] = match.group(1)[:200]
                    break
            
        except:
            pass
        
        return data

    def extract_github_data(self, content):
        data = {}
        
        repo_match = re.search(r'(\d+)\s*repositories?', content, re.IGNORECASE)
        if repo_match:
            data['repositories'] = repo_match.group(1)
        
        followers_match = re.search(r'(\d+)\s*followers?', content, re.IGNORECASE)
        if followers_match:
            data['followers'] = followers_match.group(1)
        
        return data

    def extract_twitter_data(self, content):
        data = {}
        
        followers_match = re.search(r'(\d+(?:,\d+)*)\s*Followers', content)
        if followers_match:
            data['followers'] = followers_match.group(1)
        
        following_match = re.search(r'(\d+(?:,\d+)*)\s*Following', content)
        if following_match:
            data['following'] = following_match.group(1)
        
        return data

    def extract_instagram_data(self, content):
        data = {}
        
        stats_pattern = r'"edge_followed_by":{"count":(\d+)}'
        match = re.search(stats_pattern, content)
        if match:
            data['followers'] = match.group(1)
        
        return data

    def extract_linkedin_data(self, content):
        data = {}
        
        connections_match = re.search(r'(\d+)\s*connections?', content, re.IGNORECASE)
        if connections_match:
            data['connections'] = connections_match.group(1)
        
        return data

    def display_results(self, username):
        console.print(f"\n[red]═══ USERNAME INTELLIGENCE REPORT ═══[/red]")
        
        if self.found_accounts:
            table = Table(title="✅ FOUND ACCOUNTS", border_style="green")
            table.add_column("Platform", style="cyan bold")
            table.add_column("URL", style="blue")
            table.add_column("Additional Data", style="white")
            
            for account in self.found_accounts:
                data_str = ""
                if account['data']:
                    data_parts = []
                    for key, value in account['data'].items():
                        data_parts.append(f"{key}: {value}")
                    data_str = " | ".join(data_parts)
                
                table.add_row(
                    account['platform'],
                    account['url'],
                    data_str[:100] + "..." if len(data_str) > 100 else data_str
                )
            
            console.print(table)
        
        console.print(f"\n[green]Found: {len(self.found_accounts)} accounts[/green]")
        console.print(f"[red]Not found: {len(self.not_found)} platforms[/red]")
        
        if len(self.found_accounts) > 0:
            console.print(f"\n[yellow]Recommendation: Investigate found accounts for additional intelligence[/yellow]")
