import requests
import json
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import subprocess
import platform
import re

console = Console()

class WifiGeolocation:
    def __init__(self):
        self.session = None
        self.discovered_networks = []
        self.geolocation_data = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def scan_local_wifi(self):
        console.print("[red]🔍 Scanning Local WiFi Networks[/red]")
        
        system = platform.system().lower()
        
        try:
            if system == "windows":
                return await self._scan_windows_wifi()
            elif system == "linux":
                return await self._scan_linux_wifi()
            elif system == "darwin":
                return await self._scan_macos_wifi()
            else:
                console.print("[yellow]Unsupported operating system for WiFi scanning[/yellow]")
                return []
        except Exception as e:
            console.print(f"[red]WiFi scan failed: {e}[/red]")
            return []

    async def _scan_windows_wifi(self):
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'network', 'mode=bssid'],
                capture_output=True, text=True, timeout=30
            )
            
            networks = []
            current_ssid = None
            current_bssid = None
            current_signal = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('SSID'):
                    if ':' in line:
                        current_ssid = line.split(':', 1)[1].strip()
                
                elif line.startswith('BSSID'):
                    if ':' in line:
                        current_bssid = line.split(':', 1)[1].strip()
                
                elif line.startswith('Signal'):
                    if ':' in line:
                        signal_str = line.split(':', 1)[1].strip()
                        current_signal = signal_str.replace('%', '')
                        
                        if current_ssid and current_bssid:
                            networks.append({
                                'ssid': current_ssid,
                                'bssid': current_bssid,
                                'signal': current_signal,
                                'channel': 'Unknown'
                            })
                            
                            current_ssid = None
                            current_bssid = None
                            current_signal = None
            
            return networks
            
        except Exception as e:
            console.print(f"[red]Windows WiFi scan failed: {e}[/red]")
            return []

    async def _scan_linux_wifi(self):
        try:
            result = subprocess.run(
                ['iwlist', 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            networks = []
            current_network = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {'bssid': line.split('Address: ')[1]}
                
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['ssid'] = essid
                
                elif 'Signal level=' in line:
                    signal = re.search(r'Signal level=(-?\d+)', line)
                    if signal:
                        current_network['signal'] = signal.group(1)
                
                elif 'Channel:' in line:
                    channel = re.search(r'Channel:(\d+)', line)
                    if channel:
                        current_network['channel'] = channel.group(1)
            
            if current_network:
                networks.append(current_network)
                
            return networks
            
        except Exception as e:
            try:
                result = subprocess.run(
                    ['nmcli', 'dev', 'wifi', 'list'],
                    capture_output=True, text=True, timeout=30
                )
                
                networks = []
                lines = result.stdout.split('\n')[1:]
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 6:
                            networks.append({
                                'ssid': parts[1] if parts[1] != '--' else 'Hidden',
                                'bssid': parts[0],
                                'signal': parts[5],
                                'channel': parts[2]
                            })
                
                return networks
                
            except Exception as e2:
                console.print(f"[red]Linux WiFi scan failed: {e2}[/red]")
                return []

    async def _scan_macos_wifi(self):
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True, text=True, timeout=30
            )
            
            networks = []
            lines = result.stdout.split('\n')[1:]
            
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        networks.append({
                            'ssid': parts[0],
                            'bssid': parts[1],
                            'signal': parts[2],
                            'channel': parts[3]
                        })
            
            return networks
            
        except Exception as e:
            console.print(f"[red]macOS WiFi scan failed: {e}[/red]")
            return []

    async def geolocate_bssid(self, bssid):
        console.print(f"[red]🌍 Geolocating BSSID: {bssid}[/red]")
        
        methods = [
            self._mozilla_location_service,
            self._google_geolocation,
            self._wigle_lookup,
            self._mylnikov_geo
        ]
        
        for method in methods:
            try:
                result = await method(bssid)
                if result:
                    return result
            except Exception as e:
                continue
        
        return None

    async def _mozilla_location_service(self, bssid):
        try:
            url = "https://location.services.mozilla.com/v1/geolocate"
            
            data = {
                "wifiAccessPoints": [
                    {
                        "macAddress": bssid,
                    }
                ]
            }
            
            async with self.session.post(url, json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    if 'location' in result:
                        return {
                            'service': 'Mozilla Location Service',
                            'latitude': result['location']['lat'],
                            'longitude': result['location']['lng'],
                            'accuracy': result.get('accuracy', 'Unknown')
                        }
            
            return None
            
        except Exception:
            return None

    async def _google_geolocation(self, bssid):
        try:
            import os
            api_key = os.getenv('GOOGLE_MAPS_API_KEY', 'your-google-maps-api-key-here')
            url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}"
            
            data = {
                "wifiAccessPoints": [
                    {
                        "macAddress": bssid
                    }
                ]
            }
            
            async with self.session.post(url, json=data) as response:
                if response.status == 200:
                    result = await response.json()
                    if 'location' in result:
                        return {
                            'service': 'Google Geolocation',
                            'latitude': result['location']['lat'],
                            'longitude': result['location']['lng'],
                            'accuracy': result.get('accuracy', 'Unknown')
                        }
            
            return None
            
        except Exception:
            return None

    async def _wigle_lookup(self, bssid):
        try:
            url = f"https://api.wigle.net/api/v2/network/search"
            
            headers = {
                'Authorization': 'Basic dGVzdDp0ZXN0',
                'User-Agent': 'WiFiGeolocation/1.0'
            }
            
            params = {
                'netid': bssid,
                'format': 'json'
            }
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get('results') and len(result['results']) > 0:
                        network = result['results'][0]
                        return {
                            'service': 'WiGLE',
                            'latitude': network.get('trilat'),
                            'longitude': network.get('trilong'),
                            'accuracy': 'High',
                            'first_seen': network.get('firsttime'),
                            'last_seen': network.get('lasttime'),
                            'country': network.get('country')
                        }
            
            return None
            
        except Exception:
            return None

    async def _mylnikov_geo(self, bssid):
        try:
            url = f"https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open&bssid={bssid}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get('result') == 200:
                        data = result.get('data', {})
                        return {
                            'service': 'Mylnikov Geo',
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'accuracy': 'Medium',
                            'range': data.get('range')
                        }
            
            return None
            
        except Exception:
            return None

    async def batch_geolocate(self, bssid_list):
        console.print(f"[red]🌍 Batch Geolocating {len(bssid_list)} BSSIDs[/red]")
        
        tasks = []
        for bssid in bssid_list:
            task = self.geolocate_bssid(bssid)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        geolocated = []
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                geolocated.append({
                    'bssid': bssid_list[i],
                    'location': result
                })
        
        return geolocated

    def calculate_location_accuracy(self, locations):
        if len(locations) < 2:
            return None
        
        latitudes = [loc['location']['latitude'] for loc in locations if loc['location']['latitude']]
        longitudes = [loc['location']['longitude'] for loc in locations if loc['location']['longitude']]
        
        if not latitudes or not longitudes:
            return None
        
        avg_lat = sum(latitudes) / len(latitudes)
        avg_lng = sum(longitudes) / len(longitudes)
        
        distances = []
        for lat, lng in zip(latitudes, longitudes):
            distance = self._haversine_distance(avg_lat, avg_lng, lat, lng)
            distances.append(distance)
        
        max_distance = max(distances) if distances else 0
        
        return {
            'center_latitude': avg_lat,
            'center_longitude': avg_lng,
            'accuracy_radius': max_distance,
            'confidence': 'High' if max_distance < 100 else 'Medium' if max_distance < 500 else 'Low'
        }

    def _haversine_distance(self, lat1, lon1, lat2, lon2):
        import math
        
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        r = 6371
        
        return c * r * 1000

    def display_results(self, networks, geolocations, accuracy_info=None):
        console.print(f"\n[red]═══ WIFI GEOLOCATION REPORT ═══[/red]")
        
        if networks:
            table = Table(title="🔍 Discovered WiFi Networks", border_style="cyan")
            table.add_column("SSID", style="white")
            table.add_column("BSSID", style="yellow")
            table.add_column("Signal", style="green")
            table.add_column("Channel", style="blue")
            
            for network in networks:
                table.add_row(
                    network.get('ssid', 'Unknown'),
                    network.get('bssid', 'Unknown'),
                    f"{network.get('signal', 'Unknown')}%",
                    str(network.get('channel', 'Unknown'))
                )
            
            console.print(table)
        
        if geolocations:
            table = Table(title="🌍 Geolocation Results", border_style="red")
            table.add_column("BSSID", style="cyan")
            table.add_column("Service", style="yellow")
            table.add_column("Latitude", style="green")
            table.add_column("Longitude", style="green")
            table.add_column("Accuracy", style="white")
            
            for geo in geolocations:
                loc = geo['location']
                table.add_row(
                    geo['bssid'],
                    loc.get('service', 'Unknown'),
                    str(loc.get('latitude', 'N/A')),
                    str(loc.get('longitude', 'N/A')),
                    str(loc.get('accuracy', 'Unknown'))
                )
            
            console.print(table)
        
        if accuracy_info:
            panel_text = f"""
[green]📍 Estimated Location Center:[/green]
Latitude: {accuracy_info['center_latitude']:.6f}
Longitude: {accuracy_info['center_longitude']:.6f}

[yellow]🎯 Accuracy Assessment:[/yellow]
Radius: {accuracy_info['accuracy_radius']:.0f} meters
Confidence: {accuracy_info['confidence']}
            """
            
            console.print(Panel(panel_text, title="Location Accuracy", border_style="green"))
        
        console.print(f"\n[green]Networks Found: {len(networks)}[/green]")
        console.print(f"[green]Geolocated: {len(geolocations)}[/green]")
        
        if geolocations:
            console.print(f"\n[dim white]💡 Tip: Use Google Maps with coordinates for visualization[/dim white]")
            console.print(f"[dim white]⚠️  Location accuracy varies by WiFi database coverage[/dim white]")
