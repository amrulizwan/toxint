import os
import re
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import requests
from rich.console import Console
from rich.table import Table

console = Console()

class GeoAnalyzer:
    def __init__(self):
        self.location_data = {}

    def analyze(self, source):
        console.print(f"[red]Analyzing geolocation data: {source}[/red]")
        
        if os.path.isfile(source):
            self.analyze_image(source)
        elif self.is_coordinates(source):
            self.analyze_coordinates(source)
        else:
            console.print("[red]Invalid source. Provide image path or coordinates (lat,lon)[/red]")
            return
        
        self.display_results()

    def is_coordinates(self, source):
        coord_pattern = r'^-?\d+\.?\d*,-?\d+\.?\d*$'
        return re.match(coord_pattern, source.replace(' ', ''))

    def analyze_image(self, filepath):
        console.print("[cyan]Extracting GPS data from image...[/cyan]")
        
        try:
            with Image.open(filepath) as image:
                exif_data = image._getexif()
                
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        
                        if tag == 'GPSInfo':
                            gps_data = {}
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                gps_data[gps_tag] = gps_value
                            
                            if gps_data:
                                coords = self.parse_gps_coordinates(gps_data)
                                if coords:
                                    self.location_data['GPS Coordinates'] = coords
                                    self.reverse_geocode(coords['Latitude'], coords['Longitude'])
                                    self.get_nearby_places(coords['Latitude'], coords['Longitude'])
                
                if not self.location_data:
                    console.print("[yellow]No GPS data found in image[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]Error reading image: {e}[/red]")

    def analyze_coordinates(self, coord_string):
        try:
            lat, lon = map(float, coord_string.replace(' ', '').split(','))
            
            self.location_data['Provided Coordinates'] = {
                'Latitude': lat,
                'Longitude': lon
            }
            
            self.reverse_geocode(lat, lon)
            self.get_nearby_places(lat, lon)
            
        except Exception as e:
            console.print(f"[red]Error parsing coordinates: {e}[/red]")

    def parse_gps_coordinates(self, gps_data):
        try:
            lat_ref = gps_data.get('GPSLatitudeRef')
            lat = gps_data.get('GPSLatitude')
            lon_ref = gps_data.get('GPSLongitudeRef')
            lon = gps_data.get('GPSLongitude')
            
            if lat and lon:
                lat_decimal = self.convert_to_decimal(lat, lat_ref)
                lon_decimal = self.convert_to_decimal(lon, lon_ref)
                
                return {
                    'Latitude': lat_decimal,
                    'Longitude': lon_decimal,
                    'Raw GPS Data': gps_data
                }
        except:
            pass
        return None

    def convert_to_decimal(self, coord, ref):
        degrees = float(coord[0])
        minutes = float(coord[1])
        seconds = float(coord[2])
        
        decimal = degrees + minutes/60 + seconds/3600
        
        if ref in ['S', 'W']:
            decimal = -decimal
            
        return round(decimal, 6)

    def reverse_geocode(self, lat, lon):
        console.print("[cyan]Performing reverse geocoding...[/cyan]")
        
        try:
            import os
            api_key = os.getenv('OPENCAGE_API_KEY', 'your-opencage-api-key-here')
            url = f"https://api.opencagedata.com/geocode/v1/json"
            params = {
                'q': f"{lat},{lon}",
                'key': api_key,
                'language': 'en',
                'pretty': 1
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if data['results']:
                    result = data['results'][0]
                    components = result['components']
                    
                    self.location_data['Address'] = {
                        'Formatted': result['formatted'],
                        'Country': components.get('country', 'Unknown'),
                        'State/Province': components.get('state', components.get('province', 'Unknown')),
                        'City': components.get('city', components.get('town', components.get('village', 'Unknown'))),
                        'Postal Code': components.get('postcode', 'Unknown'),
                        'Confidence': result['confidence']
                    }
        except:
            self.reverse_geocode_alternative(lat, lon)

    def reverse_geocode_alternative(self, lat, lon):
        try:
            url = f"https://nominatim.openstreetmap.org/reverse"
            params = {
                'format': 'json',
                'lat': lat,
                'lon': lon,
                'addressdetails': 1
            }
            headers = {'User-Agent': 'TOXINT-Geolocation-Tool'}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if 'address' in data:
                    address = data['address']
                    
                    self.location_data['Address'] = {
                        'Formatted': data.get('display_name', 'Unknown'),
                        'Country': address.get('country', 'Unknown'),
                        'State/Province': address.get('state', 'Unknown'),
                        'City': address.get('city', address.get('town', address.get('village', 'Unknown'))),
                        'Postal Code': address.get('postcode', 'Unknown'),
                        'Source': 'OpenStreetMap'
                    }
        except:
            console.print("[yellow]Reverse geocoding failed[/yellow]")

    def get_nearby_places(self, lat, lon):
        console.print("[cyan]Finding nearby places...[/cyan]")
        
        try:
            url = "https://nominatim.openstreetmap.org/search"
            
            radius = 0.01
            params = {
                'format': 'json',
                'q': f"amenity=*",
                'viewbox': f"{lon-radius},{lat+radius},{lon+radius},{lat-radius}",
                'bounded': 1,
                'limit': 10,
                'addressdetails': 1
            }
            headers = {'User-Agent': 'TOXINT-Geolocation-Tool'}
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                places = response.json()
                
                if places:
                    nearby = []
                    for place in places[:5]:
                        nearby.append({
                            'name': place.get('display_name', 'Unknown'),
                            'type': place.get('type', 'Unknown'),
                            'distance': self.calculate_distance(
                                lat, lon, 
                                float(place['lat']), 
                                float(place['lon'])
                            )
                        })
                    
                    self.location_data['Nearby Places'] = nearby
        except:
            console.print("[yellow]Failed to find nearby places[/yellow]")

    def calculate_distance(self, lat1, lon1, lat2, lon2):
        import math
        
        R = 6371
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        distance = R * c
        
        if distance < 1:
            return f"{int(distance * 1000)}m"
        else:
            return f"{distance:.2f}km"

    def display_results(self):
        console.print(f"\n[red]═══ GEOLOCATION INTELLIGENCE REPORT ═══[/red]")
        
        if not self.location_data:
            console.print("[yellow]No location data found[/yellow]")
            return
        
        for category, data in self.location_data.items():
            if data:
                table = Table(title=category, border_style="red")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="white")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            for i, item in enumerate(value):
                                if isinstance(item, dict):
                                    for sub_key, sub_value in item.items():
                                        table.add_row(f"{key} {i+1} - {sub_key}", str(sub_value))
                                else:
                                    table.add_row(f"{key} {i+1}", str(item))
                        else:
                            table.add_row(str(key), str(value))
                else:
                    table.add_row("Value", str(data))
                
                console.print(table)
                console.print()
        
        if 'GPS Coordinates' in self.location_data or 'Provided Coordinates' in self.location_data:
            coords = self.location_data.get('GPS Coordinates', self.location_data.get('Provided Coordinates'))
            if coords:
                lat = coords['Latitude']
                lon = coords['Longitude']
                
                console.print(f"[green]Google Maps: https://maps.google.com/?q={lat},{lon}[/green]")
                console.print(f"[green]OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15[/green]")
        
        console.print(f"[green]Geolocation analysis complete[/green]")
